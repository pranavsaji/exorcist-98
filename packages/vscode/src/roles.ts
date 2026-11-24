/**
 * Which files the extension scans. The roles come from the core scanner's own
 * classifier (`classifyFile`), so the editor and `exorcist scan` agree on what
 * an agent file is; this module only adds the editor-specific choices: which
 * roles are scanned live, a few built-in paths the scanner files as plain docs
 * (Kiro specs, Cursor folders, CONTRIBUTING), and the user's extra globs.
 *
 * Pure: no `vscode` import, so it is unit-tested directly.
 */
import { classifyFile, parseMcpConfig } from '@exorcist-98/core';
import type { FileRole } from '@exorcist-98/core';

/** Roles an agent takes instructions or settings from; always scanned. */
export const AGENT_ROLES: ReadonlySet<FileRole> = new Set<FileRole>([
  'instruction', // steering, AGENTS.md, CLAUDE.md, .cursorrules, copilot-instructions, README*, ...
  'mcp-config',  // .kiro/settings/mcp.json, .cursor/mcp.json, .vscode/mcp.json, .mcp.json, ...
  'hook',        // .kiro/hooks/**, *.hook.yaml
  'memory',      // MEMORY.md, .kiro/notes/**, agent-notes*
  'power',       // power/** (Kiro Powers)
  'manifest',    // package.json (install scripts, EX-009)
]);

/**
 * Paths an agent also reads that the scanner classifies as ordinary docs or
 * config: everything under .kiro/ (specs, notes, settings) and .cursor/, and
 * CONTRIBUTING files, which agents are routinely told to follow.
 */
export const BUILTIN_GLOBS: readonly string[] = ['.kiro/**', '.cursor/**', '**/CONTRIBUTING*'];

/** Folders never searched by the workspace scan (the same list as the CLI's walker). */
export const SKIP_DIRS: readonly string[] = ['node_modules', '.git', 'dist', '.next', '.pnpm-store', '.turbo', 'coverage', '.nyc_output'];

/** The include glob for the workspace scan: a superset, narrowed by `decideScan`. */
export const WORKSPACE_INCLUDE =
  '{**/*.md,**/*.mdc,**/*.txt,**/*.json,**/*.jsonc,**/*.yaml,**/*.yml,**/*.toml,**/.cursorrules,**/.windsurfrules,**/.clinerules,**/.clinerules/**,**/.kiro/**,**/.cursor/**,**/README*,**/CONTRIBUTING*}';

/** The exclude glob for the workspace scan. */
export const WORKSPACE_EXCLUDE = `**/{${SKIP_DIRS.join(',')}}/**`;

// ── Globs ─────────────────────────────────────────────────────────────────────

/** Longest glob accepted, and most alternatives after `{a,b}` expansion. */
export const MAX_GLOB_LENGTH = 200;
export const MAX_GLOB_ALTERNATIVES = 64;

/** A compiled glob. `test` takes a workspace-relative path with forward slashes. */
export type GlobMatcher = { readonly glob: string; test(path: string): boolean };

type Tok =
  | { k: 'lit'; c: string }
  | { k: 'one' }                                      // ?
  | { k: 'class'; neg: boolean; ranges: [string, string][] } // [...]
  | { k: 'star' }                                     // * : any run without a slash
  | { k: 'dirs' }                                     // **/ : zero or more whole folders
  | { k: 'all' };                                     // trailing ** : anything

/**
 * Compile a glob. Supports `**`, `*`, `?`, `{a,b}` (not nested) and `[...]`.
 * A glob without a slash matches the file name in any folder (as in
 * .gitignore), so `*.prompt.md` works anywhere; `docs/*.md` is anchored at the
 * workspace folder.
 *
 * Extra globs come from settings a workspace can set itself, so they are
 * untrusted input. They are never turned into a backtracking RegExp: matching
 * simulates the glob as a small automaton, one pass over the path, so its time
 * is linear in the path length whatever the glob (`*a*a*a*a*b` included).
 * Globs over the length or alternative limits, or with nested braces, throw.
 */
export function compileGlob(glob: string): GlobMatcher {
  let g = glob.trim().replace(/\\/g, '/').replace(/^\.\//, '');
  if (g.length > MAX_GLOB_LENGTH) throw new Error('glob too long');
  if (!g.includes('/')) g = `**/${g}`;
  const alts = expandBraces(g).map(tokenize);
  return { glob, test: (path: string) => alts.some((t) => run(t, path)) };
}

function expandBraces(g: string): string[] {
  const open = g.indexOf('{');
  if (open === -1) return [g];
  const close = g.indexOf('}', open + 1);
  if (close === -1) return [g];                          // an unclosed brace is literal
  const body = g.slice(open + 1, close);
  if (body.includes('{')) throw new Error('nested braces');
  const out: string[] = [];
  for (const rest of expandBraces(g.slice(close + 1))) {
    for (const opt of body.split(',')) {
      out.push(g.slice(0, open) + opt + rest);
      if (out.length > MAX_GLOB_ALTERNATIVES) throw new Error('too many alternatives');
    }
  }
  return out;
}

function tokenize(g: string): Tok[] {
  const toks: Tok[] = [];
  for (let i = 0; i < g.length; i++) {
    const c = g[i] as string;
    if (c === '*') {
      let j = i;
      while (g[j + 1] === '*') j++;                     // runs of * collapse
      const globstar = j > i;
      i = j;
      if (globstar && g[i + 1] === '/') { i++; if (toks.at(-1)?.k !== 'dirs') toks.push({ k: 'dirs' }); }
      else if (globstar) toks.push({ k: 'all' });
      else if (toks.at(-1)?.k !== 'star') toks.push({ k: 'star' });
    } else if (c === '?') {
      toks.push({ k: 'one' });
    } else if (c === '[') {
      const close = g.indexOf(']', i + 2);
      if (close === -1) { toks.push({ k: 'lit', c }); continue; }
      let body = g.slice(i + 1, close);
      const neg = body[0] === '!' || body[0] === '^';
      if (neg) body = body.slice(1);
      const ranges: [string, string][] = [];
      for (let k = 0; k < body.length; k++) {
        const a = body[k] as string;
        if (body[k + 1] === '-' && k + 2 < body.length) { ranges.push([a, body[k + 2] as string]); k += 2; }
        else ranges.push([a, a]);
      }
      toks.push({ k: 'class', neg, ranges });
      i = close;
    } else {
      toks.push({ k: 'lit', c });
    }
  }
  return toks;
}

/**
 * Run the automaton. State 2i is "before token i"; state 2i+1 is "inside the
 * folders of a `**` token i", which may only leave right after a slash.
 */
function run(toks: Tok[], path: string): boolean {
  const n = toks.length;
  const close = (set: Set<number>): Set<number> => {
    for (let i = 0; i < n; i++) {
      const k = toks[i]!.k;
      if (set.has(2 * i) && (k === 'star' || k === 'dirs' || k === 'all')) set.add(2 * (i + 1));
    }
    return set;
  };
  let cur = close(new Set([0]));
  for (const ch of path) {
    const next = new Set<number>();
    for (const s of cur) {
      const i = s >> 1;
      if (s & 1) { next.add(s); if (ch === '/') next.add(2 * (i + 1)); continue; }
      if (i === n) continue;
      const t = toks[i]!;
      switch (t.k) {
        case 'lit': if (ch === t.c) next.add(2 * (i + 1)); break;
        case 'one': if (ch !== '/') next.add(2 * (i + 1)); break;
        case 'class': {
          const hit = t.ranges.some(([lo, hi]) => ch >= lo && ch <= hi);
          if (ch !== '/' && hit !== t.neg) next.add(2 * (i + 1));
          break;
        }
        case 'star': if (ch !== '/') next.add(s); break;
        case 'dirs': next.add(s + 1); if (ch === '/') next.add(2 * (i + 1)); break;
        case 'all': next.add(s); break;
      }
    }
    if (next.size === 0) return false;
    cur = close(next);
  }
  return cur.has(2 * n);
}

/** Compile globs once; invalid ones are dropped (and reported by the caller). */
export function compileGlobs(globs: readonly string[]): { patterns: GlobMatcher[]; invalid: string[] } {
  const patterns: GlobMatcher[] = [];
  const invalid: string[] = [];
  for (const g of globs) {
    if (typeof g !== 'string' || g.trim() === '') continue;
    try { patterns.push(compileGlob(g)); } catch { invalid.push(String(g)); }
  }
  return { patterns, invalid };
}

const BUILTIN = compileGlobs(BUILTIN_GLOBS).patterns;

// ── Paths ─────────────────────────────────────────────────────────────────────

/** Folders that mark the start of an agent config tree, for files outside any workspace folder. */
const AGENT_DIRS = new Set(['.kiro', '.cursor', '.github', '.claude', '.vscode', '.amazonq', '.gemini', '.windsurf', '.clinerules']);

/**
 * The path the classifier should see for a file that is not inside a workspace
 * folder (for example ~/.kiro/settings/mcp.json, Kiro's user-level MCP config):
 * from the last agent folder on, or the file name alone.
 */
export function agentRelativePath(absPath: string): string {
  const segs = absPath.replace(/\\/g, '/').split('/').filter((s) => s !== '');
  for (let i = segs.length - 2; i >= 0; i--) {
    if (AGENT_DIRS.has(segs[i] as string)) return segs.slice(i).join('/');
  }
  return segs[segs.length - 1] ?? absPath;
}

// ── Decision ──────────────────────────────────────────────────────────────────

export type ScanReason = 'role' | 'builtin' | 'extra' | 'mcp-content';

export type ScanDecision =
  | { scan: true; role: FileRole; reason: ScanReason }
  /** Only for a path-only check: a JSON config whose name says it may be an MCP config; read it to decide. */
  | { scan: 'needs-content'; role: FileRole }
  | { scan: false; role: FileRole };

/**
 * Should the file at workspace-relative path `rel` be scanned? With `text`,
 * a generic JSON config is scanned when the core parser reads it as an MCP
 * config (an `mcpServers` object); without it (the workspace scan, before
 * reading), such a file is a candidate only when its name mentions MCP.
 */
export function decideScan(rel: string, extra: readonly GlobMatcher[] = [], text?: string): ScanDecision {
  const norm = rel.replace(/\\/g, '/');
  const role = classifyFile(norm);
  if (AGENT_ROLES.has(role)) return { scan: true, role, reason: 'role' };
  if (role === 'definition') return { scan: false, role }; // virus definitions quote attacks on purpose
  if (BUILTIN.some((re) => re.test(norm))) return { scan: true, role, reason: 'builtin' };
  if (extra.some((re) => re.test(norm))) return { scan: true, role, reason: 'extra' };
  if (role === 'config') {
    if (text !== undefined) {
      return parseMcpConfig(norm, role, text) ? { scan: true, role, reason: 'mcp-content' } : { scan: false, role };
    }
    const base = norm.split('/').pop() ?? '';
    if (/mcp/i.test(base) && /\.jsonc?$/i.test(base)) return { scan: 'needs-content', role };
  }
  return { scan: false, role };
}
