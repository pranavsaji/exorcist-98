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

/**
 * A glob as a regular expression over a workspace-relative path with forward
 * slashes. Supports `**`, `*`, `?`, `{a,b}` and `[...]`. A glob without a
 * slash matches the file name in any folder (as in .gitignore), so `*.prompt.md`
 * works anywhere; `docs/*.md` is anchored at the workspace folder.
 */
export function globToRegExp(glob: string): RegExp {
  let g = glob.trim().replace(/\\/g, '/').replace(/^\.\//, '');
  if (!g.includes('/')) g = `**/${g}`;
  let re = '';
  let depth = 0;
  for (let i = 0; i < g.length; i++) {
    const c = g[i] as string;
    if (c === '*') {
      if (g[i + 1] === '*') {
        // `**/` matches zero or more folders; a trailing `**` matches anything.
        if (g[i + 2] === '/') { re += '(?:.*/)?'; i += 2; } else { re += '.*'; i += 1; }
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else if (c === '{') {
      depth++; re += '(?:';
    } else if (c === '}' && depth > 0) {
      depth--; re += ')';
    } else if (c === ',' && depth > 0) {
      re += '|';
    } else if (c === '[') {
      const close = g.indexOf(']', i + 1);
      if (close === -1) { re += '\\['; continue; }
      const body = g.slice(i + 1, close).replace(/\\/g, '\\\\').replace(/^!/, '^');
      re += `[${body}]`;
      i = close;
    } else {
      re += c.replace(/[.+^$()|\\\]]/g, '\\$&');
    }
  }
  while (depth-- > 0) re += ')';
  return new RegExp(`^${re}$`);
}

/** Compile globs once; invalid ones are dropped (and reported by the caller). */
export function compileGlobs(globs: readonly string[]): { patterns: RegExp[]; invalid: string[] } {
  const patterns: RegExp[] = [];
  const invalid: string[] = [];
  for (const g of globs) {
    if (typeof g !== 'string' || g.trim() === '') continue;
    try { patterns.push(globToRegExp(g)); } catch { invalid.push(String(g)); }
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
export function decideScan(rel: string, extra: readonly RegExp[] = [], text?: string): ScanDecision {
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
