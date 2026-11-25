import { isAbsolute, join, resolve } from 'node:path';
import { realPath } from './allowed-reads.js';

/**
 * MCP config tamper guard (m8, CVE-2026-10591): decide whether a Kiro
 * `PreToolUse` event writes to `.kiro/settings/mcp.json`, in a project or in
 * the home folder. Pure apart from reading symlinks: the person is asked by
 * the CLI command, not here.
 *
 * Kiro's tool input keys differ by tool and version, so every string in
 * `tool_input` is looked at, not only the known path keys. Shell commands are
 * read best-effort (see SHELL_LIMIT): a command built by a script, a variable
 * other than HOME, or a program that writes on its own is not seen.
 */
export type McpWriteDecision = { target: 'mcp-config'; path: string } | { target: 'other' };

/** Keys that carry a file location in Kiro's write tools (documented names first). */
export const PATH_KEYS = ['path', 'file_path', 'filePath', 'target', 'destination', 'file'] as const;
/** Keys whose string is a shell command line. */
const COMMAND_KEYS = new Set(['command', 'cmd', 'script', 'commands']);
/** Strings longer than this are file content, not a path. */
const MAX_PATH_LEN = 1024;
const MAX_COMMAND_LEN = 8192;
const MAX_DEPTH = 6;
export const SHELL_LIMIT = 'Shell commands are checked on a best-effort basis: redirects (>, >>), tee, sed -i, cp and mv are seen; anything built at run time is not.';

const MCP_TAIL = ['.kiro', 'settings', 'mcp.json'];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Expand `~`, `$HOME` and `${HOME}`, then resolve against `cwd`. */
function expand(raw: string, home: string, cwd: string): string {
  let s = raw.trim();
  if (s.startsWith('file://')) {
    try { s = decodeURIComponent(s.slice('file://'.length)); } catch { /* keep as is */ }
  }
  if (s === '~') s = home;
  else if (s.startsWith('~/') || s.startsWith('~\\')) s = join(home, s.slice(2));
  s = s.replace(/^\$\{HOME\}|^\$HOME(?![A-Za-z0-9_])/, home);
  return isAbsolute(s) ? resolve(s) : resolve(cwd, s);
}

/** True when the real path ends in .kiro/settings/mcp.json (case-insensitive: macOS and Windows folders are). */
function isMcpConfigPath(real: string): boolean {
  const parts = real.split(/[\\/]+/).slice(-3).map((p) => p.toLowerCase());
  return parts.length === 3 && MCP_TAIL.every((t, i) => parts[i] === t);
}

/** The real path when `raw` names an MCP config, else null. */
function check(raw: string, home: string, cwd: string): string | null {
  if (raw === '' || raw.includes('\0')) return null;
  const abs = expand(raw, home, cwd);
  // A symlink can hide the name, so the real path is tested as well as the spelling.
  const real = realPath(abs);
  return isMcpConfigPath(real) || isMcpConfigPath(abs) ? real : null;
}

/** Split a command line into words, honouring quotes and backslashes. Operators become their own words. */
function words(cmd: string): string[][] {
  const segments: string[][] = [[]];
  let cur = '';
  let has = false;
  let quote: '"' | "'" | null = null;
  const push = (): void => { if (has) segments[segments.length - 1]!.push(cur); cur = ''; has = false; };
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]!;
    if (quote) {
      if (c === quote) quote = null;
      else if (c === '\\' && quote === '"' && i + 1 < cmd.length) cur += cmd[++i];
      else cur += c;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; has = true; continue; }
    if (c === '\\' && i + 1 < cmd.length) { cur += cmd[++i]; has = true; continue; }
    if (/\s/.test(c) && c !== '\n') { push(); continue; }
    if (c === ';' || c === '\n' || c === '|' || (c === '&' && cmd[i + 1] === '&')) {
      push();
      if (c === '&' || (c === '|' && cmd[i + 1] === '|')) i++;
      segments.push([]);
      continue;
    }
    if (c === '>') {
      // `>`, `>>`, `>|`, `&>`, `2>`: emit a redirect word, the target follows.
      const before = /^[0-9&]*$/.test(cur) ? cur : null;
      if (before === null) push(); else { cur = ''; has = false; }
      let op = '>';
      if (cmd[i + 1] === '>') { op = '>>'; i++; } else if (cmd[i + 1] === '|') { i++; }
      segments[segments.length - 1]!.push(op);
      continue;
    }
    cur += c; has = true;
  }
  push();
  return segments.filter((s) => s.length > 0);
}

const WRAPPERS = new Set(['sudo', 'command', 'exec', 'env', 'nohup', 'time', 'doas']);

/** Word list of one command segment -> the words that are write targets. */
function writeTargets(seg: string[]): string[] {
  const out: string[] = [];
  const rest: string[] = [];
  for (let i = 0; i < seg.length; i++) {
    if (seg[i] === '>' || seg[i] === '>>') { if (i + 1 < seg.length) out.push(seg[++i]!); } else rest.push(seg[i]!);
  }
  let i = 0;
  while (i < rest.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[i]!) || WRAPPERS.has(rest[i]!) || (i > 0 && rest[i]!.startsWith('-') && WRAPPERS.has(rest[i - 1]!)))) i++;
  const name = (rest[i] ?? '').split('/').pop() ?? '';
  const args = rest.slice(i + 1);
  const operands = args.filter((a) => !a.startsWith('-') || a === '-');
  if (name === 'tee') out.push(...operands);
  else if (name === 'sed' || name === 'gsed') {
    if (args.some((a) => /^-[A-Za-z]*i/.test(a) || a.startsWith('--in-place'))) out.push(...operands);
  } else if (name === 'cp' || name === 'mv' || name === 'install' || name === 'ln') {
    const t = args.findIndex((a) => a === '-t' || a === '--target-directory');
    if (t >= 0 && args[t + 1] !== undefined) {
      // The destination is a folder: any file named in the other operands lands in it under its own name.
      const dir = args[t + 1]!;
      out.push(dir, ...operands.filter((a) => a !== dir).map((a) => join(dir, a.split('/').pop() ?? a)));
    } else if (operands.length >= 2) out.push(operands[operands.length - 1]!);
    // `cp a ~/.kiro/settings/` copies into the folder: a file named mcp.json goes there.
    if (operands.length >= 2) {
      const last = operands[operands.length - 1]!;
      if (/[\\/]$/.test(last)) out.push(join(last, operands[0]!.split('/').pop() ?? ''));
    }
  }
  return out;
}

function shellWrites(cmd: string): string[] {
  if (cmd.length > MAX_COMMAND_LEN) return [];
  return words(cmd).flatMap(writeTargets);
}

function collect(value: unknown, key: string, shellTool: boolean, paths: string[], cmds: string[], depth: number): void {
  if (depth > MAX_DEPTH) return;
  if (typeof value === 'string') {
    if (COMMAND_KEYS.has(key) || (shellTool && value.length <= MAX_COMMAND_LEN && /\s/.test(value))) { cmds.push(value); return; }
    if (value.length <= MAX_PATH_LEN && !/[\r\n]/.test(value)) paths.push(value);
  } else if (Array.isArray(value)) {
    for (const v of value) collect(v, key, shellTool, paths, cmds, depth + 1);
  } else if (isRecord(value)) {
    for (const [k, v] of Object.entries(value)) collect(v, k, shellTool, paths, cmds, depth + 1);
  }
}

/**
 * Does this event write to an MCP config? `cwd` is used when the event has no
 * `cwd` of its own. Anything that is not a recognisable tool event is 'other'.
 */
export function decideMcpWrite(event: unknown, home: string, cwd: string): McpWriteDecision {
  if (!isRecord(event) || !isRecord(event['tool_input'])) return { target: 'other' };
  const base = typeof event['cwd'] === 'string' && event['cwd'] !== '' ? resolve(cwd, event['cwd']) : resolve(cwd);
  const toolName = typeof event['tool_name'] === 'string' ? event['tool_name'] : '';
  const shellTool = /shell|bash|exec|command|terminal/i.test(toolName);
  const paths: string[] = [];
  const cmds: string[] = [];
  collect(event['tool_input'], '', shellTool, paths, cmds, 0);
  const candidates = [...paths, ...cmds.flatMap(shellWrites)];
  for (const c of candidates) {
    // Shell words resolve against the same cwd; a `cd` first is not followed (SHELL_LIMIT).
    const hit = check(c, home, base);
    if (hit) return { target: 'mcp-config', path: hit };
  }
  return { target: 'other' };
}
