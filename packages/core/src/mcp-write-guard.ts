import { readFileSync, statSync } from 'node:fs';
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
export type McpWriteDecision =
  | { target: 'mcp-config'; path: string }
  /** m11 (CT-5): a write that adds or widens a trusted-commands entry in `.vscode/settings.json`. */
  | { target: 'trusted-commands'; path: string }
  /** m11 (CT-6): a create, change, move or delete under `.kiro/hooks/` or `.kiro/agents/`. */
  | { target: 'guard-file'; path: string }
  /** Nothing to confirm. Spelled 'other' so existing callers and tests keep working (CT-7). */
  | { target: 'other' };

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

// ---------------------------------------------------------------------------
// m11: trusted-commands writes and guard-file writes (CT-5, CT-6)
// ---------------------------------------------------------------------------

const VSCODE_TAIL = ['.vscode', 'settings.json'];
const MAX_READ_BYTES = 2 * 1024 * 1024;
/** Keys that carry a destination or source path in Kiro's file tools, beyond PATH_KEYS. */
const MOVE_KEYS = ['source', 'src', 'from', 'to', 'old_path', 'new_path', 'oldPath', 'newPath'];
const NEW_TEXT_KEYS = ['file_text', 'fileText', 'content', 'contents', 'text', 'new_str', 'newStr', 'new_string', 'newText', 'insert_text', 'data', 'body'];
const OLD_TEXT_KEYS = ['old_str', 'oldStr', 'old_string', 'oldText'];
const TRUSTED_RE = /["']?(?:kiroAgent\.)?trustedCommands["']?\s*:\s*/gi;
const MOVERS = new Set(['cp', 'mv', 'install', 'ln']);
const REMOVERS = new Set(['rm', 'rmdir', 'unlink', 'shred', 'touch', 'truncate', 'mkdir']);

interface Prepared { base: string; toolName: string; shellTool: boolean; input: Record<string, unknown>; paths: string[]; cmds: string[] }

function prepare(event: unknown, cwd: string): Prepared | null {
  if (!isRecord(event) || !isRecord(event['tool_input'])) return null;
  const base = typeof event['cwd'] === 'string' && event['cwd'] !== '' ? resolve(cwd, event['cwd']) : resolve(cwd);
  const toolName = typeof event['tool_name'] === 'string' ? event['tool_name'] : '';
  const shellTool = /shell|bash|exec|command|terminal/i.test(toolName);
  const input = event['tool_input'];
  const paths: string[] = [];
  const cmds: string[] = [];
  collect(input, '', shellTool, paths, cmds, 0);
  return { base, toolName, shellTool, input, paths, cmds };
}

/** A tool that only reads (fs_read, grep, ...) never needs the write confirmation. */
function isReadOnlyTool(name: string): boolean {
  return /read|list|grep|search|glob|fetch/i.test(name) && !/write|replace|edit|create|delete|move|bash|shell|exec/i.test(name);
}

/** The path strings a file tool names (documented keys, then move/copy keys). */
function filePaths(input: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const k of [...PATH_KEYS, ...MOVE_KEYS]) {
    const v = input[k];
    if (typeof v === 'string' && v.length <= MAX_PATH_LEN) out.push(v);
    else if (Array.isArray(v)) for (const x of v) if (typeof x === 'string' && x.length <= MAX_PATH_LEN) out.push(x);
  }
  return out;
}

function firstString(input: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const k of keys) { const v = input[k]; if (typeof v === 'string') return v; }
  return undefined;
}

function endsWithTail(real: string, tail: string[]): boolean {
  const parts = real.split(/[\\/]+/).slice(-tail.length).map((p) => p.toLowerCase());
  return parts.length === tail.length && tail.every((t, i) => parts[i] === t);
}

/** Real path when `raw` names a `.vscode/settings.json`, else null. */
function settingsPath(raw: string, home: string, base: string): string | null {
  if (raw === '' || raw.includes('\0')) return null;
  const abs = expand(raw, home, base);
  const real = realPath(abs);
  return endsWithTail(real, VSCODE_TAIL) || endsWithTail(abs, VSCODE_TAIL) ? real : null;
}

/** True when a path has `.kiro/hooks` or `.kiro/agents` as consecutive parts (the folder itself counts). */
function inGuardDir(p: string): boolean {
  const parts = p.split(/[\\/]+/).map((x) => x.toLowerCase());
  for (let i = 0; i + 1 < parts.length; i++) {
    if (parts[i] === '.kiro' && (parts[i + 1] === 'hooks' || parts[i + 1] === 'agents')) return true;
  }
  return false;
}

function guardPath(raw: string, home: string, base: string): string | null {
  if (raw === '' || raw.includes('\0')) return null;
  const abs = expand(raw, home, base);
  const real = realPath(abs);
  return inGuardDir(real) || inGuardDir(abs) ? real : null;
}

/** First command word of a segment, its arguments after wrappers, and nothing else. */
function segmentName(seg: string[]): string {
  const rest = seg.filter((w, i) => w !== '>' && w !== '>>' && seg[i - 1] !== '>' && seg[i - 1] !== '>>');
  let i = 0;
  while (i < rest.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[i]!) || WRAPPERS.has(rest[i]!) || (i > 0 && rest[i]!.startsWith('-') && WRAPPERS.has(rest[i - 1]!)))) i++;
  return (rest[i] ?? '').split('/').pop() ?? '';
}

/** Write targets plus delete/create/move-source operands, for the guard-file check. */
function guardShellTargets(cmd: string): string[] {
  if (cmd.length > MAX_COMMAND_LEN) return [];
  const out: string[] = [];
  for (const seg of words(cmd)) {
    out.push(...writeTargets(seg));
    const name = segmentName(seg);
    if (REMOVERS.has(name) || name === 'mv') {
      const operands = seg.filter((w, i) => w !== '>' && w !== '>>' && seg[i - 1] !== '>' && seg[i - 1] !== '>>').slice(seg.findIndex((w) => w.split('/').pop() === name) + 1).filter((a) => !a.startsWith('-') || a === '-');
      out.push(...operands);
    }
  }
  return out;
}

/** Strings of the trusted-commands value(s) in JSON-with-comments text, read without a full parse. */
export function trustedEntries(text: string): string[] {
  const out: string[] = [];
  TRUSTED_RE.lastIndex = 0;
  for (let m = TRUSTED_RE.exec(text); m; m = TRUSTED_RE.exec(text)) {
    let i = m.index + m[0].length;
    const open = text[i];
    if (open === '"' || open === "'") { out.push(readString(text, i).value); continue; }
    if (open !== '[') continue;
    i++;
    while (i < text.length && text[i] !== ']') {
      const c = text[i]!;
      if (c === '"' || c === "'") { const r = readString(text, i); out.push(r.value); i = r.end; continue; }
      if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; continue; }
      if (c === '/' && text[i + 1] === '*') { const e = text.indexOf('*/', i + 2); i = e < 0 ? text.length : e + 2; continue; }
      i++;
    }
  }
  return out;
}

function readString(text: string, start: number): { value: string; end: number } {
  const q = text[start]!;
  let v = '';
  let i = start + 1;
  while (i < text.length && text[i] !== q) {
    if (text[i] === '\\' && i + 1 < text.length) { v += text[i + 1]; i += 2; continue; }
    v += text[i]; i++;
  }
  return { value: v, end: i + 1 };
}

function readDisk(path: string): string | undefined {
  try {
    if (statSync(path).size > MAX_READ_BYTES) return undefined;
    return readFileSync(path, 'utf8');
  } catch { return undefined; }
}

/** Does this file-tool write add a trusted-commands entry that the file on disk does not have? */
function addsTrustedEntry(input: Record<string, unknown>, disk: string | undefined): boolean {
  const fresh = firstString(input, NEW_TEXT_KEYS);
  if (fresh === undefined) return false;
  const old = firstString(input, OLD_TEXT_KEYS);
  const verb = typeof input['command'] === 'string' ? input['command'].toLowerCase() : '';
  let after = fresh;
  if (old !== undefined && disk !== undefined && old !== '' && disk.includes(old)) {
    const at = disk.indexOf(old);
    after = disk.slice(0, at) + fresh + disk.slice(at + old.length);
  } else if (verb === 'append' && disk !== undefined) after = disk + '\n' + fresh;
  const before = new Set(trustedEntries(disk ?? ''));
  return trustedEntries(after).some((e) => !before.has(e));
}

/**
 * CT-5: the real path of `.vscode/settings.json` when the event adds or widens
 * a trusted-commands entry there; null otherwise. File tools are compared with
 * the file on disk (a str_replace is applied to it first). A shell command is
 * judged by its text: a write target of settings.json plus the key name, or a
 * cp/mv/install/ln onto it, whose content cannot be seen. See SHELL_LIMIT.
 */
export function isTrustedCommandsWrite(event: unknown, home: string, cwd: string): string | null {
  const p = prepare(event, cwd);
  if (!p || isReadOnlyTool(p.toolName)) return null;
  if (!p.shellTool) {
    for (const raw of filePaths(p.input)) {
      const real = settingsPath(raw, home, p.base);
      if (real && addsTrustedEntry(p.input, readDisk(real))) return real;
    }
  }
  for (const cmd of p.cmds) {
    if (cmd.length > MAX_COMMAND_LEN) continue;
    const names = /trustedCommands/i.test(cmd);
    for (const seg of words(cmd)) {
      const mover = MOVERS.has(segmentName(seg));
      for (const t of writeTargets(seg)) {
        const real = settingsPath(t, home, p.base);
        if (real && (names || mover)) return real;
      }
    }
  }
  return null;
}

/**
 * CT-6: the real path under `.kiro/hooks/` or `.kiro/agents/` that the event
 * creates, changes, moves or deletes; null otherwise. Absolute, relative,
 * `..` and `~` spellings and symlinks resolve to the same target.
 */
export function isGuardFileWrite(event: unknown, home: string, cwd: string): string | null {
  const p = prepare(event, cwd);
  if (!p || isReadOnlyTool(p.toolName)) return null;
  const candidates = [...(p.shellTool ? [] : filePaths(p.input)), ...p.cmds.flatMap(guardShellTargets)];
  for (const c of candidates) {
    const hit = guardPath(c, home, p.base);
    if (hit) return hit;
  }
  return null;
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
  const trusted = isTrustedCommandsWrite(event, home, cwd);
  if (trusted) return { target: 'trusted-commands', path: trusted };
  const guarded = isGuardFileWrite(event, home, cwd);
  if (guarded) return { target: 'guard-file', path: guarded };
  return { target: 'other' };
}
