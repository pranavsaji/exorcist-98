/**
 * Launch pins (S-006): the Shield pins the program behind a server, not only
 * its tool list. A server whose code changes but whose tools look the same
 * (a malicious update) is caught here before it starts.
 *
 * The pin covers the command, every argument (as a hash, because arguments
 * can hold tokens), and the contents of every argument that is a file
 * (`node dist/index.mjs`, `python server.py`). Package specs for runners such
 * as npx are recorded as text so a version change is readable, and a spec
 * without a fixed version is reported: the next release would run unreviewed.
 */
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import type { ServerState } from './state.js';

const sha256 = (b: string | Buffer): string => createHash('sha256').update(b).digest('hex');
/** Files larger than this are pinned by size and modification time, not content. */
const MAX_HASHED_BYTES = 64 * 1024 * 1024;

export type FileReader = (path: string) => { kind: 'file'; size: number; mtimeMs: number; read: () => Buffer } | { kind: 'other' };

const fsReader: FileReader = (path) => {
  try {
    const st = statSync(path);
    if (!st.isFile()) return { kind: 'other' };
    return { kind: 'file', size: st.size, mtimeMs: st.mtimeMs, read: () => readFileSync(path) };
  } catch {
    return { kind: 'other' };
  }
};

export type LaunchPin = {
  hash:  string;
  /** One readable line per part. Never holds argument text, only hashes, file paths and package specs. */
  parts: string[];
};

/** Commands that download and run a package named in their arguments. */
const RUNNERS: Record<string, string[]> = {
  npx: [], pnpx: [], bunx: [], uvx: [],
  pnpm: ['dlx'], npm: ['exec'], yarn: ['dlx'], bun: ['x'], pipx: ['run'],
};
const INTERPRETERS = /^(node|nodejs|deno|bun|python\d*(\.\d+)?|pythonw|uv|uvx|npx|pnpx|bunx|pnpm|npm|yarn|pipx|java|ruby|php|dotnet|docker|podman|sh|bash|zsh|cmd|powershell|pwsh)$/i;
const baseName = (c: string): string => c.split(/[\\/]/).pop()?.replace(/\.(cmd|exe)$/i, '') ?? c;

/** The package spec a runner command will download, if any (`npx -y pkg@1.2.3` gives `pkg@1.2.3`). */
export function packageSpec(command: string, args: readonly string[]): string | undefined {
  const sub = RUNNERS[baseName(command)];
  if (!sub) return undefined;
  let i = 0;
  if (sub.length > 0) {
    if (args[0] === undefined || !sub.includes(args[0])) return undefined;
    i = 1;
  }
  for (; i < args.length; i++) {
    const a = args[i] as string;
    if (a === '--') continue;
    if (a === '--package' || a === '-p') return args[i + 1];
    if (a.startsWith('--package=')) return a.slice('--package='.length);
    if (a.startsWith('-')) continue;
    return a;
  }
  return undefined;
}

/** True when a package spec names a fixed version (`pkg@1.2.3`, `@scope/pkg@1.2.3`, `pkg==1.2.3`). */
export function specIsPinned(spec: string): boolean {
  if (/==\d/.test(spec)) return true; // Python
  const at = spec.startsWith('@') ? spec.indexOf('@', 1) : spec.indexOf('@');
  if (at <= 0) return false;
  const version = spec.slice(at + 1);
  return /^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$/.test(version);
}

export function launchFingerprint(command: string, args: readonly string[], cwd: string, reader: FileReader = fsReader): LaunchPin {
  const fileLine = (label: string, value: string): string | undefined => {
    if (value.length === 0 || value.length > 4096) return undefined;
    const path = isAbsolute(value) ? value : resolve(cwd, value);
    const f = reader(path);
    if (f.kind !== 'file') return undefined;
    const content = f.size <= MAX_HASHED_BYTES ? `sha256:${sha256(f.read())}` : `size:${f.size} mtime:${Math.round(f.mtimeMs)}`;
    return `${label} file ${value} ${content}`;
  };
  const parts: string[] = [];
  // An interpreter (node, python, npx) is recorded by name or path only:
  // hashing it would raise an alarm on every runtime upgrade. Any other
  // command given as a path is a program of its own, so its contents count.
  const commandIsPath = /[\\/]/.test(command);
  const own = commandIsPath && !INTERPRETERS.test(baseName(command)) ? fileLine('command', command) : undefined;
  parts.push(own ?? `command ${command}`);
  const spec = packageSpec(command, args);
  if (spec) parts.push(`package ${spec}`);
  args.forEach((a, i) => {
    parts.push(fileLine(`arg ${i}`, a) ?? `arg ${i} sha256:${sha256(a).slice(0, 16)}`);
  });
  return { hash: sha256(parts.join('\n')), parts };
}

export type LaunchCheck =
  | { result: 'pinned' }
  | { result: 'same' }
  | { result: 'changed'; removed: string[]; added: string[] };

/** Compare against the server's launch pin and record the outcome in `s`. */
export function checkLaunch(s: ServerState, pin: LaunchPin, now: Date = new Date()): LaunchCheck {
  if (!s.launch) {
    s.launch = { hash: pin.hash, parts: pin.parts, pinnedAt: now.toISOString() };
    delete s.pendingLaunch;
    return { result: 'pinned' };
  }
  if (s.launch.hash === pin.hash) {
    delete s.pendingLaunch;
    return { result: 'same' };
  }
  s.pendingLaunch = { hash: pin.hash, parts: pin.parts, seenAt: now.toISOString() };
  const old = new Set(s.launch.parts);
  const fresh = new Set(pin.parts);
  return {
    result: 'changed',
    removed: s.launch.parts.filter((p) => !fresh.has(p)),
    added: pin.parts.filter((p) => !old.has(p)),
  };
}
