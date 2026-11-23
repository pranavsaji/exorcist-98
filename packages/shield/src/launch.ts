/**
 * Launch pins (S-006): the Shield pins the program behind a server, not only
 * its tool list. A server whose code changes but whose tools look the same
 * (a malicious update) is caught here before it starts.
 *
 * The pin covers the command, every argument (as a hash, because arguments
 * can hold tokens), the entry's `cwd` and `env` from the MCP config (values
 * hashed), and the contents of every argument that is a file
 * (`node dist/index.mjs`, `python server.py`). Package specs for runners such
 * as npx are recorded as text so a version change is readable, and a spec
 * without a fixed version is reported: the next release would run unreviewed.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, parse as parsePath, relative, resolve, sep } from 'node:path';
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

/**
 * What the MCP config says about how the server runs besides its command and
 * arguments, and what the program really inherits. A changed `env` can change
 * the program as much as a changed file (`NODE_OPTIONS=--require ./x.js`,
 * `LD_PRELOAD`), so it is part of the pin.
 */
export type LaunchEntry = {
  /** The entry's own `env`, as written in the config. */
  env?: Readonly<Record<string, string>>;
  /** The entry's `cwd`, as written in the config (not resolved: the same text on every machine). */
  cwd?: string;
  /** The MCP config the entry was read from, as `configLabel` gives it. */
  config?: string;
  /** Loader variables (LOADER_ENV) the program inherits from the Shield's own environment. */
  inherited?: Readonly<Record<string, string>>;
};

/** Environment variables that change how a program is loaded or what code runs first. */
export const LOADER_ENV = /^(NODE_OPTIONS|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|DYLD_[A-Z_]+|PYTHONPATH|PYTHONSTARTUP|PYTHONHOME|RUBYOPT|RUBYLIB|PERL5OPT|PERL5LIB|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|BASH_ENV|ENV)$/i;

/** The keys of an env that change how a program loads (EX-025), sorted. */
export function loaderEnvKeys(env: Readonly<Record<string, unknown>> | undefined): string[] {
  return Object.keys(env ?? {}).filter((k) => LOADER_ENV.test(k)).sort();
}

export type LaunchEntryResult = { ok: true; entry: LaunchEntry } | { ok: false; error: string };

/**
 * The `env` and `cwd` of a server entry in an MCP config, as the launch pin
 * reads them. Fail closed: an entry that is missing, or whose `env` or `cwd`
 * is not plain text, is an error, never a guess. (A client passes a number or
 * an object in `env` to the program as text, so dropping it would leave that
 * variable out of the pin.)
 */
export function launchEntryOf(entry: unknown): LaunchEntryResult {
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return { ok: false, error: 'the server is not in the MCP config' };
  const e = entry as Record<string, unknown>;
  const out: LaunchEntry = {};
  const env = e['env'];
  if (env !== undefined) {
    if (env === null || typeof env !== 'object' || Array.isArray(env)) return { ok: false, error: 'its "env" is not an object of text values' };
    const bad = Object.entries(env as Record<string, unknown>).find(([, v]) => typeof v !== 'string');
    if (bad) return { ok: false, error: `its env value for ${JSON.stringify(bad[0])} is not text (${bad[1] === null ? 'null' : typeof bad[1]})` };
    out.env = env as Record<string, string>;
  }
  const cwd = e['cwd'];
  if (cwd !== undefined) {
    if (typeof cwd !== 'string') return { ok: false, error: 'its "cwd" is not text' };
    out.cwd = cwd;
  }
  return { ok: true, entry: out };
}

/**
 * Folders that mark a project root for `configLabel`. Not `.exorcist`: the
 * Shield creates that folder itself, so the label would change after the
 * first run.
 */
const PROJECT_MARKERS = ['.git', '.kiro'];

/**
 * How the launch pin names an MCP config: its path from the project root (the
 * nearest folder above it with .git or .kiro), so the same config
 * gives the same pin on every machine and from any working folder; the
 * absolute path when it is in no project.
 */
export function configLabel(configPath: string): string {
  const abs = resolve(configPath);
  const { root } = parsePath(abs);
  for (let dir = dirname(abs); ; dir = dirname(dir)) {
    if (PROJECT_MARKERS.some((m) => existsSync(join(dir, m)))) return relative(dir, abs).split(sep).join('/');
    if (dir === root || dirname(dir) === dir) return abs;
  }
}

export function launchFingerprint(command: string, args: readonly string[], cwd: string, reader: FileReader = fsReader, entry: LaunchEntry = {}): LaunchPin {
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
  // The entry's working folder and environment, as written in the config.
  // Values are hashed (they often hold tokens); keys are sorted, so the order
  // they were written in does not matter. An entry with neither gives the
  // same parts as before they were pinned.
  const key = (k: string): string => JSON.stringify(k).slice(1, -1);
  if (entry.config !== undefined) parts.push(`config ${entry.config}`);
  if (entry.cwd !== undefined) parts.push(`cwd ${entry.cwd}`);
  for (const k of Object.keys(entry.env ?? {}).sort()) {
    const v = (entry.env as Record<string, string>)[k] as string;
    parts.push(`env ${key(k)} sha256:${sha256(v).slice(0, 16)}${LOADER_ENV.test(k) ? ' (changes how the program loads)' : ''}`);
  }
  for (const k of Object.keys(entry.inherited ?? {}).sort()) {
    parts.push(`inherited env ${key(k)} sha256:${sha256((entry.inherited as Record<string, string>)[k] as string).slice(0, 16)} (changes how the program loads)`);
  }
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
