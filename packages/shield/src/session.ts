/**
 * Session Guard (EX-027): the lethal trifecta, enforced at run time.
 *
 * EX-023 warns that a config *could* combine private data, untrusted text and
 * a way out. The Session Guard watches what really happens in one agent
 * session: once the agent has taken in untrusted text (a tool result the
 * Shield flagged, or one from a tool labelled untrusted-input) AND read
 * private data (a tool labelled private-data returned, a secret or canary
 * token was in a result, or a call read a secrets file), the next call that
 * could send data out is held for the user (or refused).
 *
 * ── Shared state across Shield processes ─────────────────────────────────────
 *
 * Each wrapped MCP server runs its own Shield process, and the trifecta almost
 * always spans servers (an issue tracker, a filesystem, a chat tool). So the
 * facts live in the Shield state folder, where every Shield of the session
 * can read them:
 *
 *   <state folder>/sessions/<session key>/<writer>.json
 *
 * - One file per Shield process (the writer is its pid). A process only ever
 *   writes its own file, by writing a temp file and renaming it over the old
 *   one, so there are no write races and no torn reads; readers read every
 *   file in the folder and merge. A process also keeps its own facts in
 *   memory, so its own decisions never depend on the disk.
 * - The session key names the agent process: EXORCIST_SESSION if set,
 *   otherwise the first ancestor of the Shield that is not a launcher (npx,
 *   npm, sh, ...), as `p<pid>-<hash of its start time>`, so a reused pid is
 *   a different session. Without `ps` (Windows), it is the parent pid.
 * - Facts expire after SESSION_TTL_MS (2 hours) and are refreshed when they
 *   happen again. Files and session folders older than that are deleted.
 * - Bounded: at most MAX_FACTS facts and MAX_GRANTS grants per file, files
 *   over MAX_FILE_BYTES or more than MAX_FILES per session are not read.
 * - Only facts are stored: kind, tool, server, rule id and time. Never a
 *   secret, an argument, a path or any text from a tool result.
 *
 * Failure: a file that cannot be read or does not validate is a *problem*,
 * never silently ignored. With a problem, the guard is cautious: it holds
 * data going out as soon as any one leg is known (it cannot rule out that the
 * unreadable file held the other). With no leg known at all, a benign session
 * is not blocked. Each problem is alerted once.
 *
 * Limits (also in docs/KNOWN_LIMITATIONS.md):
 * - Shields with different state folders never see each other's facts.
 * - An agent process that hosts many chats (an IDE) is one session, so facts
 *   from one chat hold calls in another until they expire. Conservative.
 * - A conversation that outlives the TTL forgets the earlier legs.
 * - A process that cannot write its file (alerted) is invisible to the others.
 * - Anyone who can write the state folder can add or remove facts; that is
 *   true of the pin file too.
 */
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import type { Stats } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';

export const SESSION_RULE_ID = 'EX-027';
/** How long a fact stays live without happening again. */
export const SESSION_TTL_MS = 2 * 60 * 60 * 1000;
export const MAX_FACTS = 32;
export const MAX_GRANTS = 4;
export const MAX_FILE_BYTES = 64 * 1024;
export const MAX_FILES = 64;
/** A time further ahead than this is not believed. */
const MAX_SKEW_MS = 5 * 60 * 1000;
const NAME_CHARS = 80;
const MAX_SESSION_DIRS = 256;

const WRITER_RE = /^[A-Za-z0-9_-]{1,64}$/;
const KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const RULE_RE = /^[A-Z]{2,5}-[0-9]{3}$/;

export type FactKind = 'untrusted' | 'private';

const Name = z.string().max(NAME_CHARS);
const Time = z.string().max(40).refine((t) => !Number.isNaN(Date.parse(t)), 'not a time');

const FactSchema = z.object({
  kind:   z.enum(['untrusted', 'private']),
  server: Name,
  tool:   Name,
  /** What made it a fact: a capability rule (CAP-012) or a Shield rule (EX-017). */
  ruleId: z.string().regex(RULE_RE),
  time:   Time,
}).strict();

/** The user let data go out despite the facts so far (a prompt's "rest of this session", or `exorcist approve session`). */
const GrantSchema = z.object({
  time:   Time,
  by:     z.enum(['prompt', 'cli']),
  server: Name.optional(),
}).strict();

export const SessionRecordSchema = z.object({
  version: z.literal(1),
  writer:  z.string().regex(WRITER_RE),
  updated: Time,
  facts:   z.array(FactSchema).max(MAX_FACTS),
  grants:  z.array(GrantSchema).max(MAX_GRANTS),
}).strict();

export type Fact = z.infer<typeof FactSchema>;
export type Grant = z.infer<typeof GrantSchema>;
export type SessionRecord = z.infer<typeof SessionRecordSchema>;

export type SessionRead = { records: SessionRecord[]; problems: string[] };

/** Where the facts of one agent session are shared. */
export interface SessionStore {
  /** The session key, shown to the user for `exorcist approve session <key>`. */
  readonly key: string;
  /** Every record of the session. Anything that could not be read is a problem, in plain words. */
  read(now: Date): SessionRead;
  /** Replace one writer's record. Returns a problem in plain words, or null. */
  write(record: SessionRecord): string | null;
}

export const isSessionKey = (key: string): boolean => KEY_RE.test(key);

// ── The decision ─────────────────────────────────────────────────────────────

export type Assessment = {
  /** Both legs happened in this session (any server) since the user last let data out. */
  armed: boolean;
  /** The shared state could not be fully read and one leg is known: hold to be safe. */
  cautious: boolean;
  /** The newest live fact of each kind. */
  untrusted: Fact | null;
  private: Fact | null;
  /** What could not be read. */
  problems: string[];
};

const timeOf = (t: string): number => Date.parse(t);

/** Which fact to name first when several happened at once: the plainest evidence. */
function factRank(f: Fact): number {
  if (f.kind === 'private') return f.ruleId === 'EX-017' ? 0 : f.ruleId === 'EX-022' ? 1 : f.ruleId.startsWith('CAP-') ? 2 : 3;
  return f.ruleId.startsWith('CAP-') ? 0 : 1;
}

/** What made a fact, in words (capability rules use their own label). */
const FACT_WORDS: Record<string, string> = {
  'EX-017': 'returned a secret',
  'EX-022': 'returned a canary token',
  'EX-011': 'read a file that usually holds secrets, or one outside the project',
};

/** One fact in plain words: which tool, on which server, did what, and the rule. Names are cleaned of control characters. */
export function describeFact(f: Fact, rules: ReadonlyArray<{ id: string; label: string }> = []): string {
  const clean = (s: string): string => s.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁠-⁯﻿]+/g, ' ').trim();
  const label = f.ruleId.startsWith('CAP-') ? rules.find((r) => r.id === f.ruleId)?.label : undefined;
  const words = label ?? FACT_WORDS[f.ruleId] ?? (f.kind === 'untrusted' ? 'returned text that may be instructions for your AI' : 'returned private data');
  return `"${clean(f.tool)}" on "${clean(f.server)}" ${words} (${f.ruleId})`;
}

/**
 * Pure: what the facts of a session mean now. A fact is live for `ttlMs`.
 * A grant covers the facts that existed when it was given; any newer fact
 * arms the guard again. Times further than a few minutes in the future are
 * not believed (a problem), so a forged time can neither keep a fact alive
 * forever nor make a grant cover facts that come later.
 */
export function assessSession(records: readonly SessionRecord[], problems: readonly string[], now: Date, ttlMs = SESSION_TTL_MS): Assessment {
  const n = now.getTime();
  const issues = [...problems];
  const live: Fact[] = [];
  let lastGrant = -Infinity;
  for (const r of records) {
    let future = false;
    for (const f of r.facts) {
      const t = timeOf(f.time);
      if (t > n + MAX_SKEW_MS) { future = true; continue; }
      if (n - t <= ttlMs) live.push(f);
    }
    for (const g of r.grants) {
      const t = timeOf(g.time);
      if (t > n + MAX_SKEW_MS) { future = true; continue; }
      if (n - t <= ttlMs && t > lastGrant) lastGrant = t;
    }
    if (future) issues.push(`the record of ${r.writer} is dated in the future`);
  }
  // The newest fact of a kind; at the same time, the one that says most.
  const better = (f: Fact, a: Fact): boolean => {
    const d = timeOf(f.time) - timeOf(a.time);
    return d !== 0 ? d > 0 : factRank(f) < factRank(a);
  };
  const newest = (kind: FactKind): Fact | null =>
    live.filter((f) => f.kind === kind).reduce<Fact | null>((a, f) => (a === null || better(f, a) ? f : a), null);
  const untrusted = newest('untrusted');
  const priv = newest('private');
  const uncovered = live.some((f) => timeOf(f.time) > lastGrant);
  const armed = untrusted !== null && priv !== null && uncovered;
  return { armed, cautious: !armed && issues.length > 0 && uncovered, untrusted, private: priv, problems: issues };
}

// ── One process's view ───────────────────────────────────────────────────────

/**
 * The Session Guard of one Shield process: notes facts, gives grants and
 * assesses the session, merging its own record (kept in memory) with every
 * other record in the store.
 */
export class SessionGuard {
  private readonly record: SessionRecord;
  private readonly now: () => Date;
  private readonly ttlMs: number;
  private failing: string | null = null;

  constructor(readonly store: SessionStore, o: { writer: string; now?: () => Date; ttlMs?: number }) {
    if (!WRITER_RE.test(o.writer)) throw new Error(`Invalid session writer "${o.writer}".`);
    this.now = o.now ?? (() => new Date());
    this.ttlMs = o.ttlMs ?? SESSION_TTL_MS;
    this.record = { version: 1, writer: o.writer, updated: this.now().toISOString(), facts: [], grants: [] };
  }

  get key(): string {
    return this.store.key;
  }

  /**
   * Record that something happened. Returns a problem with saving it, the
   * first time saving fails (so it can be alerted once), else null.
   */
  note(kind: FactKind, server: string, tool: string, ruleId: string): string | null {
    const now = this.now();
    const s = server.slice(0, NAME_CHARS);
    const t = tool.slice(0, NAME_CHARS);
    // Never write a record the other Shields would reject as invalid.
    if (!RULE_RE.test(ruleId)) ruleId = SESSION_RULE_ID;
    // A repeat replaces the old fact with a fresh time. It is always written:
    // a repeat after a grant (from any Shield of the session) must arm the
    // guard again everywhere.
    const same = this.record.facts.find((f) => f.kind === kind && f.server === s && f.tool === t && f.ruleId === ruleId);
    this.record.facts = this.record.facts.filter((f) => f !== same && now.getTime() - timeOf(f.time) <= this.ttlMs);
    this.record.facts.push({ kind, server: s, tool: t, ruleId, time: now.toISOString() });
    if (this.record.facts.length > MAX_FACTS) this.record.facts = this.record.facts.slice(-MAX_FACTS);
    return this.save(now);
  }

  /** The user let data go out: covers every fact so far. */
  grant(by: Grant['by'], server?: string): string | null {
    const now = this.now();
    this.record.grants = [...this.record.grants, { time: now.toISOString(), by, ...(server ? { server: server.slice(0, NAME_CHARS) } : {}) }].slice(-MAX_GRANTS);
    return this.save(now);
  }

  assess(): Assessment {
    const now = this.now();
    const view = this.store.read(now);
    // This process's own record always counts, read or not.
    const records = [...view.records.filter((r) => r.writer !== this.record.writer), this.record];
    return assessSession(records, view.problems, now, this.ttlMs);
  }

  /** This process's own facts (for tests and the Possession Lab). */
  facts(): Fact[] {
    return this.record.facts.map((f) => ({ ...f }));
  }

  private save(now: Date): string | null {
    this.record.updated = now.toISOString();
    const problem = this.store.write(structuredClone(this.record));
    if (problem === null) { this.failing = null; return null; }
    if (this.failing !== null) return null;
    this.failing = problem;
    return problem;
  }
}

// ── Stores ───────────────────────────────────────────────────────────────────

/** In memory: one process (the default), or several engines in one process (the Possession Lab, tests). */
export class MemorySessionStore implements SessionStore {
  private readonly records = new Map<string, SessionRecord>();
  constructor(readonly key: string = 'this-process') {}
  read(): SessionRead {
    return { records: [...this.records.values()].map((r) => structuredClone(r)), problems: [] };
  }
  write(record: SessionRecord): string | null {
    this.records.set(record.writer, structuredClone(record));
    return null;
  }
}

const FILE_RE = /^[A-Za-z0-9_-]{1,64}\.json$/;
const TMP_RE = /\.tmp$/;

function code(err: unknown): string {
  return err && typeof err === 'object' && 'code' in err ? String((err as { code: unknown }).code) : 'error';
}

export const sessionsPath = (stateDir: string): string => join(stateDir, 'sessions');

/** In the Shield state folder, shared by every Shield process of the session. See the top of this file. */
export class FileSessionStore implements SessionStore {
  readonly dir: string;
  private readonly root: string;
  private lastPrune = 0;

  constructor(stateDir: string, readonly key: string, private readonly ttlMs = SESSION_TTL_MS) {
    if (!isSessionKey(key)) throw new Error(`Invalid session key "${key}".`);
    this.root = sessionsPath(stateDir);
    this.dir = join(this.root, key);
  }

  read(now: Date): SessionRead {
    const records: SessionRecord[] = [];
    const problems: string[] = [];
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch (err) {
      if (code(err) === 'ENOENT') return { records, problems };
      return { records, problems: [`the session folder ${this.dir} could not be read (${code(err)})`] };
    }
    const files = names.filter((n) => !TMP_RE.test(n)).sort();
    if (files.length > MAX_FILES) problems.push(`the session folder ${this.dir} holds more than ${MAX_FILES} files`);
    for (const name of files.slice(0, MAX_FILES)) {
      if (!FILE_RE.test(name)) { problems.push(`${name} in ${this.dir} is not a session record`); continue; }
      const path = join(this.dir, name);
      let st: Stats;
      try { st = lstatSync(path); } catch (err) {
        if (code(err) !== 'ENOENT') problems.push(`${name} could not be read (${code(err)})`);
        continue;
      }
      if (!st.isFile()) { problems.push(`${name} is not a regular file`); continue; }
      // Expired: its facts are too old to count. Pruned on the next write.
      if (now.getTime() - st.mtimeMs > this.ttlMs) continue;
      if (st.size > MAX_FILE_BYTES) { problems.push(`${name} is larger than ${MAX_FILE_BYTES} bytes`); continue; }
      let json: unknown;
      try { json = JSON.parse(readFileSync(path, 'utf8')); } catch (err) {
        if (code(err) !== 'ENOENT') problems.push(`${name} is not valid JSON`);
        continue;
      }
      const parsed = SessionRecordSchema.safeParse(json);
      if (!parsed.success || `${parsed.data.writer}.json` !== name) { problems.push(`${name} is not a valid session record`); continue; }
      records.push(parsed.data);
    }
    return { records, problems };
  }

  write(record: SessionRecord): string | null {
    const path = join(this.dir, `${record.writer}.json`);
    const tmp = `${path}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
    try {
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      writeFileSync(tmp, `${JSON.stringify(record)}\n`, { encoding: 'utf8', mode: 0o600 });
      renameSync(tmp, path);
    } catch (err) {
      try { unlinkSync(tmp); } catch { /* never created */ }
      return `the session record ${path} could not be written (${code(err)})`;
    }
    this.prune(record.writer);
    return null;
  }

  /** Delete expired records and session folders, at most once a minute. Never follows links. */
  private prune(own: string): void {
    const t = Date.now();
    if (t - this.lastPrune < 60_000) return;
    this.lastPrune = t;
    const old = (st: Stats, age: number): boolean => t - st.mtimeMs > age;
    try {
      for (const name of readdirSync(this.dir)) {
        if (name === `${own}.json`) continue;
        const p = join(this.dir, name);
        const st = lstatSync(p);
        if (st.isFile() && old(st, TMP_RE.test(name) ? 60_000 : this.ttlMs)) unlinkSync(p);
      }
    } catch { /* pruning is best effort */ }
    try {
      for (const name of readdirSync(this.root).slice(0, MAX_SESSION_DIRS)) {
        if (name === this.key || !KEY_RE.test(name)) continue;
        const p = join(this.root, name);
        const st = lstatSync(p);
        if (!st.isDirectory()) continue;
        const entries = readdirSync(p);
        const newest = entries.reduce((m, e) => {
          try { return Math.max(m, lstatSync(join(p, e)).mtimeMs); } catch { return m; }
        }, st.mtimeMs);
        if (t - newest > this.ttlMs) rmSync(p, { recursive: true, force: true });
      }
    } catch { /* pruning is best effort */ }
  }
}

/** The keys of the sessions in a state folder that still have live records (for `exorcist approve session`). */
export function liveSessions(stateDir: string, now: Date = new Date(), ttlMs = SESSION_TTL_MS): string[] {
  const root = sessionsPath(stateDir);
  let names: string[];
  try { names = readdirSync(root); } catch { return []; }
  return names.filter((name) => {
    if (!KEY_RE.test(name)) return false;
    const r = new FileSessionStore(stateDir, name, ttlMs).read(now);
    return r.records.some((rec) => rec.facts.length > 0);
  }).sort();
}

/**
 * `exorcist approve session <key>`: let data go out of that session despite
 * the facts so far. Written as the session's `cli` record; a new fact arms
 * the guard again.
 */
export function grantSession(stateDir: string, key: string, now: Date = new Date()): { ok: true; message: string } | { ok: false; error: string } {
  if (!isSessionKey(key)) return { ok: false, error: `"${key}" is not a session key.` };
  if (!liveSessions(stateDir, now).includes(key)) {
    return { ok: false, error: `There is no live session "${key}" in ${sessionsPath(stateDir)} (it may have expired).` };
  }
  const store = new FileSessionStore(stateDir, key);
  const prev = store.read(now).records.find((r) => r.writer === 'cli');
  const grants = [...(prev?.grants ?? []), { time: now.toISOString(), by: 'cli' as const }].slice(-MAX_GRANTS);
  const problem = store.write({ version: 1, writer: 'cli', updated: now.toISOString(), facts: [], grants });
  if (problem) return { ok: false, error: `Could not approve: ${problem}.` };
  return { ok: true, message: `Session "${key}" may send data out again. The Session Guard asks again if the agent takes in new untrusted text or reads private data.` };
}

// ── The session key ──────────────────────────────────────────────────────────

export type ProcInfo = { ppid: number; started: string; command: string };
export type ProcLookup = (pid: number) => ProcInfo | null;

/** Programs that only start the Shield: the session is whoever started them. */
const LAUNCHER_NAMES = new Set([
  'npm', 'npx', 'pnpm', 'pnpx', 'yarn', 'bunx', 'uvx', 'pipx', 'corepack', 'exorcist',
  'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'env', 'cmd', 'cmd.exe', 'powershell', 'pwsh',
]);
const NODE_LAUNCHER = /(?:^|[\\/\s])(?:npm|npx|pnpm|pnpx|yarn|corepack)(?:-cli)?(?:\.c?js)?(?:\s|$)|[\\/]exorcist(?:\.c?js)?(?:\s|$)|[\\/]@exorcist-98[\\/]cli[\\/]/;

export function isLauncher(command: string): boolean {
  const first = command.trim().split(/\s+/)[0] ?? '';
  const base = (first.replace(/\\/g, '/').split('/').pop() ?? first).replace(/^-/, '').toLowerCase();
  if (LAUNCHER_NAMES.has(base)) return true;
  if (base === 'node' || base === 'node.exe' || base === 'bun') return NODE_LAUNCHER.test(command);
  return false;
}

/** `ps` for one process: parent, start time and command line. Null where there is no `ps` or it fails. */
export function psLookup(pid: number): ProcInfo | null {
  if (process.platform === 'win32' || !Number.isInteger(pid) || pid <= 0) return null;
  try {
    const r = spawnSync('ps', ['-o', 'ppid=', '-o', 'lstart=', '-o', 'args=', '-p', String(pid)], { encoding: 'utf8', timeout: 1000, env: { ...process.env, LC_ALL: 'C' } });
    if (r.status !== 0 || typeof r.stdout !== 'string') return null;
    const m = /^\s*(\d+)\s+(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}\s+\d{4})\s*(.*)$/.exec(r.stdout.split('\n')[0] ?? '');
    if (!m) return null;
    return { ppid: Number(m[1]), started: m[2] as string, command: m[3] ?? '' };
  } catch {
    return null;
  }
}

/**
 * The key of the agent session this Shield belongs to. EXORCIST_SESSION
 * when set (letters, digits, `.`, `_`, `-`); otherwise the first ancestor
 * that is not a launcher, with its start time hashed in; otherwise the
 * parent pid.
 */
export function resolveSessionKey(o: { env?: NodeJS.ProcessEnv; lookup?: ProcLookup; startPid?: number } = {}): string {
  const env = o.env ?? process.env;
  const fromEnv = env['EXORCIST_SESSION'];
  if (fromEnv !== undefined && isSessionKey(fromEnv)) return fromEnv;
  const lookup = o.lookup ?? psLookup;
  const start = o.startPid ?? process.ppid;
  let pid = start;
  for (let hop = 0; hop < 8 && pid > 1; hop++) {
    const info = lookup(pid);
    if (!info) break;
    if (!isLauncher(info.command)) return `p${pid}-${createHash('sha256').update(info.started).digest('hex').slice(0, 8)}`;
    if (info.ppid === pid) break;
    pid = info.ppid;
  }
  return `p${start}`;
}
