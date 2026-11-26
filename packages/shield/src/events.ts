/**
 * The Shield's event log: what each Shield process decided, for the live
 * console (`exorcist console`).
 *
 *   <state folder>/events.jsonl     newest events, one JSON object per line
 *   <state folder>/events.1.jsonl   the file before the last rotation
 *
 * ── Writing ──────────────────────────────────────────────────────────────────
 *
 * Every Shield process of the state folder appends to the same file. Each
 * event is one line, written with a single `write` on a file opened with
 * O_APPEND, so lines from different processes never interleave or overwrite
 * each other (POSIX appends to a local file are atomic with respect to the
 * end of the file). A line is at most MAX_LINE_BYTES.
 *
 * Bounded: when the file would grow past `maxBytes` (1 MiB), it is renamed to
 * events.1.jsonl (replacing the older one) under a short-lived lock folder, so
 * two processes never rotate at once. If the lock cannot be taken and the
 * file has reached twice `maxBytes`, the event is dropped instead of written:
 * the two files together never hold much more than 4 × maxBytes.
 *
 * ── What is in it ────────────────────────────────────────────────────────────
 *
 * The same kind of text as alerts.jsonl, and less: the decision, the rule id,
 * the server and tool names (cleaned of control and hidden characters and
 * shortened; they come from the MCP server, so they are attacker-controlled
 * text and the console shows them as text only), and the Shield's own
 * plain-language reason. Never a tool's arguments, a result's text, a secret
 * or an alert's `detail` (the description diff of a changed tool).
 *
 * ── Reading ──────────────────────────────────────────────────────────────────
 *
 * EventTail reads both files and then follows the current one, across
 * rotations. A line that is not valid JSON or not a valid event (a damaged
 * line, a hand edit, a newer version) is skipped and counted, never fatal.
 */
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readSync, renameSync, rmdirSync, writeSync } from 'node:fs';
import type { Stats } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { cleanText } from './notify.js';
import { eventHash, loadOrCreateGenesis, readHead, writeHeadAtomic } from './chain.js';

export const eventsPath = (dir: string): string => join(dir, 'events.jsonl');
export const oldEventsPath = (dir: string): string => join(dir, 'events.1.jsonl');
const lockPath = (dir: string): string => join(dir, 'events.lock');

export const MAX_EVENT_BYTES = 1024 * 1024;
export const MAX_LINE_BYTES = 8 * 1024;
/** A rotation lock older than this was left by a process that died; it is removed. */
const STALE_LOCK_MS = 10_000;
/** The reader never reads more than this from one file at once. */
const MAX_READ_BYTES = 8 * 1024 * 1024;

const HEX64 = /^[0-9a-f]{64}$/;
const NAME_CHARS = 80;
const WHY_CHARS = 400;
const MESSAGE_CHARS = 600;
const RULE_RE = /^[A-Z][A-Z0-9-]{1,15}$/;
const KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

const Time = z.string().max(40).refine((t) => !Number.isNaN(Date.parse(t)), 'not a time');
const Name = z.string().max(NAME_CHARS);
const Rule = z.string().regex(RULE_RE);
const Base = {
  v:       z.literal(1),
  time:    Time,
  pid:     z.number().int().positive(),
  server:  Name,
  session: z.string().regex(KEY_RE).optional(),
  /** Hash-chain fields (chain.ts). Absent on lines written before the chain existed or when the lock could not be taken. */
  seq:     z.number().int().positive().optional(),
  prev:    z.string().regex(HEX64).optional(),
  hash:    z.string().regex(HEX64).optional(),
};

/** A Shield process started (one per wrapped server). */
const StartEvent = z.object({
  ...Base,
  kind:   z.literal('start'),
  mode:   z.enum(['enforce', 'monitor']),
  guard:  z.enum(['hold', 'block', 'monitor', 'off']),
  remote: z.boolean(),
  /** How a held Session Guard call is released: in the system prompt (`os`) or with `exorcist approve session` (`terminal`). Absent in older logs. */
  release: z.enum(['os', 'terminal']).optional(),
}).strict();

/**
 * A tool call and what the Shield did with it.
 *   allowed  sent to the server (`monitor`: a rule matched, but monitor mode sent it)
 *   held     waiting for the user's answer in the agent's approval prompt (`prompt` numbers it)
 *   blocked  not sent
 * `by: 'user'` marks the outcome of an approval prompt the user answered.
 */
const CallEvent = z.object({
  ...Base,
  kind:     z.literal('call'),
  tool:     Name,
  decision: z.enum(['allowed', 'held', 'blocked']),
  ruleId:   Rule.optional(),
  why:      z.string().max(WHY_CHARS).optional(),
  monitor:  z.literal(true).optional(),
  prompt:   z.number().int().positive().optional(),
  by:       z.literal('user').optional(),
  /** The hold is answered in the system prompt (Touch ID or login password), not in the agent's approval prompt. `prompt` then numbers the system prompt. */
  via:      z.literal('os').optional(),
}).strict();

/** A tool result that looked like an attack on the AI: withheld (enforce) or flagged (monitor). */
const ResultEvent = z.object({
  ...Base,
  kind:     z.literal('result'),
  tool:     Name,
  decision: z.enum(['withheld', 'flagged']),
  ruleId:   Rule,
  why:      z.string().max(WHY_CHARS).optional(),
}).strict();

/** An alert, as in alerts.jsonl but without `detail`. */
const AlertEvent = z.object({
  ...Base,
  kind:     z.literal('alert'),
  severity: z.enum(['critical', 'high', 'medium']),
  ruleId:   Rule,
  tool:     Name.optional(),
  message:  z.string().max(MESSAGE_CHARS),
}).strict();

export const ShieldEventSchema = z.discriminatedUnion('kind', [StartEvent, CallEvent, ResultEvent, AlertEvent]);
export type ShieldEvent = z.infer<typeof ShieldEventSchema>;
export type CallShieldEvent = z.infer<typeof CallEvent>;

/** What the engine reports; the log adds time, pid, server and session. */
export type EngineEvent =
  | { kind: 'call'; tool: string; decision: 'allowed' | 'held' | 'blocked'; ruleId?: string; why?: string; monitor?: boolean; prompt?: number; by?: 'user'; via?: 'os' }
  | { kind: 'result'; tool: string; decision: 'withheld' | 'flagged'; ruleId: string; why?: string };

type Omitted = 'v' | 'time' | 'pid' | 'server' | 'session';
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
export type EventBody = DistributiveOmit<ShieldEvent, Omitted>;

const rule = (r: string | undefined): string => (r !== undefined && RULE_RE.test(r) ? r : 'SHIELD');

/** Clean every text field and drop anything the schema does not allow. */
function sanitize(body: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(body)) {
    if (val === undefined) continue;
    if (k === 'tool') out[k] = cleanText(String(val), NAME_CHARS);
    else if (k === 'why') out[k] = cleanText(String(val), WHY_CHARS);
    else if (k === 'message') out[k] = cleanText(String(val), MESSAGE_CHARS);
    else if (k === 'ruleId') out[k] = rule(typeof val === 'string' ? val : undefined);
    else if (k === 'monitor') { if (val === true) out[k] = true; }
    else if (k === 'prompt') { if (typeof val === 'number' && Number.isInteger(val) && val > 0) out[k] = val; }
    else if (k === 'via') { if (val === 'os') out[k] = 'os'; }
    else out[k] = val;
  }
  return out;
}

function code(err: unknown): string {
  return err && typeof err === 'object' && 'code' in err ? String((err as { code: unknown }).code) : 'error';
}

export type EventLogOptions = {
  pid?: number;
  server: string;
  session?: string;
  maxBytes?: number;
  now?: () => Date;
  /** Hash-chain each event (default true). false writes plain lines, like a log from before the chain. */
  chain?: boolean;
  /** Genesis value generator, injectable for tests. */
  random?: () => Buffer;
  /** How many times to try for the lock before writing an event unchained (default LOCK_ATTEMPTS). */
  lockAttempts?: number;
};

/** About 2.4 s of waiting in all, enough to ride out a loaded machine: the critical section lasts well under a millisecond, so this only runs out when a lock is truly stuck. */
const LOCK_ATTEMPTS = 800;
const LOCK_WAIT_MS = 5;

function sleepMs(ms: number): void {
  try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); } catch { /* no wait available: retry at once */ }
}

/**
 * Run `fn` holding the state folder's lock folder (`mkdirSync` as the mutex). A lock
 * older than STALE_LOCK_MS was left by a dead process and is removed. Tries up to
 * `attempts` times, waiting briefly between tries; `{ held: false }` when it never got
 * the lock (`fn` is not run). Never throws: a failure inside `fn` propagates to the caller.
 */
function withLock<T>(lock: string, attempts: number, fn: () => T): { held: true; value: T } | { held: false } {
  let got = false;
  for (let i = 0; i < attempts && !got; i++) {
    try {
      mkdirSync(lock);
      got = true;
    } catch (err) {
      if (code(err) !== 'EEXIST') return { held: false };
      try {
        if (Date.now() - lstatSync(lock).mtimeMs > STALE_LOCK_MS) {
          rmdirSync(lock);
          mkdirSync(lock);
          got = true;
        }
      } catch { /* another process won the race; try again */ }
    }
    if (!got && i + 1 < attempts) sleepMs(1 + Math.random() * (LOCK_WAIT_MS - 1));
  }
  if (!got) return { held: false };
  try {
    return { held: true, value: fn() };
  } finally {
    try { rmdirSync(lock); } catch { /* removed as stale later */ }
  }
}

/**
 * One Shield process's writer. Never throws: a log that cannot be written
 * must not stop the Shield. `problem` holds the first failure, for one line
 * on stderr.
 */
export class EventLog {
  readonly path: string;
  private readonly old: string;
  private readonly lock: string;
  private readonly maxBytes: number;
  private readonly pid: number;
  private readonly server: string;
  private readonly now: () => Date;
  private readonly chain: boolean;
  private readonly random: (() => Buffer) | undefined;
  private readonly lockAttempts: number;
  private sessionKey: string | undefined;
  /** Events not written because the file was full and could not be rotated. */
  dropped = 0;
  problem: string | null = null;

  constructor(readonly dir: string, o: EventLogOptions) {
    this.path = eventsPath(dir);
    this.old = oldEventsPath(dir);
    this.lock = lockPath(dir);
    this.maxBytes = o.maxBytes ?? MAX_EVENT_BYTES;
    this.pid = o.pid ?? process.pid;
    this.server = cleanText(o.server, NAME_CHARS);
    this.now = o.now ?? (() => new Date());
    this.chain = o.chain ?? true;
    this.random = o.random;
    this.lockAttempts = o.lockAttempts ?? LOCK_ATTEMPTS;
    this.session = o.session;
  }

  set session(key: string | undefined) {
    this.sessionKey = key !== undefined && KEY_RE.test(key) ? key : undefined;
  }

  get session(): string | undefined {
    return this.sessionKey;
  }

  /** Append one event. Returns true when it was written. */
  write(body: EventBody | EngineEvent): boolean {
    const record = {
      v: 1,
      time: this.now().toISOString(),
      pid: this.pid,
      server: this.server,
      ...(this.sessionKey ? { session: this.sessionKey } : {}),
      ...sanitize(body as Record<string, unknown>),
    };
    const parsed = ShieldEventSchema.safeParse(record);
    if (!parsed.success) { this.fail(`an event did not validate (${parsed.error.issues[0]?.message ?? 'invalid'})`); return false; }
    try {
      mkdirSync(this.dir, { recursive: true });
      if (this.chain) {
        // One critical section per event: read head, compute, append, write head.
        const r = withLock(this.lock, this.lockAttempts, () => this.writeChained(parsed.data));
        if (r.held) return r.value;
        this.fail('the event log lock could not be taken, so an event was written without chain fields');
      }
      return this.append(this.encode(parsed.data));
    } catch (err) {
      this.fail(`${this.path} could not be written (${code(err)})`);
      return false;
    }
  }

  private encode(e: ShieldEvent): Buffer | null {
    const line = Buffer.from(`${JSON.stringify(e)}\n`, 'utf8');
    if (line.length > MAX_LINE_BYTES) { this.fail('an event was too long'); return null; }
    return line;
  }

  /** Size check, rotation and the single O_APPEND write of one line. The caller holds no lock unless it is chaining. */
  private append(line: Buffer | null, locked = false): boolean {
    if (line === null) return false;
    const size = this.size();
    if (size + line.length > this.maxBytes) {
      if (locked) this.rotateLocked(); else this.rotate();
      if (this.size() + line.length > this.maxBytes * 2) { this.dropped++; return false; }
    }
    // O_NOFOLLOW: never append through a symlink someone put in the state folder.
    const flags = constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0);
    const fd = openSync(this.path, flags, 0o600);
    try {
      if (!fstatSync(fd).isFile()) { this.fail(`${this.path} is not a regular file`); return false; }
      writeSync(fd, line);
    } finally {
      closeSync(fd);
    }
    return true;
  }

  /** The chained write, with the lock held. Falls back to an unchained line when the chain files are unusable. */
  private writeChained(event: ShieldEvent): boolean {
    const g = loadOrCreateGenesis(this.dir, this.random);
    if (!g.ok) { this.fail(g.error); return this.append(this.encode(event), true); }
    const h = readHead(this.dir);
    // A damaged head counts as "no head yet": the verifier then reports the break instead of the writer hiding it.
    if (!h.ok) this.fail(h.error);
    const head = h.ok ? h.value : null;
    const seq = (head?.seq ?? 0) + 1;
    const prev = head?.hash ?? g.value;
    const hash = eventHash({ ...event, seq, prev });
    const chained = ShieldEventSchema.safeParse({ ...event, seq, prev, hash });
    if (!chained.success) { this.fail('a chained event did not validate'); return false; }
    if (!this.append(this.encode(chained.data), true)) return false;
    const w = writeHeadAtomic(this.dir, { v: 1, genesis: g.value, seq, hash });
    if (!w.ok) this.fail(w.error);
    return true;
  }

  private fail(p: string): void {
    this.problem ??= p;
  }

  private size(): number {
    try { return lstatSync(this.path).size; } catch { return 0; }
  }

  /** Rename the full file to events.1.jsonl, under the lock (one try). Best effort. */
  private rotate(): void {
    withLock(this.lock, 1, () => this.rotateLocked());
  }

  /** The rotation itself; the caller holds the lock. */
  private rotateLocked(): void {
    try {
      // Another process may have rotated just before this one took the lock.
      if (this.size() > 0 && this.size() >= this.maxBytes / 2) renameSync(this.path, this.old);
    } catch { /* the next write tries again */ }
  }
}

// ── Reading ──────────────────────────────────────────────────────────────────

export type ParsedLines = { events: ShieldEvent[]; skipped: number };

/** Parse complete lines. Anything that is not a valid event is skipped and counted. */
export function parseEventLines(text: string): ParsedLines {
  const events: ShieldEvent[] = [];
  let skipped = 0;
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue;
    if (Buffer.byteLength(line, 'utf8') > MAX_LINE_BYTES) { skipped++; continue; }
    let json: unknown;
    try { json = JSON.parse(line); } catch { skipped++; continue; }
    const r = ShieldEventSchema.safeParse(json);
    if (r.success) events.push(r.data); else skipped++;
  }
  return { events, skipped };
}

type Cursor = { ino: number; dev: number; offset: number };

/** Read [offset, end) of a file, up to MAX_READ_BYTES from the end, and stop at the last full line. */
function readFrom(path: string, from: number): { text: string; end: number; st: Stats } | null {
  let fd: number;
  try { fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); } catch { return null; }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return null;
    let start = from > st.size ? 0 : from;
    let dropFirst = false;
    if (st.size - start > MAX_READ_BYTES) { start = st.size - MAX_READ_BYTES; dropFirst = true; }
    const len = st.size - start;
    const buf = Buffer.alloc(len);
    let got = 0;
    while (got < len) {
      const n = readSync(fd, buf, got, len - got, start + got);
      if (n === 0) break;
      got += n;
    }
    const lastNl = buf.lastIndexOf(0x0a, got - 1);
    if (lastNl === -1) return { text: '', end: start, st };
    let text = buf.subarray(0, lastNl + 1).toString('utf8');
    if (dropFirst) text = text.slice(text.indexOf('\n') + 1);
    return { text, end: start + lastNl + 1, st };
  } finally {
    closeSync(fd);
  }
}

/**
 * Follows the event log of a state folder: `read()` returns every event not
 * returned before, in file order, across rotations. Read-only.
 */
export class EventTail {
  private cur: Cursor | null = null;
  skipped = 0;
  private readonly path: string;
  private readonly old: string;

  constructor(readonly dir: string) {
    this.path = eventsPath(dir);
    this.old = oldEventsPath(dir);
  }

  read(): ShieldEvent[] {
    const out: ShieldEvent[] = [];
    const take = (text: string): void => {
      const p = parseEventLines(text);
      this.skipped += p.skipped;
      out.push(...p.events);
    };
    let st: Stats | null = null;
    try { st = lstatSync(this.path); } catch { st = null; }

    if (this.cur === null) {
      // First read: the older file, then the current one.
      const o = readFrom(this.old, 0);
      if (o) take(o.text);
    } else if (st === null || st.ino !== this.cur.ino || st.dev !== this.cur.dev) {
      // Rotated since the last read: finish the file that was being followed.
      const o = readFrom(this.old, this.cur.offset);
      if (o && o.st.ino === this.cur.ino && o.st.dev === this.cur.dev) take(o.text);
      this.cur = null;
      if (st === null) return out;
      const r = readFrom(this.path, 0);
      if (r) { take(r.text); this.cur = { ino: r.st.ino, dev: r.st.dev, offset: r.end }; }
      return out;
    }
    if (st === null) return out;
    const r = readFrom(this.path, this.cur?.offset ?? 0);
    if (r) {
      // The same file but shorter: it was truncated by hand; start again.
      if (this.cur && r.st.size < this.cur.offset) {
        const again = readFrom(this.path, 0);
        if (again) { take(again.text); this.cur = { ino: again.st.ino, dev: again.st.dev, offset: again.end }; }
        return out;
      }
      take(r.text);
      this.cur = { ino: r.st.ino, dev: r.st.dev, offset: r.end };
    }
    return out;
  }
}
