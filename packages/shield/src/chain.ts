/**
 * Chain file helpers: the genesis and head files, and `verifyLogDir`, which reads
 * a state folder's log and runs the pure `verifyChain` over it. The pure core
 * (canonicalize, eventHash, verifyChain, types) lives in chain-core.ts, which has
 * no `node:fs` import, and is re-exported here. Every helper returns a typed
 * result instead of throwing.
 */
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { HEX64, HeadRecordSchema, verifyChain } from './chain-core.js';
import type { ChainStatus, Genesis, HeadRecord, VerifyOptions } from './chain-core.js';
import { MAX_LINE_BYTES, ShieldEventSchema, eventsPath, oldEventsPath } from './events.js';
import type { ShieldEvent } from './events.js';

export { HeadRecordSchema, canonicalize, eventHash, verifyChain } from './chain-core.js';
export type { Genesis, ChainFields, ChainedShieldEvent, HeadRecord, BreakReason, ChainStatus, VerifyOptions } from './chain-core.js';

/** A typed result for file helpers: they never throw across the module boundary. */
export type ChainResult<T> = { ok: true; value: T } | { ok: false; error: string };
const ok = <T>(value: T): ChainResult<T> => ({ ok: true, value });
const fail = <T>(error: string): ChainResult<T> => ({ ok: false, error });

export const headPath = (dir: string): string => join(dir, 'events.head.json');
/** Separate from the head so a lost head can be rebuilt by rescanning the log against this value. */
export const genesisPath = (dir: string): string => join(dir, 'events.genesis.json');

const GenesisFileSchema = z.object({ v: z.literal(1), genesis: z.string().regex(HEX64) }).strict();
const MAX_FILE_BYTES = 4096;

function errCode(e: unknown): string {
  return e && typeof e === 'object' && 'code' in e ? String((e as { code: unknown }).code) : 'error';
}

/** Read a small regular file without following a symlink. null when it does not exist. */
function readSmall(path: string): ChainResult<string | null> {
  let fd: number | null = null;
  try {
    const st = lstatSync(path, { throwIfNoEntry: false });
    if (st === undefined) return ok(null);
    if (!st.isFile()) return fail('not a regular file');
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    if (fstatSync(fd).size > MAX_FILE_BYTES) return fail('file is too large');
    return ok(readFileSync(fd, 'utf8'));
  } catch (e) {
    return errCode(e) === 'ENOENT' ? ok(null) : fail(`could not read (${errCode(e)})`);
  } finally {
    if (fd !== null) { try { closeSync(fd); } catch { /* nothing to do */ } }
  }
}

function parseWith<T>(text: string, schema: z.ZodType<T>): ChainResult<T> {
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { return fail('not valid JSON'); }
  const r = schema.safeParse(raw);
  return r.success ? ok(r.data) : fail('does not match the expected shape');
}

/** The state folder's genesis value, or null when none has been created. A damaged file is an error. */
export function readGenesis(dir: string): ChainResult<Genesis | null> {
  const t = readSmall(genesisPath(dir));
  if (!t.ok) return fail(`genesis file: ${t.error}`);
  if (t.value === null) return ok(null);
  const g = parseWith(t.value, GenesisFileSchema);
  return g.ok ? ok(g.value.genesis) : fail(`genesis file: ${g.error}`);
}

/** Write a new file that must not exist yet (no symlink or race can redirect it). */
function writeNew(path: string, text: string): ChainResult<void> {
  let fd: number | null = null;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    writeSync(fd, text);
    return ok(undefined);
  } catch (e) {
    return fail(errCode(e));
  } finally {
    if (fd !== null) { try { closeSync(fd); } catch { /* nothing to do */ } }
  }
}

/**
 * Load the state folder's genesis value, creating it on first use (SHA-256 of 32
 * random bytes). The file is created exclusively, so two processes starting at once
 * end up with the same value: the loser reads the winner's file.
 */
export function loadOrCreateGenesis(dir: string, random: () => Buffer = () => randomBytes(32)): ChainResult<Genesis> {
  const existing = readGenesis(dir);
  if (!existing.ok) return existing;
  if (existing.value !== null) return ok(existing.value);
  const genesis = createHash('sha256').update(random()).digest('hex');
  const w = writeNew(genesisPath(dir), `${JSON.stringify({ v: 1, genesis })}\n`);
  if (!w.ok) {
    if (w.error !== 'EEXIST') return fail(`genesis file: could not create (${w.error})`);
    const again = readGenesis(dir);
    if (!again.ok) return again;
    return again.value === null ? fail('genesis file: could not be read after creation') : ok(again.value);
  }
  return ok(genesis);
}

/** The current head record: null when there is none yet, an error when the file is damaged. */
export function readHead(dir: string): ChainResult<HeadRecord | null> {
  const t = readSmall(headPath(dir));
  if (!t.ok) return fail(`head file: ${t.error}`);
  if (t.value === null) return ok(null);
  const h = parseWith(t.value, HeadRecordSchema);
  return h.ok ? ok(h.value) : fail(`head file: ${h.error}`);
}

/** Replace the head record atomically: write a temp file in the same folder, then rename over it. */
export function writeHeadAtomic(dir: string, head: HeadRecord): ChainResult<void> {
  const parsed = HeadRecordSchema.safeParse(head);
  if (!parsed.success) return fail('head file: record is not valid');
  const tmp = join(dir, `events.head.json.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
  const w = writeNew(tmp, `${JSON.stringify(parsed.data)}\n`);
  if (!w.ok) return fail(`head file: could not write (${w.error})`);
  try {
    renameSync(tmp, headPath(dir));
    return ok(undefined);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* nothing to do */ }
    return fail(`head file: could not replace (${errCode(e)})`);
  }
}

// ── Verifying a state folder ─────────────────────────────────────────────────

const CHUNK = 1 << 20;

/**
 * Read one log file in 1 MiB chunks and append each valid event to `out`, in file
 * order. Same rules as `parseEventLines` (oversized, non-JSON and non-event lines are
 * skipped), but the file is never held as one string. null when the file is absent.
 */
function readEventsInto(path: string, out: ShieldEvent[]): ChainResult<null> {
  let fd: number | null = null;
  try {
    const st = lstatSync(path, { throwIfNoEntry: false });
    if (st === undefined) return ok(null);
    if (!st.isFile()) return fail('not a regular file');
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const buf = Buffer.alloc(CHUNK);
    let carry: Buffer = Buffer.alloc(0);
    const take = (raw: Buffer): void => {
      if (raw.length === 0 || raw.length > MAX_LINE_BYTES) return;
      const text = raw.toString('utf8');
      if (text.trim() === '') return;
      let json: unknown;
      try { json = JSON.parse(text); } catch { return; }
      const r = ShieldEventSchema.safeParse(json);
      if (r.success) out.push(r.data);
    };
    for (;;) {
      const n = readSync(fd, buf, 0, CHUNK, null);
      if (n === 0) break;
      let from = 0;
      for (;;) {
        const nl = buf.indexOf(0x0a, from);
        if (nl === -1 || nl >= n) break;
        take(Buffer.concat([carry, buf.subarray(from, nl)]));
        carry = Buffer.alloc(0);
        from = nl + 1;
      }
      if (from < n) {
        carry = Buffer.concat([carry, buf.subarray(from, n)]);
        // A partial line longer than any valid line can never become one: drop it.
        if (carry.length > MAX_LINE_BYTES * 2) carry = carry.subarray(0, MAX_LINE_BYTES * 2);
      }
    }
    // A last line without a newline is still a line.
    take(carry);
    return ok(null);
  } catch (e) {
    return fail(`could not read (${errCode(e)})`);
  } finally {
    if (fd !== null) { try { closeSync(fd); } catch { /* nothing to do */ } }
  }
}

/**
 * Verify the event log of a state folder: read events.1.jsonl then events.jsonl, the
 * head and genesis files, and run `verifyChain` once over the lot. `allowRotatedStart`
 * is set only when events.1.jsonl exists, because only then may the log legitimately
 * start after seq 1. An unreadable log or damaged head/genesis file is reported as
 * `broken` / `head-mismatch`, never thrown.
 */
export function verifyLogDir(dir: string, opts?: VerifyOptions): ChainStatus {
  const unreadable = (what: string, error: string): ChainStatus =>
    ({ status: 'broken', atSeq: 1, reason: 'head-mismatch', detail: `${what} could not be read: ${error}` });

  const head = readHead(dir);
  if (!head.ok) return unreadable('the head record', head.error);
  const genesis = readGenesis(dir);
  if (!genesis.ok) return unreadable('the genesis value', genesis.error);

  const events: ShieldEvent[] = [];
  const old = oldEventsPath(dir);
  let rotated = false;
  try { rotated = lstatSync(old, { throwIfNoEntry: false }) !== undefined; } catch { return unreadable('events.1.jsonl', 'not accessible'); }
  if (rotated) {
    const r = readEventsInto(old, events);
    if (!r.ok) return unreadable('events.1.jsonl', r.error);
  }
  const cur = readEventsInto(eventsPath(dir), events);
  if (!cur.ok) return unreadable('events.jsonl', cur.error);

  return verifyChain(events, head.value, genesis.value, { ...opts, allowRotatedStart: rotated });
}
