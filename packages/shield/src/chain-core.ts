/**
 * The hash chain over the Shield's event log: the pure core.
 *
 * Every chained event carries `seq`, `prev` (the previous event's hash, or the
 * genesis value for the first) and `hash` (SHA-256 over the event's canonical
 * form, which includes `seq` and `prev` and leaves `hash` out). Changing,
 * removing, inserting or reordering a line breaks the links after it.
 *
 * `canonicalize`, `eventHash` and `verifyChain` are pure, so the same
 * `verifyChain` runs in the CLI, the console and the web demos. This module has
 * no `node:fs` or `node:crypto` import (SHA-256 is the pure sha256.ts, so a browser bundle can use it); the genesis and head file helpers and `verifyLogDir` live
 * in chain.ts, which re-exports everything here. The chain detects edits; it
 * cannot stop someone who can rewrite the whole state folder (see
 * docs/KNOWN_LIMITATIONS.md).
 */
import { z } from 'zod';
import { canonicalJson } from './canonical.js';
import { sha256Hex } from './sha256.js';
import type { ShieldEvent } from './events.js';

/** 64 hex characters: SHA-256 of 32 random bytes. */
export type Genesis = string;

export type ChainFields = { seq: number; prev: string; hash: string };
/** A ShieldEvent after chaining: the existing fields plus ChainFields. */
export type ChainedShieldEvent = ShieldEvent & ChainFields;

export const HEX64 = /^[0-9a-f]{64}$/;

export const HeadRecordSchema = z.object({
  v:       z.literal(1),
  genesis: z.string().regex(HEX64),
  seq:     z.number().int().positive(),
  hash:    z.string().regex(HEX64),
}).strict();
export type HeadRecord = z.infer<typeof HeadRecordSchema>;

export type BreakReason = 'changed' | 'removed' | 'inserted' | 'reordered' | 'head-mismatch' | 'expect-mismatch';

export type ChainStatus =
  | { status: 'intact'; head: HeadRecord; unchained?: number }
  | { status: 'not-chained' }
  | { status: 'broken'; atSeq: number; reason: BreakReason; detail: string };

export type VerifyOptions = {
  expect?: { seq: number; hash: string };
  /** The log may start after seq 1 because older lines were rotated away. Off by default: otherwise deleting the first events would pass for a rotation. */
  allowRotatedStart?: boolean;
};

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
/** An event with its chain fields but without its own hash. */
type HashInput = DistributiveOmit<ChainedShieldEvent, 'hash'>;

/** Deterministic text hashed for one event: sorted keys, `seq` and `prev` included, `hash` excluded. */
export function canonicalize(e: HashInput): string {
  const { ...rest } = e as Record<string, unknown>;
  delete rest['hash'];
  return canonicalJson(rest);
}

/** SHA-256 hex of `canonicalize(e)`. */
export function eventHash(e: HashInput): string {
  return sha256Hex(canonicalize(e));
}

type Line = ShieldEvent & Partial<ChainFields>;

function chainOf(e: Line): ChainFields | null {
  const { seq, prev, hash } = e;
  if (typeof seq === 'number' && Number.isInteger(seq) && seq > 0 && typeof prev === 'string' && typeof hash === 'string') {
    return { seq, prev, hash };
  }
  return null;
}

const broken = (atSeq: number, reason: BreakReason, detail: string): ChainStatus => ({ status: 'broken', atSeq, reason, detail });

/**
 * Check a log in one pass. `lines` are the events in file order (oldest first);
 * `head` and `genesis` are the values read from the state folder, or null.
 *
 * - No chained line at all and no head: `not-chained` (an old or empty log).
 * - Unchained lines before the first chained line are old-log lines and are skipped.
 * - An unchained line after the chain started is tolerated only as a trailing run after
 *   the last chained line (what a writer leaves when it could not take the lock). The head
 *   record covers every chained line, so such lines cannot hide a change; they are counted
 *   in `unchained` and are not verified. One followed by a chained line is `inserted`:
 *   a forged line there would otherwise go unnoticed.
 * - The first chained line must be seq 1, linked to the genesis. With `allowRotatedStart`
 *   (the caller saw a rotated file) it may start later; that line is then the anchor and
 *   only the links after it are checked. Lines rotated away are not covered.
 * - `atSeq` is the sequence position where the log first stops matching the chain.
 */
export function verifyChain(lines: readonly Line[], head: HeadRecord | null, genesis: Genesis | null, opts?: VerifyOptions): ChainStatus {
  const g = genesis ?? head?.genesis ?? null;
  if (genesis !== null && head !== null && genesis !== head.genesis) {
    return broken(1, 'head-mismatch', 'the head record belongs to a different log (its genesis value does not match)');
  }

  let started = false;
  let expectedSeq = 1;
  let prevHash = g;
  let last: ChainFields | null = null;
  let expectSeen: string | null = null;
  let trailing = 0;
  const want = opts?.expect;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as Line;
    const c = chainOf(line);
    if (c === null) {
      if (started) trailing++;
      continue;
    }
    if (trailing > 0) return broken(expectedSeq, 'inserted', `a line without chain fields sits before event ${c.seq}, where event ${expectedSeq} should be`);
    const actual = eventHash({ ...line, seq: c.seq, prev: c.prev } as HashInput);
    if (!started) {
      started = true;
      if (c.seq !== 1 && opts?.allowRotatedStart === true) { expectedSeq = c.seq; prevHash = c.prev; }
    }
    if (actual !== c.hash) return broken(expectedSeq, 'changed', `event ${expectedSeq} was changed after it was written (its hash no longer matches)`);
    if (c.seq === expectedSeq && (prevHash === null || c.prev === prevHash)) {
      // linked correctly
    } else if (c.seq === expectedSeq) {
      return broken(expectedSeq, 'inserted', `an event that does not follow event ${expectedSeq - 1} sits at position ${expectedSeq}`);
    } else if (c.seq > expectedSeq) {
      const next = i + 1 < lines.length ? chainOf(lines[i + 1] as Line) : null;
      if (next !== null && next.seq === expectedSeq) return broken(expectedSeq, 'reordered', `events ${expectedSeq} and ${c.seq} are out of order`);
      return broken(expectedSeq, 'removed', `event ${expectedSeq} is missing (the log jumps to ${c.seq})`);
    } else {
      return broken(c.seq, 'reordered', `event ${c.seq} appears after event ${expectedSeq - 1}, out of order`);
    }
    if (want !== undefined && c.seq === want.seq) expectSeen = c.hash;
    last = c;
    prevHash = c.hash;
    expectedSeq = c.seq + 1;
  }

  if (last === null) {
    if (head === null) return { status: 'not-chained' };
    return broken(head.seq, 'head-mismatch', 'the log has no chained events but a head record exists (the log was emptied or replaced)');
  }
  if (head === null) return broken(last.seq, 'head-mismatch', 'the log has chained events but no head record');
  if (last.seq !== head.seq || last.hash !== head.hash) {
    return broken(Math.min(last.seq + 1, head.seq), 'head-mismatch', "the log's end does not match its head record (it was cut short or replaced)");
  }
  if (want !== undefined && expectSeen !== want.hash) {
    return broken(want.seq, 'expect-mismatch', "the log's head does not match the expected hash");
  }
  return trailing > 0 ? { status: 'intact', head, unchained: trailing } : { status: 'intact', head };
}
