/**
 * The hash chain core (chain.ts): genesis and head files, and properties 1, 3 and 4
 * of .kiro/specs/m12-audit-chain/design.md.
 */
import { describe, expect, it, afterEach } from 'vitest';
import fc from 'fast-check';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  eventHash, genesisPath, headPath, loadOrCreateGenesis, readGenesis, readHead, verifyChain, writeHeadAtomic,
} from '../chain.js';
import type { ChainFields, Genesis, HeadRecord } from '../chain.js';
import type { ShieldEvent } from '../events.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-chain-')); dirs.push(d); return d; };

type Line = ShieldEvent & Partial<ChainFields>;
const hex = (c: string): string => c.repeat(64);

/** A plausible event body, valid against ShieldEventSchema. */
const body: fc.Arbitrary<ShieldEvent> = fc.oneof(
  fc.record({ tool: fc.string({ minLength: 1, maxLength: 20 }), decision: fc.constantFrom<'allowed' | 'held' | 'blocked'>('allowed', 'held', 'blocked') }).map(
    ({ tool, decision }): ShieldEvent => ({ v: 1, time: '2026-11-24T10:00:00.000Z', pid: 42, server: 'notes', kind: 'call', tool, decision }),
  ),
  fc.constantFrom<'enforce' | 'monitor'>('enforce', 'monitor').map(
    (mode): ShieldEvent => ({ v: 1, time: '2026-11-24T10:00:00.000Z', pid: 42, server: 'notes', kind: 'start', mode, guard: 'hold', remote: false }),
  ),
  fc.string({ maxLength: 40 }).map(
    (message): ShieldEvent => ({ v: 1, time: '2026-11-24T10:00:00.000Z', pid: 42, server: 'notes', kind: 'alert', severity: 'high', ruleId: 'EX-006', message }),
  ),
);
const bodies = (min: number): fc.Arbitrary<ShieldEvent[]> => fc.array(body, { minLength: min, maxLength: 12 });

/** One append, shaped like the writer's critical section: read head, compute, then write head. */
function append(dir: string, e: ShieldEvent): Line {
  const g = loadOrCreateGenesis(dir);
  const h = readHead(dir);
  if (!g.ok || !h.ok) throw new Error('chain files unreadable in test');
  const seq = (h.value?.seq ?? 0) + 1;
  const prev = h.value?.hash ?? g.value;
  const hash = eventHash({ ...e, seq, prev });
  const w = writeHeadAtomic(dir, { v: 1, genesis: g.value, seq, hash });
  if (!w.ok) throw new Error('head write failed in test');
  return { ...e, seq, prev, hash };
}

function build(events: readonly ShieldEvent[]): { dir: string; lines: Line[]; genesis: Genesis; head: HeadRecord } {
  const dir = tmp();
  const lines = events.map((e) => append(dir, e));
  const g = loadOrCreateGenesis(dir);
  const h = readHead(dir);
  if (!g.ok || !h.ok || h.value === null) throw new Error('no chain built');
  return { dir, lines, genesis: g.value, head: h.value };
}

describe('AC-2 / AC-3: genesis and head files', () => {
  it('AC-2: creates a 64-hex genesis once and returns the same value afterwards', () => {
    const dir = tmp();
    expect(readGenesis(dir)).toEqual({ ok: true, value: null });
    const a = loadOrCreateGenesis(dir, () => Buffer.alloc(32, 7));
    const b = loadOrCreateGenesis(dir, () => Buffer.alloc(32, 9));
    expect(a.ok && a.value).toMatch(/^[0-9a-f]{64}$/);
    expect(b).toEqual(a);
    expect(readGenesis(dir)).toEqual(a.ok ? { ok: true, value: a.value } : a);
  });
  it('AC-2: different random input gives different genesis values', () => {
    const a = loadOrCreateGenesis(tmp(), () => Buffer.alloc(32, 1));
    const b = loadOrCreateGenesis(tmp(), () => Buffer.alloc(32, 2));
    expect(a).not.toEqual(b);
  });
  it('AC-2: a damaged genesis file is an error result, not a throw or a silent new value', () => {
    const dir = tmp();
    writeFileSync(genesisPath(dir), 'not json');
    expect(loadOrCreateGenesis(dir).ok).toBe(false);
    expect(readFileSync(genesisPath(dir), 'utf8')).toBe('not json');
  });
  it('AC-2: a genesis file that is a symlink is refused', () => {
    const dir = tmp();
    writeFileSync(join(dir, 'real.json'), JSON.stringify({ v: 1, genesis: hex('a') }));
    symlinkSync(join(dir, 'real.json'), genesisPath(dir));
    expect(readGenesis(dir).ok).toBe(false);
  });
  it('AC-3: readHead is null when no head exists, and round-trips what writeHeadAtomic wrote', () => {
    const dir = tmp();
    expect(readHead(dir)).toEqual({ ok: true, value: null });
    const head: HeadRecord = { v: 1, genesis: hex('a'), seq: 3, hash: hex('b') };
    expect(writeHeadAtomic(dir, head).ok).toBe(true);
    expect(readHead(dir)).toEqual({ ok: true, value: head });
    const next = { ...head, seq: 4, hash: hex('c') };
    expect(writeHeadAtomic(dir, next).ok).toBe(true);
    expect(readHead(dir)).toEqual({ ok: true, value: next });
  });
  it('AC-3: writeHeadAtomic leaves no temp file behind', () => {
    const dir = tmp();
    writeHeadAtomic(dir, { v: 1, genesis: hex('a'), seq: 1, hash: hex('b') });
    expect(readdirSync(dir)).toEqual(['events.head.json']);
  });
  it('AC-3: a malformed or extra-field head is an error result', () => {
    const dir = tmp();
    for (const text of ['{', '{"v":1}', JSON.stringify({ v: 1, genesis: hex('a'), seq: 0, hash: hex('b') }), JSON.stringify({ v: 1, genesis: hex('a'), seq: 1, hash: hex('b'), x: 1 })]) {
      writeFileSync(headPath(dir), text);
      expect(readHead(dir).ok).toBe(false);
    }
  });
  it('AC-3: writeHeadAtomic rejects an invalid record and reports a missing folder as an error', () => {
    expect(writeHeadAtomic(tmp(), { v: 1, genesis: 'short', seq: 1, hash: hex('b') }).ok).toBe(false);
    const missing = join(tmp(), 'nope');
    expect(existsSync(missing)).toBe(false);
    expect(writeHeadAtomic(missing, { v: 1, genesis: hex('a'), seq: 1, hash: hex('b') }).ok).toBe(false);
  });
});

describe('AC-5: unchained lines after the chain began', () => {
  const chain = (): { lines: Line[]; genesis: Genesis; head: HeadRecord } => build(fc.sample(body, 4));
  const loose = (): Line => ({ v: 1, time: '2026-11-24T10:00:00.000Z', pid: 42, server: 'notes', kind: 'call', tool: 'x', decision: 'allowed' });

  it('AC-5: trailing unchained lines (a lock fallback) are tolerated and counted, not reported as broken', () => {
    const { lines, genesis, head } = chain();
    const r = verifyChain([...lines, loose(), loose()], head, genesis);
    expect(r).toEqual({ status: 'intact', head, unchained: 2 });
  });
  it('AC-5: an unchained line between chained lines is inserted, so a forged line cannot sit inside the chain', () => {
    const { lines, genesis, head } = chain();
    const r = verifyChain([...lines.slice(0, 2), loose(), ...lines.slice(2)], head, genesis);
    expect(r).toMatchObject({ status: 'broken', atSeq: 3, reason: 'inserted' });
  });
  it('AC-5: replacing the last chained event with an unchained line is caught by the head record', () => {
    const { lines, genesis, head } = chain();
    const r = verifyChain([...lines.slice(0, -1), loose()], head, genesis);
    expect(r).toMatchObject({ status: 'broken', reason: 'head-mismatch' });
  });
  it('AC-5: a log with no head but chained lines is broken, and a head with no chained lines is broken', () => {
    const { lines, genesis, head } = chain();
    expect(verifyChain(lines, null, genesis)).toMatchObject({ status: 'broken', reason: 'head-mismatch' });
    expect(verifyChain([loose()], head, genesis)).toMatchObject({ status: 'broken', reason: 'head-mismatch' });
  });
});

describe('Property 1: building a chain is self-consistent and matches the head', () => {
  // Feature: m12-audit-chain, Property 1: Building a chain from a sequence of events is self-consistent and matches the head
  it('AC-1: seq counts from 1, prev links back to the genesis, hash matches the canonical form, and the head equals the last line', () => {
    fc.assert(fc.property(bodies(1), (events) => {
      const { lines, genesis, head } = build(events);
      expect(lines).toHaveLength(events.length);
      lines.forEach((l, i) => {
        expect(l.seq).toBe(i + 1);
        expect(l.prev).toBe(i === 0 ? genesis : lines[i - 1]?.hash);
        const { hash, ...rest } = l;
        expect(hash).toBe(eventHash(rest as Parameters<typeof eventHash>[0]));
      });
      const last = lines[lines.length - 1] as Line;
      expect(head).toEqual({ v: 1, genesis, seq: last.seq, hash: last.hash });
    }), { numRuns: 100 });
  });
  it('AC-30: verifyChain reports intact, with the head, for every untouched chain', () => {
    fc.assert(fc.property(bodies(1), (events) => {
      const { lines, genesis, head } = build(events);
      expect(verifyChain(lines, head, genesis)).toEqual({ status: 'intact', head });
    }), { numRuns: 100 });
  });
  it('AC-4: the chain survives a round trip through JSON lines (file form)', () => {
    fc.assert(fc.property(bodies(1), (events) => {
      const { lines, genesis, head } = build(events);
      const reread = lines.map((l) => JSON.parse(JSON.stringify(l)) as Line);
      expect(verifyChain(reread, head, genesis).status).toBe('intact');
    }), { numRuns: 100 });
  });
});

describe('Property 3: a log with no chained events is not-chained, never broken', () => {
  // Feature: m12-audit-chain, Property 3: A log with no chained events is reported as not-chained, never as broken
  it('AC-5: any run of unchained events, including none, is not-chained', () => {
    fc.assert(fc.property(fc.array(body, { maxLength: 15 }), fc.boolean(), (events, withGenesis) => {
      const genesis = withGenesis ? hex('a') : null;
      expect(verifyChain(events, null, genesis)).toEqual({ status: 'not-chained' });
    }), { numRuns: 100 });
  });
});

describe('Property 4: any single-event tamper is detected', () => {
  // Feature: m12-audit-chain, Property 4: Any single-event tamper on a chained log is detected, and an untouched one is not
  type Tamper =
    | { op: 'change'; at: number }
    | { op: 'delete'; at: number }
    | { op: 'insert'; at: number; unchained: boolean }
    | { op: 'swap'; at: number };
  const tamper: fc.Arbitrary<Tamper> = fc.oneof(
    fc.record({ op: fc.constant('change' as const), at: fc.nat() }),
    fc.record({ op: fc.constant('delete' as const), at: fc.nat() }),
    fc.record({ op: fc.constant('insert' as const), at: fc.nat(), unchained: fc.boolean() }),
    fc.record({ op: fc.constant('swap' as const), at: fc.nat() }),
  );

  /** Apply a tamper; returns the tampered lines and the first 1-based position at which they differ from the original. */
  function apply(lines: readonly Line[], t: Tamper): { out: Line[]; firstDiff: number } | null {
    const n = lines.length;
    const out = lines.map((l) => ({ ...l }));
    if (t.op === 'change') {
      const i = t.at % n;
      const e = out[i] as Line;
      out[i] = e.kind === 'call' ? { ...e, tool: `${e.tool}!` } : { ...e, pid: e.pid + 1 };
      return { out, firstDiff: i + 1 };
    }
    if (t.op === 'delete') {
      const i = t.at % n;
      out.splice(i, 1);
      return { out, firstDiff: i + 1 };
    }
    if (t.op === 'swap') {
      if (n < 2) return null;
      const i = t.at % (n - 1);
      const a = out[i] as Line;
      out[i] = out[i + 1] as Line;
      out[i + 1] = a;
      return { out, firstDiff: i + 1 };
    }
    // insert: a well-formed event with a made-up link, or (strictly inside the chain) one with no chain fields
    if (t.unchained) {
      if (n < 2) return null;
      const i = 1 + (t.at % (n - 1));
      const forged: Line = { v: 1, time: '2026-11-24T10:00:00.000Z', pid: 1, server: 'notes', kind: 'call', tool: 'forged', decision: 'allowed' };
      out.splice(i, 0, forged);
      return { out, firstDiff: i + 1 };
    }
    const i = t.at % (n + 1);
    const base: Line = { v: 1, time: '2026-11-24T10:00:00.000Z', pid: 1, server: 'notes', kind: 'call', tool: 'forged', decision: 'allowed' };
    const seq = i + 1;
    const prev = hex('f');
    out.splice(i, 0, { ...base, seq, prev, hash: eventHash({ ...base, seq, prev }) });
    return { out, firstDiff: i + 1 };
  }

  it('AC-31: change, delete, insert or swap is reported broken at or before the first difference', () => {
    fc.assert(fc.property(bodies(1), tamper, (events, t) => {
      const { lines, genesis, head } = build(events);
      const r = apply(lines, t);
      fc.pre(r !== null);
      const { out, firstDiff } = r as { out: Line[]; firstDiff: number };
      const res = verifyChain(out, head, genesis);
      expect(res.status).toBe('broken');
      if (res.status === 'broken') expect(res.atSeq).toBeLessThanOrEqual(firstDiff);
    }), { numRuns: 200 });
  });
  it('AC-8: each tamper kind gets its own reason', () => {
    const { lines, genesis, head } = build(fc.sample(body, 4));
    const reasonOf = (out: Line[]): string => { const r = verifyChain(out, head, genesis); return r.status === 'broken' ? r.reason : r.status; };
    expect(reasonOf(lines.map((l, i) => (i === 1 && l.kind === 'call' ? { ...l, tool: 'z' } : i === 1 ? { ...l, pid: 99 } : l)))).toBe('changed');
    expect(reasonOf([lines[0] as Line, lines[2] as Line, lines[3] as Line])).toBe('removed');
    expect(reasonOf([lines[0] as Line, lines[2] as Line, lines[1] as Line, lines[3] as Line])).toBe('reordered');
  });
  it('AC-9: cutting events off the end is caught by the head record', () => {
    fc.assert(fc.property(bodies(2), fc.nat(), (events, k) => {
      const { lines, genesis, head } = build(events);
      const keep = 1 + (k % (lines.length - 1));
      const res = verifyChain(lines.slice(0, keep), head, genesis);
      expect(res).toMatchObject({ status: 'broken', reason: 'head-mismatch' });
    }), { numRuns: 100 });
  });
  it('AC-10: --expect matches the tip, and a different hash is expect-mismatch', () => {
    const { lines, genesis, head } = build(fc.sample(body, 3));
    expect(verifyChain(lines, head, genesis, { expect: { seq: head.seq, hash: head.hash } }).status).toBe('intact');
    expect(verifyChain(lines, head, genesis, { expect: { seq: head.seq, hash: hex('0') } })).toMatchObject({ status: 'broken', reason: 'expect-mismatch' });
    expect(verifyChain(lines, head, genesis, { expect: { seq: 99, hash: hex('0') } })).toMatchObject({ status: 'broken', reason: 'expect-mismatch' });
  });
  it('AC-8: deleting the first events is removed unless the caller allows a rotated start', () => {
    const { lines, genesis, head } = build(fc.sample(body, 4));
    expect(verifyChain(lines.slice(1), head, genesis)).toMatchObject({ status: 'broken', reason: 'removed', atSeq: 1 });
    expect(verifyChain(lines.slice(2), head, genesis, { allowRotatedStart: true })).toEqual({ status: 'intact', head });
    expect(verifyChain([lines[0] as Line, lines[2] as Line], head, genesis, { allowRotatedStart: true })).toMatchObject({ status: 'broken', reason: 'removed' });
  });
  it('AC-9: a head from a different genesis is head-mismatch', () => {
    const { lines, head } = build(fc.sample(body, 2));
    expect(verifyChain(lines, head, hex('9'))).toMatchObject({ status: 'broken', reason: 'head-mismatch' });
  });
});

