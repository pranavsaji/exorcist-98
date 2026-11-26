/**
 * verifyLogDir (m12-audit-chain task 5): reads a real state folder and verifies it.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eventHash, loadOrCreateGenesis, verifyLogDir, writeHeadAtomic } from '../chain.js';
import { EventLog, eventsPath, oldEventsPath } from '../events.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-vld-')); dirs.push(d); return d; };

const write = (log: EventLog, n: number): void => {
  for (let i = 0; i < n; i++) log.write({ kind: 'call', tool: `t${i}`, decision: 'allowed' });
};

describe('verifyLogDir', () => {
  it('AC-7: a log written by EventLog is intact and the head matches', () => {
    const dir = tmp();
    write(new EventLog(dir, { server: 's', pid: 1 }), 5);
    const r = verifyLogDir(dir);
    expect(r.status).toBe('intact');
    if (r.status === 'intact') expect(r.head.seq).toBe(5);
  });

  it('AC-8: an edited line is reported as changed at its sequence number', () => {
    const dir = tmp();
    write(new EventLog(dir, { server: 's', pid: 1 }), 4);
    const text = readFileSync(eventsPath(dir), 'utf8');
    writeFileSync(eventsPath(dir), text.replace('"t2"', '"tX"'));
    const r = verifyLogDir(dir);
    expect(r).toMatchObject({ status: 'broken', atSeq: 3, reason: 'changed' });
  });

  it('AC-9: a log cut short is reported against the head file', () => {
    const dir = tmp();
    write(new EventLog(dir, { server: 's', pid: 1 }), 4);
    const lines = readFileSync(eventsPath(dir), 'utf8').split('\n').filter((l) => l !== '');
    writeFileSync(eventsPath(dir), `${lines.slice(0, 3).join('\n')}\n`);
    expect(verifyLogDir(dir)).toMatchObject({ status: 'broken', reason: 'head-mismatch' });
  });

  it('AC-10: --expect with the right head hash is intact, a wrong one is expect-mismatch', () => {
    const dir = tmp();
    write(new EventLog(dir, { server: 's', pid: 1 }), 3);
    const head = verifyLogDir(dir);
    if (head.status !== 'intact') throw new Error('setup');
    expect(verifyLogDir(dir, { expect: { seq: 3, hash: head.head.hash } }).status).toBe('intact');
    expect(verifyLogDir(dir, { expect: { seq: 3, hash: 'a'.repeat(64) } })).toMatchObject({ status: 'broken', reason: 'expect-mismatch' });
  });

  it('AC-5: an empty folder is not-chained', () => {
    expect(verifyLogDir(tmp()).status).toBe('not-chained');
  });

  it('AC-8: allowRotatedStart is set only when events.1.jsonl exists', () => {
    const dir = tmp();
    write(new EventLog(dir, { server: 's', pid: 1 }), 4);
    const lines = readFileSync(eventsPath(dir), 'utf8').split('\n').filter((l) => l !== '');
    // Without a rotated file, losing the first two events is `removed`.
    writeFileSync(eventsPath(dir), `${lines.slice(2).join('\n')}\n`);
    expect(verifyLogDir(dir)).toMatchObject({ status: 'broken', reason: 'removed' });
    // With one, the log may start later: the first two lines now sit in events.1.jsonl's place.
    writeFileSync(oldEventsPath(dir), `${lines.slice(0, 2).join('\n')}\n`);
    writeFileSync(eventsPath(dir), `${lines.slice(2).join('\n')}\n`);
    expect(verifyLogDir(dir).status).toBe('intact');
    // Dropping the oldest lines of a rotated pair is accepted (they were rotated away).
    writeFileSync(oldEventsPath(dir), `${lines.slice(1, 2).join('\n')}\n`);
    expect(verifyLogDir(dir).status).toBe('intact');
  });

  it('AC-13: verifies a 100,000-event chained log in under 15 seconds (5 s target alone, 3x headroom for parallel load)', () => {
    // Fast path: the lines are chained with eventHash directly (EventLog.write takes a lock and
    // rewrites the head file per event, and rotates at 1 MiB, so it cannot hold 100k events).
    // The log is read and verified by the real verifyLogDir.
    const dir = tmp();
    const g = loadOrCreateGenesis(dir);
    if (!g.ok) throw new Error('setup');
    const N = 100_000;
    const out: string[] = [];
    let prev = g.value;
    for (let seq = 1; seq <= N; seq++) {
      const e = { v: 1 as const, time: '2026-01-01T00:00:00.000Z', pid: 1, server: 's', kind: 'call' as const, tool: `tool${seq % 50}`, decision: 'allowed' as const, seq, prev };
      const hash = eventHash(e);
      out.push(JSON.stringify({ ...e, hash }));
      prev = hash;
    }
    writeFileSync(eventsPath(dir), `${out.join('\n')}\n`);
    const w = writeHeadAtomic(dir, { v: 1, genesis: g.value, seq: N, hash: prev });
    if (!w.ok) throw new Error('setup');

    const t0 = performance.now();
    const r = verifyLogDir(dir);
    const ms = performance.now() - t0;
    expect(r.status).toBe('intact');
    if (r.status === 'intact') expect(r.head.seq).toBe(N);
    // Alone this takes ~1.5 s; under a fully parallel suite it has reached ~5 s, so the bound
    // is 15 s. The measured time is logged so a regression toward the bound is visible.
    console.log(`AC-13 verifyLogDir(100000 events): ${Math.round(ms)} ms`);
    expect(ms).toBeLessThan(15_000);
  }, 60_000);
});
