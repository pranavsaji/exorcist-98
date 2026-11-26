/**
 * EventLog.write chaining (m12-audit-chain task 3): concurrent writers, real
 * processes, and the unchained fallback.
 */
import { describe, expect, it, afterEach } from 'vitest';
import fc from 'fast-check';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadOrCreateGenesis, readHead, verifyChain } from '../chain.js';
import type { ChainStatus } from '../chain.js';
import { EventLog, eventsPath, parseEventLines } from '../events.js';

const ROOT = join(import.meta.dirname, '../../../..');
const TSX = join(ROOT, 'node_modules/.bin/tsx');
const WORKER = join(import.meta.dirname, 'event-writer-worker.ts');

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-chainw-')); dirs.push(d); return d; };

/** What `verify-log` will do: read the lines, head and genesis, run the pure core. */
function verifyDir(dir: string): { status: ChainStatus; seqs: (number | undefined)[]; count: number } {
  const text = existsSync(eventsPath(dir)) ? readFileSync(eventsPath(dir), 'utf8') : '';
  const { events } = parseEventLines(text);
  const head = readHead(dir);
  const genesis = loadOrCreateGenesis(dir);
  if (!head.ok || !genesis.ok) throw new Error('chain files unreadable in test');
  return { status: verifyChain(events, head.value, genesis.value), seqs: events.map((e) => e.seq), count: events.length };
}

describe('AC-6: concurrent appends', () => {
  it('AC-6: writers interleaved in any order still produce one ordered chain with no repeated seq', () => {
    fc.assert(
      fc.property(fc.array(fc.integer({ min: 0, max: 2 }), { minLength: 1, maxLength: 30 }), (schedule) => {
        const dir = tmp();
        // Three writers with their own state, as three Shield processes would have.
        const logs = [0, 1, 2].map((i) => new EventLog(dir, { server: `w${i}`, pid: 100 + i }));
        schedule.forEach((w, n) => {
          expect((logs[w] as EventLog).write({ kind: 'call', tool: `t${n}`, decision: 'allowed' })).toBe(true);
        });
        const r = verifyDir(dir);
        expect(r.seqs).toEqual(schedule.map((_, n) => n + 1));
        expect(r.status.status).toBe('intact');
        expect(logs.every((l) => l.problem === null)).toBe(true);
      }),
      { numRuns: 25 },
    );
  });

  it('AC-6: a stale lock folder left by a dead process is removed and the event is chained', () => {
    const dir = tmp();
    const lock = join(dir, 'events.lock');
    mkdirSync(lock);
    const old = new Date(Date.now() - 60_000);
    utimesSync(lock, old, old);
    const log = new EventLog(dir, { server: 'w', lockAttempts: 2 });
    expect(log.write({ kind: 'call', tool: 'a', decision: 'allowed' })).toBe(true);
    expect(verifyDir(dir).seqs).toEqual([1]);
    expect(existsSync(lock)).toBe(false);
  });
});

describe('AC-6: real processes', () => {
  it('AC-6: three Node processes appending to one state folder leave an intact chain with unique seq values', async () => {
    const dir = tmp();
    const run = (name: string): Promise<number> =>
      new Promise((resolve) => {
        const c = spawn(TSX, [WORKER, dir, name, '100', String(64 * 1024 * 1024)], { stdio: 'ignore' });
        c.on('close', (c2) => resolve(c2 ?? 1));
      });
    const codes = await Promise.all(['a', 'b', 'c'].map(run));
    expect(codes).toEqual([0, 0, 0]);
    const r = verifyDir(dir);
    expect(r.count).toBe(300);
    expect(new Set(r.seqs).size).toBe(300);
    expect(r.seqs).toEqual(Array.from({ length: 300 }, (_, i) => i + 1));
    expect(r.status.status).toBe('intact');
  }, 60_000);
});

describe('AC-5: unchained fallback and old logs', () => {
  it('AC-5: a log written with chain: false loads and reports not-chained', () => {
    const dir = tmp();
    const log = new EventLog(dir, { server: 'old', chain: false });
    expect(log.write({ kind: 'call', tool: 'a', decision: 'allowed' })).toBe(true);
    expect(log.write({ kind: 'call', tool: 'b', decision: 'blocked' })).toBe(true);
    const text = readFileSync(eventsPath(dir), 'utf8');
    expect(text).not.toMatch(/"seq"|"prev"|"hash"/);
    expect(existsSync(join(dir, 'events.head.json'))).toBe(false);
    expect(existsSync(join(dir, 'events.genesis.json'))).toBe(false);
    expect(verifyDir(dir).status).toEqual({ status: 'not-chained' });
  });

  it('AC-5: a lock that cannot be taken still writes the event, unchained, and sets problem', () => {
    const dir = tmp();
    mkdirSync(join(dir, 'events.lock')); // fresh, so not stale: held by "someone else"
    const log = new EventLog(dir, { server: 'w', lockAttempts: 2 });
    expect(log.write({ kind: 'call', tool: 'a', decision: 'allowed' })).toBe(true);
    expect(log.problem).toMatch(/lock/);
    const { events } = parseEventLines(readFileSync(eventsPath(dir), 'utf8'));
    expect(events).toHaveLength(1);
    expect(events[0]?.seq).toBeUndefined();
    expect(existsSync(join(dir, 'events.lock'))).toBe(true); // not ours: left alone
    expect(verifyDir(dir).status).toEqual({ status: 'not-chained' });
  });

  it('AC-5: an unchained line after chained ones is counted, not reported as a break', () => {
    const dir = tmp();
    const log = new EventLog(dir, { server: 'w', lockAttempts: 2 });
    log.write({ kind: 'call', tool: 'a', decision: 'allowed' });
    log.write({ kind: 'call', tool: 'b', decision: 'allowed' });
    mkdirSync(join(dir, 'events.lock'));
    log.write({ kind: 'call', tool: 'c', decision: 'allowed' });
    const r = verifyDir(dir);
    expect(r.seqs).toEqual([1, 2, undefined]);
    expect(r.status).toMatchObject({ status: 'intact', unchained: 1 });
  });

  it('AC-5: a later chained write after an unchained fallback is reported as inserted (design rule)', () => {
    const dir = tmp();
    const log = new EventLog(dir, { server: 'w', lockAttempts: 2 });
    log.write({ kind: 'call', tool: 'a', decision: 'allowed' });
    mkdirSync(join(dir, 'events.lock'));
    log.write({ kind: 'call', tool: 'b', decision: 'allowed' });
    rmSync(join(dir, 'events.lock'), { recursive: true });
    log.write({ kind: 'call', tool: 'c', decision: 'allowed' });
    expect(verifyDir(dir).status).toMatchObject({ status: 'broken', reason: 'inserted' });
  });
});

describe('AC-1 / AC-2 / AC-3: write wiring', () => {
  it('AC-1: seq starts at 1, prev is the genesis for the first line and the previous hash after', () => {
    const dir = tmp();
    const log = new EventLog(dir, { server: 'w', random: () => Buffer.alloc(32, 5) });
    log.write({ kind: 'call', tool: 'a', decision: 'allowed' });
    log.write({ kind: 'call', tool: 'b', decision: 'allowed' });
    const { events } = parseEventLines(readFileSync(eventsPath(dir), 'utf8'));
    const g = loadOrCreateGenesis(dir);
    expect(g.ok && events[0]?.prev).toBe(g.ok ? g.value : '');
    expect(events.map((e) => e.seq)).toEqual([1, 2]);
    expect(events[1]?.prev).toBe(events[0]?.hash);
  });

  it('AC-3: the head file matches the last written line, and no lock folder or temp file is left', () => {
    const dir = tmp();
    const log = new EventLog(dir, { server: 'w' });
    for (let i = 0; i < 5; i++) log.write({ kind: 'call', tool: `t${i}`, decision: 'allowed' });
    const { events } = parseEventLines(readFileSync(eventsPath(dir), 'utf8'));
    const h = readHead(dir);
    expect(h.ok && h.value).toMatchObject({ seq: 5, hash: events[4]?.hash });
    expect(existsSync(join(dir, 'events.lock'))).toBe(false);
    expect(log.problem).toBeNull();
  });
});
