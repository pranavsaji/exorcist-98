/** m12-audit-chain: `exorcist verify-log` wiring (AC-7 to AC-12), on real temporary state folders. */
import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventLog, eventsPath } from '@exorcist-98/shield';
import { verifyLogCommand } from '../commands/verify-log.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

function folder(n: number, chain = true): string {
  const d = mkdtempSync(join(tmpdir(), 'exorcist-verify-log-'));
  dirs.push(d);
  const log = new EventLog(d, { server: 's', pid: 1, chain });
  for (let i = 0; i < n; i++) log.write({ kind: 'call', tool: `t${i}`, decision: 'allowed' });
  return d;
}
const fileLines = (d: string): string[] => readFileSync(eventsPath(d), 'utf8').split('\n').filter((l) => l !== '');
const setLines = (d: string, l: string[]): void => writeFileSync(eventsPath(d), `${l.join('\n')}\n`);

async function run(args: string[]): Promise<{ code: number; out: string; err: string }> {
  let out = '';
  let err = '';
  const code = await verifyLogCommand(args, { out: (s) => { out += s; }, err: (s) => { err += s; } });
  return { code, out, err };
}
const headHash = (d: string): string => (JSON.parse(readFileSync(join(d, 'events.head.json'), 'utf8')) as { hash: string }).hash;

describe('exorcist verify-log', () => {
  it('AC-7: an intact log prints the head hash and exits 0', async () => {
    const d = folder(4);
    const r = await run(['--dir', d]);
    expect(r.code).toBe(0);
    expect(r.out).toContain('intact');
    expect(r.out).toContain(headHash(d));
  });

  it('AC-8: a changed event is named by sequence number, exit 1', async () => {
    const d = folder(4);
    writeFileSync(eventsPath(d), readFileSync(eventsPath(d), 'utf8').replace('"t1"', '"tX"'));
    const r = await run(['--dir', d]);
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/event 2: an event was changed/);
  });

  it('AC-8: a removed event is named by sequence number, exit 1', async () => {
    const d = folder(4);
    const l = fileLines(d);
    setLines(d, [l[0] as string, l[2] as string, l[3] as string]);
    const r = await run(['--dir', d]);
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/event 2: an event was removed/);
  });

  it('AC-8: an inserted event is reported, exit 1', async () => {
    const d = folder(3);
    const l = fileLines(d);
    const foreign = fileLines(folder(3))[1] as string; // well-formed, but chained under another genesis
    setLines(d, [l[0] as string, foreign, l[1] as string, l[2] as string]);
    const r = await run(['--dir', d]);
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/broken at event 2: an event was inserted/);
  });

  it('AC-8: swapped events are reported, exit 1', async () => {
    const d = folder(4);
    const l = fileLines(d);
    setLines(d, [l[0] as string, l[2] as string, l[1] as string, l[3] as string]);
    const r = await run(['--dir', d]);
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/event 2: events were swapped/);
  });

  it('AC-9: a log cut short is reported against its head record, exit 1', async () => {
    const d = folder(4);
    setLines(d, fileLines(d).slice(0, 3));
    const r = await run(['--dir', d]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("log's end does not match its head record");
  });

  it('AC-10: --expect with the current head hash exits 0; a different hash exits 1', async () => {
    const d = folder(3);
    expect((await run(['--dir', d, '--expect', headHash(d)])).code).toBe(0);
    const bad = await run(['--dir', d, '--expect', 'a'.repeat(64)]);
    expect(bad.code).toBe(1);
    expect(bad.out).toContain('does not match the expected hash');
  });

  it('AC-10: --expect seq:hash still matches after the log grows, and fails for a wrong hash', async () => {
    const d = folder(3);
    const saved = `3:${headHash(d)}`;
    const log = new EventLog(d, { server: 's', pid: 1 });
    log.write({ kind: 'call', tool: 'more', decision: 'allowed' });
    expect((await run(['--dir', d, '--expect', saved])).code).toBe(0);
    expect((await run(['--dir', d, '--expect', `3:${'b'.repeat(64)}`])).code).toBe(1);
  });

  it('AC-11: a malformed --expect, an unknown flag and an extra argument exit 2', async () => {
    const d = folder(1);
    expect((await run(['--dir', d, '--expect', 'nothex'])).code).toBe(2);
    expect((await run(['--dir', d, '--expect', 'abc123'])).code).toBe(2);
    expect((await run(['--dir', d, '--bogus'])).code).toBe(2);
    expect((await run(['--dir', d, 'extra'])).code).toBe(2);
  });

  it('AC-11: --help prints usage and exits 0', async () => {
    const r = await run(['--help']);
    expect(r.code).toBe(0);
    expect(r.out).toContain('Usage: exorcist verify-log');
  });

  it('AC-12: --json prints one object per status: intact, not-chained, broken', async () => {
    const intact = await run(['--dir', folder(2), '--json']);
    const a = JSON.parse(intact.out) as { status: string; head: { seq: number } };
    expect(intact.code).toBe(0);
    expect(intact.out.trim().split('\n')).toHaveLength(1);
    expect(a.status).toBe('intact');
    expect(a.head.seq).toBe(2);

    const old = await run(['--dir', folder(2, false), '--json']);
    expect(old.code).toBe(0);
    expect(JSON.parse(old.out)).toEqual({ status: 'not-chained' });

    const d = folder(3);
    setLines(d, fileLines(d).slice(0, 2));
    const broken = await run(['--dir', d, '--json']);
    const b = JSON.parse(broken.out) as { status: string; atSeq: number; reason: string };
    expect(broken.code).toBe(1);
    expect(b).toMatchObject({ status: 'broken', reason: 'head-mismatch' });
    expect(typeof b.atSeq).toBe('number');
  });

  it('AC-5: a log with no chain is reported as "not chained" in plain text and exits 0; with --expect it exits 1', async () => {
    const d = folder(2, false);
    const r = await run(['--dir', d]);
    expect(r.code).toBe(0);
    expect(r.out).toContain('not chained');
    expect((await run(['--dir', d, '--expect', 'a'.repeat(64)])).code).toBe(1);
  });
});
