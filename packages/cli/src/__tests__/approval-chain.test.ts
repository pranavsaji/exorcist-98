/**
 * AC-29 / Property 9 for the CLI side: every approve session / allow-read outcome
 * (accepted, declined, expired, used) appends exactly one chained event, written to
 * the state folder, never holding the code. AC-28: refusal before any prompt.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eventsPath, verifyLogDir } from '@exorcist-98/shield';
import { CODE_TTL_MS, allowReadCommand, personConfirms, recordApproval } from '../commands/on-access.js';
import { approveCommand } from '../commands/approve.js';
import type { ApprovalAudit, DialogAnswer, Terminal } from '../commands/on-access.js';

const dirs: string[] = [];
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-approval-chain-cli-')); dirs.push(d); return d; };
let saved: string | undefined;
beforeEach(() => { saved = process.env['EXORCIST_DIR']; });
afterEach(() => {
  if (saved === undefined) delete process.env['EXORCIST_DIR']; else process.env['EXORCIST_DIR'] = saved;
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const NO_OS = { available: async () => false, verify: async () => 'error' as const };
const io = () => {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (s: string) => void out.push(s), err: (s: string) => void err.push(s) }, out, err };
};
const lines = (dir: string): Array<Record<string, unknown>> =>
  readFileSync(eventsPath(dir), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);

type Outcome = 'ok' | 'mismatch' | 'expired' | 'dialog-allow' | 'dialog-deny';
async function run(dir: string, outcome: Outcome, subject: ApprovalAudit['subject']) {
  const issued = 1_000_000;
  let step = 0;
  const term: Terminal = {
    interactive: true,
    osAuth: NO_OS,
    nonce: () => 'abc123',
    now: () => new Date(step++ === 0 ? issued : outcome === 'expired' ? issued + CODE_TTL_MS + 1 : issued + 1),
    ask: async () => (outcome === 'mismatch' ? 'zzzzzz' : 'abc123'),
    ...(outcome === 'dialog-allow' || outcome === 'dialog-deny'
      ? { dialog: async (): Promise<DialogAnswer> => (outcome === 'dialog-allow' ? 'allow' : 'deny') }
      : {}),
  };
  const r = io();
  const ok = await personConfirms(term, r.io, 'message', 'reason', { dir, subject });
  return { ok, out: r.out.join('\n') };
}

describe('CLI approval outcomes are chained', () => {
  it('AC-29: Property 9: each outcome appends exactly one chained event, intact, with the right decision and no code', async () => {
    const expected: Record<Outcome, 'allowed' | 'blocked'> = { ok: 'allowed', mismatch: 'blocked', expired: 'blocked', 'dialog-allow': 'allowed', 'dialog-deny': 'blocked' };
    await fc.assert(fc.asyncProperty(
      fc.constantFrom<Outcome>('ok', 'mismatch', 'expired', 'dialog-allow', 'dialog-deny'),
      fc.constantFrom<ApprovalAudit['subject']>('approve session', 'allow-read'),
      fc.integer({ min: 0, max: 3 }),
      async (outcome, subject, prior) => {
        const dir = tmp();
        for (let i = 0; i < prior; i++) recordApproval({ dir, subject }, 'accepted');
        const before = prior === 0 ? 0 : lines(dir).length;
        const r = await run(dir, outcome, subject);
        const all = lines(dir);
        expect(all.length - before).toBe(1);
        expect(all[all.length - 1]).toMatchObject({ kind: 'call', tool: subject, decision: expected[outcome], by: 'user', seq: before + 1 });
        expect(verifyLogDir(dir).status).toBe('intact');
        const raw = readFileSync(eventsPath(dir), 'utf8');
        expect(raw).not.toContain('abc123');
        expect(r.out).toContain(outcome.startsWith('dialog') ? '' : 'abc123');
      },
    ), { numRuns: 25 });
  });
  it('AC-29: an expired code is recorded as expired, and a used code as used', async () => {
    const dir = tmp();
    await run(dir, 'expired', 'allow-read');
    recordApproval({ dir, subject: 'allow-read' }, 'used');
    const [a, b] = lines(dir);
    expect(a?.['why']).toContain('expired');
    expect(b?.['why']).toContain('already been used');
    expect(verifyLogDir(dir).status).toBe('intact');
  });
  it('AC-29: recordApproval never throws and returns false when the state folder cannot be written', () => {
    const dir = join(tmp(), 'file');
    writeFileSync(dir, 'not a folder');
    expect(recordApproval({ dir: join(dir, 'sub'), subject: 'approve session' }, 'accepted')).toBe(false);
    expect(recordApproval(undefined, 'accepted')).toBe(false);
  });
  it('AC-29: allow-read writes its outcome to the state folder named by EXORCIST_DIR', async () => {
    const store = tmp();
    process.env['EXORCIST_DIR'] = store;
    const f = join(tmp(), 'NOTES.md');
    writeFileSync(f, 'x\n');
    const term: Terminal = { interactive: true, ask: async () => '', dialog: async () => 'deny', osAuth: NO_OS };
    expect(await allowReadCommand([f], io().io, term)).toBe(1);
    expect(lines(store)).toEqual([expect.objectContaining({ tool: 'allow-read', decision: 'blocked' })]);
  });
});

describe('who can run approve and allow-read', () => {
  it('AC-28: allow-read and approve session refuse before any prompt when not interactive, and record nothing', async () => {
    const store = tmp();
    process.env['EXORCIST_DIR'] = store;
    const asked: string[] = [];
    const term: Terminal = {
      interactive: false,
      ask: async (p) => { asked.push(p); return 'abc123'; },
      dialog: async (m) => { asked.push(m); return 'allow'; },
      osAuth: { available: async () => { asked.push('os'); return true; }, verify: async () => 'ok' },
      nonce: () => 'abc123',
    };
    const f = join(tmp(), 'NOTES.md');
    writeFileSync(f, 'x\n');
    expect(await allowReadCommand([f], io().io, term)).toBe(1);
    writeFileSync(join(store, 'policy.json'), JSON.stringify({ sessionRelease: 'terminal' }));
    expect(await approveCommand(['session', 'p1-key', '--dir', store], io().io, term, { available: async () => false, verify: async () => 'error' })).toBe(1);
    expect(asked).toEqual([]);
    expect(() => readFileSync(eventsPath(store))).toThrow();
  });
});
