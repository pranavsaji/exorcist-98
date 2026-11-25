// m6-os-release, task 15: `exorcist approve session` under OS release (REQ-09.1-09.5).
// Only fakes: the OsAuth and the terminal are test doubles, so no prompt or dialog can open.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileSessionStore, policyPath } from '@exorcist-98/shield';
import type { OsAuth, OsVerdict } from '@exorcist-98/shield';
import { APPROVE_HELP, approveCommand } from '../commands/approve.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

const KEY = 'p5151-abcd1234';

function setup(policy?: Record<string, unknown>) {
  const root = mkdtempSync(join(tmpdir(), 'exorcist-m6-approve-'));
  dirs.push(root);
  const dir = join(root, '.exorcist');
  const now = new Date().toISOString();
  new FileSessionStore(dir, KEY).write({
    version: 1, writer: '5151', updated: now,
    facts: [{ kind: 'untrusted', server: 'web', tool: 'fetch_url', ruleId: 'CAP-010', time: now }], grants: [],
  });
  if (policy) writeFileSync(policyPath(dir), JSON.stringify(policy));
  const out: string[] = [];
  const io = { out: (x: string) => void out.push(x), err: (x: string) => void out.push(x) };
  return { dir, io, out };
}

const fakeAuth = (available: boolean) => {
  const verify = vi.fn(async (_reason: string): Promise<OsVerdict> => 'ok');
  const auth: OsAuth = { available: async () => available, verify };
  return Object.assign(auth, { verify });
};

function term(interactive: boolean) {
  const dialog = vi.fn(async () => 'allow' as const);
  const ask = vi.fn(async () => '');
  return { t: { interactive, dialog, ask, nonce: () => 'c0ffee' }, dialog, ask };
}

describe('m6 approve session under OS release (REQ-09)', () => {
  it('os mode: prints the system-prompt message, exits 1, writes nothing, never opens the dialog (09.1, 09.2)', async () => {
    const { dir, io, out } = setup();
    const { t, dialog, ask } = term(true);
    const auth = fakeAuth(true);
    const before = readdirSync(join(dir, 'sessions', KEY)).sort();

    expect(await approveCommand(['session', KEY, '--dir', dir], io, t, auth)).toBe(1);

    expect(out.join('\n')).toContain('released in the system prompt');
    expect(out.join('\n')).toContain('Nothing was written here');
    expect(readdirSync(join(dir, 'sessions', KEY)).sort()).toEqual(before);
    expect(existsSync(join(dir, 'sessions', KEY, 'cli.json'))).toBe(false);
    expect(dialog).not.toHaveBeenCalled();
    expect(ask).not.toHaveBeenCalled();
    expect(auth.verify).not.toHaveBeenCalled();
  });

  it('os mode is decided before the interactive check: a non-interactive run gets the OS message (09.2)', async () => {
    const { dir, io, out } = setup({ sessionRelease: 'os' });
    expect(await approveCommand(['session', KEY, '--dir', dir], io, term(false).t, fakeAuth(true))).toBe(1);
    expect(out.join('\n')).toContain('system prompt');
    expect(out.join('\n')).not.toContain('only runs in an interactive terminal');
  });

  it('policy "terminal" behaves as before even when the OS check is available (09.3, 09.4)', async () => {
    const { dir, io, out } = setup({ sessionRelease: 'terminal' });
    const { t, dialog } = term(true);
    const auth = fakeAuth(true);
    const available = vi.spyOn(auth, 'available');

    expect(await approveCommand(['session', KEY, '--dir', dir], io, t, auth)).toBe(0);

    expect(available).not.toHaveBeenCalled();
    expect(dialog).toHaveBeenCalledTimes(1);
    expect(out.join('\n')).toContain('may send data out again');
    const cli = JSON.parse(readFileSync(join(dir, 'sessions', KEY, 'cli.json'), 'utf8')) as { grants: Array<{ by: string }> };
    expect(cli.grants.map((g) => g.by)).toEqual(['cli']);
  });

  it('osAuth unavailable falls back to the terminal behaviour (09.3, 09.4)', async () => {
    const { dir, io, out } = setup();
    const { t, dialog } = term(true);
    expect(await approveCommand(['session', KEY, '--dir', dir], io, t, fakeAuth(false))).toBe(0);
    expect(dialog).toHaveBeenCalledTimes(1);
    expect(out.join('\n')).toContain('may send data out again');
    expect(existsSync(join(dir, 'sessions', KEY, 'cli.json'))).toBe(true);
  });

  it('terminal fallback still refuses a non-interactive run', async () => {
    const { dir, io, out } = setup({ sessionRelease: 'terminal' });
    expect(await approveCommand(['session', KEY, '--dir', dir], io, term(false).t, fakeAuth(true))).toBe(1);
    expect(out.join('\n')).toContain('only runs in an interactive terminal');
    expect(existsSync(join(dir, 'sessions', KEY, 'cli.json'))).toBe(false);
  });

  it('APPROVE_HELP describes the OS release and the terminal fallback (09.5)', () => {
    expect(APPROVE_HELP).toMatch(/system prompt/u);
    expect(APPROVE_HELP).toMatch(/Touch ID/u);
    expect(APPROVE_HELP).toContain('"sessionRelease": "terminal"');
  });
});
