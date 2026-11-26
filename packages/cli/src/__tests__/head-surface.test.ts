/** m12-audit-chain: head hash shown by `exorcist alerts` (AC-14) and `exorcist gate` (AC-15). */
import { afterEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { EventLog, alertsPath } from '@exorcist-98/shield';
import { alertsCommand } from '../commands/approve.js';
import { gateCommand } from '../commands/gate.js';
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (p: string): string => { const d = mkdtempSync(join(tmpdir(), p)); dirs.push(d); return d; };
function stateWithHead(): { dir: string; hash: string } {
  const dir = tmp('exorcist-head-state-');
  const log = new EventLog(dir, { server: 's', pid: 1 });
  log.write({ kind: 'call', tool: 't', decision: 'allowed' });
  const hash = (JSON.parse(readFileSync(join(dir, 'events.head.json'), 'utf8')) as { hash: string }).hash;
  return { dir, hash };
}
async function io(f: (o: { out: (s: string) => void; err: (s: string) => void }) => Promise<number>): Promise<{ code: number; out: string; err: string }> {
  let out = '';
  let err = '';
  const code = await f({ out: (s) => { out += s; }, err: (s) => { err += s; } });
  return { code, out, err };
}
const git = (cwd: string, ...a: string[]): void => {
  execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...a], { cwd });
};
function repo(): string {
  const d = tmp('exorcist-head-gate-');
  git(d, 'init', '-q');
  mkdirSync(join(d, '.kiro/steering'), { recursive: true });
  writeFileSync(join(d, '.kiro/steering/style.md'), '# Style\n');
  git(d, 'add', '-A');
  git(d, 'commit', '-qm', 'first');
  return d;
}
describe('exorcist alerts head hash', () => {
  it('AC-14: prints the head hash after the alert lines when a head file exists', async () => {
    const { dir, hash } = stateWithHead();
    writeFileSync(alertsPath(dir), `${JSON.stringify({ time: 't', severity: 'high', ruleId: 'R', server: 's', message: 'm' })}\n`);
    const r = await io((i) => alertsCommand(['--dir', dir], i));
    expect(r.code).toBe(0);
    expect(r.out).toContain(hash);
    expect(r.out.indexOf('HIGH')).toBeLessThan(r.out.indexOf(hash));
  });
  it('AC-14: prints the head hash even when there are no alerts', async () => {
    const { dir, hash } = stateWithHead();
    expect((await io((i) => alertsCommand(['--dir', dir], i))).out).toContain(hash);
  });
  it('AC-14: says plainly that no head exists yet', async () => {
    const dir = tmp('exorcist-head-empty-');
    expect((await io((i) => alertsCommand(['--dir', dir], i))).out).toContain('none yet');
  });
});
describe('exorcist gate head hash', () => {
  it('AC-15: a passing gate prints the head hash when a head file exists', async () => {
    const { dir, hash } = stateWithHead();
    const r = await io((i) => gateCommand([repo(), '--dir', dir], i));
    expect(r.code).toBe(0);
    expect(r.out).toContain(hash);
  });
  it('AC-15: a blocking gate includes the head hash in its output', async () => {
    const { dir, hash } = stateWithHead();
    const d = repo();
    mkdirSync(dirname(join(d, 'AGENTS.md')), { recursive: true });
    writeFileSync(join(d, 'AGENTS.md'), `# Agents\n${String.fromCodePoint(0xe0049, 0xe004e, 0xe0050)}\n`);
    const r = await io((i) => gateCommand([d, '--dir', dir], i));
    expect(r.code).toBe(1);
    expect(r.err).toContain(hash);
  });
  it('AC-15: stays silent when there is no head file', async () => {
    const r = await io((i) => gateCommand([repo(), '--dir', tmp('exorcist-head-none-')], i));
    expect(r).toEqual({ code: 0, out: '', err: '' });
  });
});
