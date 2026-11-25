/** m10-kiro-gate requirements 1.1, 1.3 to 1.7 and 1.10, on real temporary git repositories. */
import { describe, it, expect, afterEach } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gateCommand } from '../commands/gate.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const HIDDEN = String.fromCodePoint(0xe0049, 0xe004e, 0xe0050);
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

const git = (cwd: string, ...a: string[]): string =>
  execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...a], { cwd, encoding: 'utf8' });
const put = (repo: string, rel: string, text: string): void => {
  mkdirSync(dirname(join(repo, rel)), { recursive: true });
  writeFileSync(join(repo, rel), text);
};
/** A repository with one commit holding a steering file and a source file. */
function repo(): string {
  const d = mkdtempSync(join(tmpdir(), 'exorcist-gate-'));
  dirs.push(d);
  git(d, 'init', '-q');
  put(d, '.kiro/steering/style.md', '# Style\n\nUse tabs.\n');
  put(d, 'src/app.ts', 'export const x = 1;\n');
  git(d, 'add', '-A');
  git(d, 'commit', '-qm', 'first');
  return d;
}
async function gate(dir: string, extra: string[] = []): Promise<{ code: number; out: string; err: string }> {
  let out = '';
  let err = '';
  const code = await gateCommand([dir, ...extra], { out: (s) => { out += s; }, err: (s) => { err += s; } });
  return { code, out, err };
}

describe('exorcist gate', () => {
  it('passes with no change, and says nothing (1.6)', async () => {
    const r = await gate(repo());
    expect(r).toEqual({ code: 0, out: '', err: '' });
  });
  it('passes a clean change to an agent file (1.6)', async () => {
    const d = repo();
    put(d, '.kiro/steering/style.md', '# Style\n\nUse tabs.\nPrefer small functions.\n');
    put(d, 'AGENTS.md', '# Agents\n\nRun the tests.\n');
    expect(await gate(d)).toEqual({ code: 0, out: '', err: '' });
  });
  it('fails a change that adds hidden characters to a steering file, with a plain list (1.3)', async () => {
    const d = repo();
    put(d, '.kiro/steering/style.md', `# Style\n\nUse tabs.${HIDDEN}\n`);
    const r = await gate(d);
    expect(r.code).toBe(1);
    expect(r.err).toContain('.kiro/steering/style.md:3');
    expect(r.err).toContain('EX-001');
    expect(r.err).toContain('This file hides instructions for your AI');
    expect(r.err).toContain('fix:');
    expect(r.err).not.toContain(HIDDEN);
  });
  it('also catches a staged change and a brand-new untracked file (1.1, 1.5)', async () => {
    const d = repo();
    put(d, '.kiro/steering/style.md', `# Style\n\nUse tabs.${HIDDEN}\n`);
    git(d, 'add', '-A');
    expect((await gate(d)).code).toBe(1);
    git(d, 'commit', '-qm', 'oops');
    expect((await gate(d)).code).toBe(0); // now committed: the committed version has it
    put(d, 'AGENTS.md', `New file.${HIDDEN}\n`);
    const r = await gate(d);
    expect(r.code).toBe(1);
    expect(r.err).toContain('AGENTS.md:1');
  });
  it('ignores a finding that was already in the last commit (1.4)', async () => {
    const d = repo();
    put(d, '.kiro/steering/style.md', `# Style\n\nUse tabs.${HIDDEN}\n`);
    git(d, 'add', '-A');
    git(d, 'commit', '-qm', 'old finding');
    put(d, '.kiro/steering/style.md', `# Style\n\nA new first line.\nUse tabs.${HIDDEN}\nA new last line.\n`);
    expect(await gate(d)).toEqual({ code: 0, out: '', err: '' });
  });
  it('does not look at files an agent does not obey (1.2)', async () => {
    const d = repo();
    put(d, 'src/app.ts', `export const x = '${HIDDEN}';\n`);
    put(d, 'notes/todo.md', `todo${HIDDEN}\n`);
    expect((await gate(d)).code).toBe(0);
  });
  it('treats .kiro specs, hooks and agents as agent files (1.2)', async () => {
    const d = repo();
    put(d, '.kiro/specs/m1/design.md', `Design.${HIDDEN}\n`);
    expect((await gate(d)).err).toContain('.kiro/specs/m1/design.md');
  });
  it('--fail-on: a critical finding still fails at the strictest threshold; a bad value is a usage error', async () => {
    const d = repo();
    put(d, 'AGENTS.md', `x${HIDDEN}\n`);
    expect((await gate(d, ['--fail-on', 'critical'])).code).toBe(1);
    expect((await gate(d, ['--fail-on', 'nope'])).code).toBe(2);
  });
  it('exits 0 and says nothing was checked outside a git repository (1.10)', async () => {
    const d = mkdtempSync(join(tmpdir(), 'exorcist-gate-nogit-'));
    dirs.push(d);
    put(d, 'AGENTS.md', `x${HIDDEN}\n`);
    const r = await gate(d);
    expect(r.code).toBe(0);
    expect(r.out).toContain('nothing checked');
    expect(r.err).toBe('');
  });
  it('works before the first commit: everything is new (1.5)', async () => {
    const d = mkdtempSync(join(tmpdir(), 'exorcist-gate-empty-'));
    dirs.push(d);
    git(d, 'init', '-q');
    put(d, 'AGENTS.md', `x${HIDDEN}\n`);
    expect((await gate(d)).code).toBe(1);
  });
  it('reports an agent file that is too large to check instead of calling it clean (1.9)', async () => {
    const d = repo();
    writeFileSync(join(d, 'AGENTS.md'), Buffer.alloc(11 * 1_048_576, 0x61));
    const r = await gate(d, ['--fail-on', 'medium']);
    expect(r.code).toBe(1);
    expect(r.err).toContain('EX-026');
  });
  it('does not follow a symlink', async () => {
    const d = repo();
    put(d, 'outside.txt', `secret${HIDDEN}\n`);
    symlinkSync(join(d, 'outside.txt'), join(d, 'AGENTS.md'));
    expect((await gate(d)).code).toBe(0);
  });
  it('is read-only: git state and files are the same after a failing run (1.7)', async () => {
    const d = repo();
    put(d, '.kiro/steering/style.md', `# Style\n${HIDDEN}\n`);
    const before = git(d, 'status', '--porcelain=v2', '-z');
    const index = readFileSync(join(d, '.git/index'));
    await gate(d);
    expect(git(d, 'status', '--porcelain=v2', '-z')).toBe(before);
    expect(readFileSync(join(d, '.git/index')).equals(index)).toBe(true);
  });
  it('finishes well under a second on this repository (1.7)', async () => {
    const t0 = performance.now();
    const r = await gate(ROOT);
    const ms = performance.now() - t0;
    expect(r.code === 0 || r.code === 1).toBe(true);
    expect(ms).toBeLessThan(1000);
  });
  it('through the real CLI: exit code 1 and the list on stderr; the Kiro Stop hook command form', () => {
    const d = repo();
    put(d, '.kiro/steering/style.md', `# Style\n${HIDDEN}\n`);
    const r = spawnSync(join(ROOT, 'node_modules/.bin/tsx'), [join(ROOT, 'packages/cli/src/index.ts'), 'gate'], { cwd: d, encoding: 'utf8' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('EX-001');
    expect(r.stdout).toBe('');
  }, 30_000);
});
