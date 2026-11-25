import { afterEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { originCommand } from '../commands/origin.js';
import { scanCommand } from '../commands/scan.js';
import type { Io } from '../util.js';

// m7-precision, requirement 1: no CLI format prints a secret in full.
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const DEFS = join(ROOT, 'definitions');
const B62 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
function fakeChars(n: number, seed: number): string {
  let x = seed; let out = '';
  for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) % 2147483648; out += B62[(x >> 8) % 62]; }
  return out;
}
const GITHUB = `ghp_${fakeChars(36, 21)}`;
const OPENAI = `sk-${fakeChars(48, 22)}`;
const SECRETS = [GITHUB, OPENAI];

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
function repoWithKeys(): string {
  const d = mkdtempSync(join(tmpdir(), 'exorcist-m7-cli-'));
  dirs.push(d);
  writeFileSync(join(d, 'README.md'), `# Setup\n\nGITHUB_TOKEN=${GITHUB}\nexport OPENAI_API_KEY=${OPENAI}\n`);
  return d;
}
const capture = (): Io & { text: () => string } => {
  const parts: string[] = [];
  return { out: (s) => { parts.push(s); }, err: (s) => { parts.push(s); }, text: () => parts.join('\n') };
};
const expectNoSecret = (what: string, text: string): void => {
  for (const s of SECRETS) {
    expect(text, `${what} printed a secret in full`).not.toContain(s);
    expect(text, `${what} printed most of a secret`).not.toContain(s.slice(0, 14));
  }
};

describe('exorcist scan keeps secrets out of every format', () => {
  for (const format of ['text', 'json', 'sarif', 'markdown', 'badge'] as const) {
    it(`--format ${format}`, async () => {
      const dir = repoWithKeys();
      const io = capture();
      const code = await scanCommand([dir, '--format', format, '--definitions', DEFS, '--fail-on', 'none'], io);
      expect(code).toBe(0);
      expectNoSecret(format, io.text());
      if (format === 'text') {
        expect(io.text()).toContain('README.md:3:');
        expect(io.text()).toContain('[redacted github-token: ghp_…');
      }
    });
  }

  it('--output writes a redacted file too', async () => {
    const dir = repoWithKeys();
    const file = join(dir, '..', `out-${Date.now()}.sarif`);
    dirs.push(file);
    await scanCommand([dir, '--format', 'sarif', '--definitions', DEFS, '--output', file, '--fail-on', 'none'], capture());
    expectNoSecret('sarif file', readFileSync(file, 'utf8'));
  });
});

describe('exorcist origin keeps secrets out of its timeline', () => {
  it('text and json', async () => {
    const dir = repoWithKeys();
    const env = {
      ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
      GIT_AUTHOR_NAME: 'A', GIT_AUTHOR_EMAIL: 'a@example.invalid', GIT_COMMITTER_NAME: 'A', GIT_COMMITTER_EMAIL: 'a@example.invalid',
    };
    const run = (...a: string[]): void => { execFileSync('git', a, { cwd: dir, env, stdio: 'ignore' }); };
    run('init', '-q');
    run('add', 'README.md');
    run('-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'add readme');
    for (const format of ['text', 'json']) {
      const io = capture();
      await originCommand([dir, '--format', format, '--definitions', DEFS, '--fail-on', 'none'], io);
      const out = io.text();
      expect(out).toContain('README.md');
      expectNoSecret(`origin ${format}`, out);
    }
  }, 60_000);
});
