import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../../..');
const CLI_DIR = join(ROOT, 'packages/cli');
const BUNDLE = join(CLI_DIR, 'dist/index.mjs');
const FIXTURE = join(ROOT, 'fixtures/haunted-repo/EX-002-ai-instructions.md');

beforeAll(() => {
  execFileSync(process.execPath, [join(CLI_DIR, 'build.mjs')], { cwd: CLI_DIR, stdio: 'pipe' });
}, 60_000);

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-origin-cli-')); dirs.push(d); return d; };

function git(cwd: string, ...args: string[]): void {
  execFileSync('git', args, { cwd, stdio: 'ignore' });
}
const head = (cwd: string): string => execFileSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8' }).trim();

function run(args: string[], o: { cwd?: string } = {}) {
  const r = spawnSync(process.execPath, [BUNDLE, ...args], { cwd: o.cwd ?? ROOT, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

/** A git repo with a clean first commit and a Haunted Repo sample in the second. */
function makeRepo(): { dir: string; first: string; second: string } {
  const dir = tmp();
  git(dir, 'init', '-q');
  git(dir, 'config', 'user.email', 'human@example.invalid');
  git(dir, 'config', 'user.name', 'Human Author');
  writeFileSync(join(dir, 'README.md'), 'clean\n');
  git(dir, 'add', 'README.md');
  git(dir, 'commit', '-q', '-m', 'clean start');
  const first = head(dir);
  copyFileSync(FIXTURE, join(dir, 'ATTACK.md'));
  git(dir, 'add', 'ATTACK.md');
  git(dir, 'commit', '-q', '-m', 'add contributing guide');
  return { dir, first, second: head(dir) };
}

describe('exorcist origin', () => {
  it('prints help', () => {
    const r = run(['origin', '--help']);
    expect(r.code).toBe(0);
    expect(r.out).toContain('infection timeline');
    expect(r.out).toContain('--format <text|json>');
  });

  it('refuses to run outside a git repository', () => {
    const d = tmp();
    const r = run(['origin', d]);
    expect(r.code).toBe(2);
    expect(r.err).toContain('git');
  });

  it('blames the second commit, in text', () => {
    const { dir, first, second } = makeRepo();
    const r = run(['origin', dir]);
    expect(r.code).toBe(1);
    expect(r.out).toContain(second.slice(0, 7));
    expect(r.out).not.toContain(first.slice(0, 7));
    expect(r.out).toContain('by Human Author');
    expect(r.out).toContain('add contributing guide');
    expect(r.out).toMatch(/added \d+ threats?/);
    expect(r.out).toContain('ATTACK.md:');
  });

  it('emits a JSON timeline with the introducing commit', () => {
    const { dir, second } = makeRepo();
    const r = run(['origin', dir, '--format', 'json', '--fail-on', 'none']);
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out) as {
      tool: string; shallowClone: boolean;
      commits: Array<{ sha: string; author: string; subject: string; bot: boolean; threats: unknown[] }>;
      unknown: unknown[]; findingsTotal: number;
    };
    expect(report.tool).toBe('exorcist-origin');
    expect(report.shallowClone).toBe(false);
    expect(report.findingsTotal).toBeGreaterThan(0);
    expect(report.unknown).toEqual([]);
    expect(report.commits).toHaveLength(1);
    expect(report.commits[0]?.sha).toBe(second);
    expect(report.commits[0]?.author).toBe('Human Author');
    expect(report.commits[0]?.subject).toBe('add contributing guide');
    expect(report.commits[0]?.bot).toBe(false);
    expect((report.commits[0]?.threats.length ?? 0)).toBe(report.findingsTotal);
  });

  it('labels bot authors and sanitises hostile commit text', () => {
    const dir = tmp();
    git(dir, 'init', '-q');
    git(dir, 'config', 'user.email', '49699333+dependabot[bot]@users.noreply.github.com');
    git(dir, 'config', 'user.name', 'dependabot[bot]');
    copyFileSync(FIXTURE, join(dir, 'ATTACK.md'));
    git(dir, 'add', 'ATTACK.md');
    git(dir, 'commit', '-q', '-m', 'bump\u0007deps \u202Eevil');
    const r = run(['origin', dir, '--format', 'json', '--fail-on', 'none']);
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out) as { commits: Array<{ bot: boolean; subject: string; author: string }> };
    expect(report.commits[0]?.bot).toBe(true);
    expect(report.commits[0]?.author).toBe('dependabot[bot]');
    expect(report.commits[0]?.subject).toBe('bumpdeps evil');
    const text = run(['origin', dir, '--fail-on', 'none']);
    expect(text.out).toContain('(bot)');
    expect(text.out).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f]/);
  });

  it('notes missing history on a shallow clone', () => {
    const { dir } = makeRepo();
    const clone = tmp();
    execFileSync('git', ['clone', '-q', '--depth', '1', `file://${dir}`, clone], { stdio: 'ignore' });
    const text = run(['origin', clone, '--fail-on', 'none']);
    expect(text.code).toBe(0);
    expect(text.out).toContain('shallow clone');
    const json = run(['origin', clone, '--format', 'json', '--fail-on', 'none']);
    const report = JSON.parse(json.out) as { shallowClone: boolean; commits: Array<{ threats: unknown[] }> };
    expect(report.shallowClone).toBe(true);
    expect(report.commits.length).toBe(1);
    expect((report.commits[0]?.threats.length ?? 0)).toBeGreaterThan(0);
  });

  it('sorts the timeline by date across commits', () => {
    const { dir, second } = makeRepo();
    // A third, later commit adds another threat.
    copyFileSync(join(ROOT, 'fixtures/haunted-repo/EX-019-memory-poisoning.md'), join(dir, 'MEMORY.md'));
    git(dir, 'config', 'user.name', 'Later Author');
    git(dir, 'add', 'MEMORY.md');
    git(dir, 'commit', '-q', '-m', 'add memory notes');
    const r = run(['origin', dir, '--format', 'json', '--fail-on', 'none']);
    const report = JSON.parse(r.out) as { commits: Array<{ date: string; sha: string; author: string }> };
    const shas = report.commits.map((c) => c.sha);
    expect(shas).toContain(second);
    expect(report.commits.map((c) => c.author)).toEqual(
      [...report.commits.map((c) => c.author)].sort((a, b) => a.localeCompare(b)),
    );
    expect(report.commits.at(-1)?.author).toBe('Later Author');
  });
});
