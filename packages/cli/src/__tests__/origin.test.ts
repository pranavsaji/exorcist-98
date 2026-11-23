import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../../..');
const CLI_DIR = join(ROOT, 'packages/cli');
const BUNDLE = join(CLI_DIR, 'dist/index.mjs');
const SAMPLE = join(ROOT, 'fixtures/haunted-repo/EX-002-ai-instructions.md');
const SAMPLE_2 = join(ROOT, 'fixtures/haunted-repo/EX-019-memory-poisoning.md');
const ESC = String.fromCharCode(0x1b);
const BEL = String.fromCharCode(0x07);
const RLO = String.fromCharCode(0x202e);
const ZWSP = String.fromCharCode(0x200b);
/** Anything a terminal could act on, or that hides text: C0/C1 controls (bar newline) and format characters. */
const UNSAFE = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\p{Cf}]/u;
/** Each test spawns the CLI and many git processes; give them room on a loaded machine. */
const SLOW = { timeout: 60_000 };

beforeAll(() => {
  execFileSync(process.execPath, [join(CLI_DIR, 'build.mjs')], { cwd: CLI_DIR, stdio: 'pipe' });
}, 120_000);

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-origin-cli-')); dirs.push(d); return d; };

type Who = { name?: string; email?: string; date?: string };
function git(cwd: string, args: string[], who: Who = {}): string {
  const date = who.date ?? '2026-10-01T12:00:00Z';
  return execFileSync('git', args, {
    cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    env: {
      ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
      GIT_AUTHOR_NAME: who.name ?? 'Human Author', GIT_AUTHOR_EMAIL: who.email ?? 'human@example.invalid',
      GIT_COMMITTER_NAME: 'Committer', GIT_COMMITTER_EMAIL: 'committer@example.invalid',
      GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date,
    },
  });
}
const commit = (dir: string, msg: string, who: Who = {}): string => {
  git(dir, ['add', '-A'], who);
  git(dir, ['commit', '-q', '--no-verify', '-m', msg], who);
  return git(dir, ['rev-parse', 'HEAD']).trim();
};

function run(args: string[], cwd = ROOT) {
  const r = spawnSync(process.execPath, [BUNDLE, ...args], { cwd, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

/** A git repo with a clean first commit and a Haunted Repo sample in the second. */
function makeRepo(file = 'ATTACK.md'): { dir: string; first: string; second: string } {
  const dir = tmp();
  git(dir, ['init', '-q']);
  writeFileSync(join(dir, 'README.md'), 'clean\n');
  const first = commit(dir, 'clean start', { date: '2026-10-01T12:00:00Z' });
  mkdirSync(dirname(join(dir, file)), { recursive: true });
  copyFileSync(SAMPLE, join(dir, file));
  const second = commit(dir, 'add contributing guide', { date: '2026-10-02T12:00:00Z' });
  return { dir, first, second };
}

type Report = {
  tool: string; shallowClone: boolean; notes: string[];
  limits: { perFindingMs: number; totalMs: number };
  commits: Array<{ sha: string; author: string; date: string; subject: string; bot: boolean; hiddenText: boolean; boundary: boolean; threats: Array<{ file: string; origin: string }> }>;
  unknown: Array<{ file: string; origin: string; reason?: string }>;
  findingsTotal: number;
};

describe('exorcist origin', () => {
  it('prints help, and is listed in the main help', () => {
    const r = run(['origin', '--help']);
    expect(r.code).toBe(0);
    expect(r.out).toContain('infection timeline');
    expect(r.out).toContain('--format <text|json>');
    expect(r.out).toContain('--max-time');
    expect(r.out).toContain('shallow clone');
    expect(run(['--help']).out).toContain('origin [dir]');
  });

  it('rejects bad options and refuses to run outside a git repository', SLOW, () => {
    expect(run(['origin', '--format', 'xml']).code).toBe(2);
    expect(run(['origin', '--max-time', '0']).code).toBe(2);
    expect(run(['origin', 'a', 'b']).code).toBe(2);
    const d = tmp();
    const r = run(['origin', d]);
    expect(r.code).toBe(2);
    expect(r.err).toContain('Not a git repository');
  });

  it('blames the second commit, in text', SLOW, () => {
    const { dir, first, second } = makeRepo();
    const r = run(['origin', dir]);
    expect(r.code).toBe(1);
    expect(r.out).toMatch(new RegExp(`${second.slice(0, 7)} by Human Author on 2026-10-02 added \\d+ threats`));
    expect(r.out).not.toContain(first.slice(0, 7));
    expect(r.out).toContain('subject: "add contributing guide"');
    expect(r.out).toContain('ATTACK.md:');
    expect(r.out).not.toContain('shallow');
  });

  it('emits a JSON timeline that names the introducing commit', SLOW, () => {
    const { dir, second } = makeRepo();
    const r = run(['origin', dir, '--format', 'json', '--fail-on', 'none']);
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out) as Report;
    expect(report.tool).toBe('exorcist-origin');
    expect(report.shallowClone).toBe(false);
    expect(report.notes).toEqual([]);
    expect(report.limits).toEqual({ perFindingMs: 10_000, totalMs: 120_000 });
    expect(report.findingsTotal).toBeGreaterThan(0);
    expect(report.unknown).toEqual([]);
    expect(report.commits).toHaveLength(1);
    const c = report.commits[0];
    expect(c?.sha).toBe(second);
    expect(c?.author).toBe('Human Author');
    expect(c?.subject).toBe('add contributing guide');
    expect(c?.bot).toBe(false);
    expect(c?.threats.length).toBe(report.findingsTotal);
  });

  it('traces findings in a sub-folder of the repository', SLOW, () => {
    const { dir, second } = makeRepo('docs/guide/ATTACK.md');
    const r = run(['origin', join(dir, 'docs'), '--format', 'json', '--fail-on', 'none']);
    const report = JSON.parse(r.out) as Report;
    expect(report.commits.map((c) => c.sha)).toEqual([second]);
    expect(report.commits[0]?.threats[0]?.file).toBe('guide/ATTACK.md');
  });

  it('labels bot authors and strips escape sequences and hidden characters from commit text', SLOW, () => {
    const dir = tmp();
    git(dir, ['init', '-q']);
    copyFileSync(SAMPLE, join(dir, 'ATTACK.md'));
    const sha = commit(dir, `bump${BEL} deps ${ESC}[2J${ESC}]0;owned${BEL}${RLO}evil${ZWSP}`, {
      name: `dependabot[bot]${ESC}[31m`, email: '49699333+dependabot[bot]@users.noreply.github.com',
    });
    const r = run(['origin', dir, '--format', 'json', '--fail-on', 'none']);
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out) as Report;
    expect(report.commits[0]?.bot).toBe(true);
    expect(report.commits[0]?.author).toBe('dependabot[bot]');
    expect(report.commits[0]?.subject).toBe('bump deps evil');
    expect(report.commits[0]?.hiddenText).toBe(true);

    const text = run(['origin', dir, '--fail-on', 'none']);
    expect(text.out).toContain(`${sha.slice(0, 7)} by dependabot[bot] (bot) on 2026-10-01 added`);
    expect(text.out).toContain('subject: "bump deps evil"');
    expect(text.out).toContain('hidden or control characters');
    expect(text.out).not.toMatch(UNSAFE);
    expect(text.out).not.toContain('owned');
  });

  it('shows a hostile file name inertly and keeps it from being read as a git option', SLOW, () => {
    const { dir, second } = makeRepo(`--output=owned.md`);
    // A second file whose name carries a terminal escape.
    copyFileSync(SAMPLE, join(dir, `evil${ESC}[2Jname.md`));
    commit(dir, 'more', { date: '2026-10-03T12:00:00Z' });
    const r = run(['origin', dir, '--fail-on', 'none']);
    expect(r.code).toBe(0);
    expect(existsSync(join(dir, 'owned.md'))).toBe(false);
    expect(r.out).toContain(`${second.slice(0, 7)} by Human Author`);
    expect(r.out).toContain('--output=owned.md:');
    expect(r.out).toContain('evil[U+001B][2Jname.md:');
    expect(r.out).not.toMatch(UNSAFE);
    const json = JSON.parse(run(['origin', dir, '--format', 'json', '--fail-on', 'none']).out) as Report;
    expect(json.unknown).toEqual([]);
    expect(json.commits).toHaveLength(2);
  });

  it('says plainly when history is missing on a shallow clone', SLOW, () => {
    const { dir, second } = makeRepo();
    const clone = tmp();
    rmSync(clone, { recursive: true });
    git(tmpdir(), ['clone', '-q', '--depth', '1', `file://${dir}`, clone]);
    const text = run(['origin', clone, '--fail-on', 'none']);
    expect(text.code).toBe(0);
    expect(text.out).toContain('Note: this is a shallow clone');
    expect(text.out).toContain('shallow cut-off');
    const report = JSON.parse(run(['origin', clone, '--format', 'json', '--fail-on', 'none']).out) as Report;
    expect(report.shallowClone).toBe(true);
    expect(report.notes[0]).toContain('shallow clone');
    expect(report.commits.map((c) => [c.sha, c.boundary])).toEqual([[second, true]]);
  });

  it('sorts the timeline by date, not by commit order, and lists uncommitted threats separately', SLOW, () => {
    const { dir, second } = makeRepo();
    // A later commit whose author date claims to be older than everything.
    copyFileSync(SAMPLE_2, join(dir, 'MEMORY.md'));
    const third = commit(dir, 'add memory notes', { name: 'Backdated Author', date: '2026-09-01T12:00:00Z' });
    mkdirSync(join(dir, 'wip'));
    copyFileSync(SAMPLE, join(dir, 'wip/LOCAL.md'));
    const report = JSON.parse(run(['origin', dir, '--format', 'json', '--fail-on', 'none']).out) as Report;
    expect(report.commits.map((c) => c.sha)).toEqual([third, second]);
    expect(report.unknown.length).toBeGreaterThan(0);
    expect(report.unknown.every((t) => t.file === 'wip/LOCAL.md' && t.origin === 'not-found')).toBe(true);
    const text = run(['origin', dir, '--fail-on', 'none']).out;
    expect(text.indexOf(third.slice(0, 7))).toBeLessThan(text.indexOf(second.slice(0, 7)));
    expect(text).toContain('Origin unknown');
  });

  it('a clean repository has nothing to trace', SLOW, () => {
    const dir = tmp();
    git(dir, ['init', '-q']);
    writeFileSync(join(dir, 'README.md'), 'clean\n');
    commit(dir, 'clean');
    const r = run(['origin', dir]);
    expect(r.code).toBe(0);
    expect(r.out).toContain('No threats found');
  });
});
