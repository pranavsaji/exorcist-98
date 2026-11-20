import { describe, it, expect, afterEach } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { findSecrets, findStagedSecrets, redact } from '../secrets-check.js';
import { decide, isGitCommit } from '../hook-guard.js';
import { fromRoot } from './repo-root.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = fromRoot();
const TSX = join(ROOT, 'node_modules/.bin/tsx');
const HOOK = join(ROOT, 'scripts/hook-pre-commit-secrets.ts');

// Shaped like an AWS access key id (the documented example shape), built at run
// time so this source file never contains a whole key.
const FAKE_KEY = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function git(cwd: string, ...args: string[]): void {
  execFileSync('git', args, { cwd, stdio: 'ignore' });
}

function makeRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'exorcist-secrets-'));
  dirs.push(dir);
  git(dir, 'init', '-q');
  git(dir, 'config', 'user.email', 'test@example.invalid');
  git(dir, 'config', 'user.name', 'Test');
  return dir;
}

describe('findSecrets placeholders (L-002)', () => {
  it('ignores a key that sits inside a placeholder token', () => {
    expect(findSecrets(`token=EXAMPLE_${FAKE_KEY}_DO_NOT_USE`)).toEqual([]);
  });

  it('still flags a real key written right next to a placeholder', () => {
    const hits = findSecrets(`EXAMPLE_TOKEN_DO_NOT_USE ${FAKE_KEY}`);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.match).toBe(FAKE_KEY);
  });

  it('redact never returns the full secret', () => {
    expect(redact(FAKE_KEY)).not.toBe(FAKE_KEY);
    expect(redact(FAKE_KEY).startsWith('AKIA')).toBe(true);
    expect(redact(FAKE_KEY)).not.toContain('ABCDEFGHIJKLMNOP');
  });
});

describe('findStagedSecrets (L-001)', () => {
  it('flags a staged file and reports its repo-relative path and line', () => {
    const repo = makeRepo();
    writeFileSync(join(repo, 'config.txt'), `a\nb\nkey = ${FAKE_KEY}\n`);
    git(repo, 'add', 'config.txt');
    const r = findStagedSecrets(repo);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.hits).toHaveLength(1);
    expect(r.hits[0]).toMatchObject({ file: 'config.txt', line: 3, pattern: 'aws-access-key' });
    expect(JSON.stringify(r)).not.toContain(FAKE_KEY);
  });

  it('works when called from a subdirectory (the original bug)', () => {
    const repo = makeRepo();
    mkdirSync(join(repo, 'packages/core'), { recursive: true });
    writeFileSync(join(repo, 'src.txt'), `key = ${FAKE_KEY}\n`);
    git(repo, 'add', 'src.txt');
    const r = findStagedSecrets(join(repo, 'packages/core'));
    expect(r.ok && r.hits.map((h) => h.file)).toEqual(['src.txt']);
  });

  it('ignores secrets that are not staged', () => {
    const repo = makeRepo();
    writeFileSync(join(repo, 'untracked.txt'), `key = ${FAKE_KEY}\n`);
    writeFileSync(join(repo, 'ok.txt'), 'nothing here\n');
    git(repo, 'add', 'ok.txt');
    const r = findStagedSecrets(repo);
    expect(r.ok && r.hits).toEqual([]);
  });

  it('does not flag placeholders in staged files', () => {
    const repo = makeRepo();
    writeFileSync(join(repo, 'fixture.env'), 'TOKEN=EXAMPLE_TOKEN_DO_NOT_USE\n');
    git(repo, 'add', 'fixture.env');
    const r = findStagedSecrets(repo);
    expect(r.ok && r.hits).toEqual([]);
  });

  it('reports an error outside a git repository', () => {
    const dir = mkdtempSync(join(tmpdir(), 'exorcist-nogit-'));
    dirs.push(dir);
    expect(findStagedSecrets(dir).ok).toBe(false);
  });
});

describe('hook decision', () => {
  const event = (command: string, cwd: string) => JSON.stringify({ hook_event_name: 'PreToolUse', cwd, tool_name: 'execute_bash', tool_input: { command } });

  it.each([
    ['git commit -m "x"', true],
    ['git add . && git commit -am wip', true],
    ['git -C some/dir commit -m x', true],
    ['git -c user.name=a commit -m x', true],
    ['git status', false],
    ['git log --grep commit', false],
    ['git committee', false],
    ['ls -la', false],
  ])('isGitCommit(%j) = %s', (cmd, expected) => {
    expect(isGitCommit(cmd)).toBe(expected);
  });

  it('blocks a commit with a staged secret and names the file', () => {
    const repo = makeRepo();
    writeFileSync(join(repo, 'leak.txt'), `k=${FAKE_KEY}\n`);
    git(repo, 'add', 'leak.txt');
    const d = decide(event('git commit -m x', repo));
    expect(d.exitCode).toBe(2);
    expect(d.message).toContain('leak.txt:1');
    expect(d.message).not.toContain(FAKE_KEY);
  });

  it('lets a clean commit and unrelated commands through', () => {
    const repo = makeRepo();
    writeFileSync(join(repo, 'ok.txt'), 'fine\n');
    git(repo, 'add', 'ok.txt');
    expect(decide(event('git commit -m x', repo)).exitCode).toBe(0);
    writeFileSync(join(repo, 'leak.txt'), `k=${FAKE_KEY}\n`);
    git(repo, 'add', 'leak.txt');
    expect(decide(event('ls -la', repo)).exitCode).toBe(0);
  });

  it('does not block on input it cannot read', () => {
    expect(decide('not json').exitCode).toBe(0);
  });

  it('as a real process: exit 2 with the reason on stderr, exit 0 when clean', () => {
    const repo = makeRepo();
    writeFileSync(join(repo, 'leak.txt'), `k=${FAKE_KEY}\n`);
    git(repo, 'add', 'leak.txt');
    const blocked = spawnSync(TSX, [HOOK], { cwd: repo, input: event('git commit -m x', repo), encoding: 'utf8' });
    expect(blocked.status).toBe(2);
    expect(blocked.stderr).toContain('leak.txt');
    expect(blocked.stderr).not.toContain(FAKE_KEY);

    git(repo, 'rm', '--cached', '-q', 'leak.txt');
    const clean = spawnSync(TSX, [HOOK], { cwd: repo, input: event('git commit -m x', repo), encoding: 'utf8' });
    expect(clean.status).toBe(0);
  });
});
