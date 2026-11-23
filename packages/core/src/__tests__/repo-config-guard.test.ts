import { describe, it, expect, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { appendFileSync, chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dangerousKey, guardRepoConfig, locateRepo, parseGitConfig } from '../repo-config-guard.js';
import { findOriginCommit, mapLineToHead, openRepo } from '../origin.js';
import { fromRoot } from './repo-root.js';

const SAMPLE = fromRoot('fixtures/haunted-repo/EX-002-ai-instructions.md');
const SLOW = { timeout: 60_000 };

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = realpathSync(mkdtempSync(join(tmpdir(), 'exorcist-guard-'))); dirs.push(d); return d; };

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, {
    cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    env: {
      ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
      GIT_AUTHOR_NAME: 'Human', GIT_AUTHOR_EMAIL: 'human@example.invalid', GIT_COMMITTER_NAME: 'Human', GIT_COMMITTER_EMAIL: 'human@example.invalid',
    },
  });
}

/** A committed repo with the sample; hostile config is appended afterwards with plain file writes (never through git). */
function repoWithSample(): { dir: string; sha: string } {
  const dir = tmp();
  git(dir, ['init', '-q']);
  copyFileSync(SAMPLE, join(dir, 'ATTACK.md'));
  writeFileSync(join(dir, '.gitattributes'), '*.md filter=haunt diff=haunt\n');
  git(dir, ['add', '-A']);
  git(dir, ['commit', '-q', '--no-verify', '-m', 'add']);
  return { dir, sha: git(dir, ['rev-parse', 'HEAD']).trim() };
}

/** A harmless stand-in for "evil command": a script that only creates a marker file. */
function markerScript(dir: string, marker: string): string {
  const script = join(dir, '..', `${dir.split('/').pop() ?? 'x'}-hook.sh`);
  writeFileSync(script, `#!/bin/sh\ntouch '${marker}'\nexit 0\n`);
  chmodSync(script, 0o755);
  dirs.push(script);
  return script;
}

describe('parseGitConfig and dangerousKey', () => {
  const keysOf = (text: string): string[] => {
    const r = parseGitConfig(text);
    if (!r.ok) throw new Error(`parse error at ${r.line}`);
    return r.entries.map(dangerousKey).filter((k): k is string => k !== null);
  };

  it('lets an ordinary clone config through', () => {
    expect(keysOf([
      '[core]', '\trepositoryformatversion = 0', '\tfilemode = true', '\tbare = false', '\tfsmonitor = false',
      '[remote "origin"]', '\turl = https://example.invalid/filter/diff.git # a comment', '\tfetch = +refs/heads/*:refs/remotes/origin/*',
      '[branch "main"]', '\tremote = origin', '\tmerge = refs/heads/main',
      '[diff]', '\talgorithm = histogram',
    ].join('\n'))).toEqual([]);
  });

  it.each([
    ['[filter "x"]\n\tclean = touch m', 'filter.x.clean'],
    ['[filter "x"]\n\tsmudge = cat', 'filter.x.smudge'],
    ['[filter.x]\n\tprocess = run', 'filter.x.process'],
    ['[FILTER "x"]\n\tClean = run', 'filter.x.clean'],
    ['[diff "pdf"]\n\ttextconv = pdftotext', 'diff.pdf.textconv'],
    ['[diff "x"]\n\tcommand = run', 'diff.x.command'],
    ['[diff]\n\texternal = run', 'diff.external'],
    ['[core]\n\tfsmonitor = /tmp/hook', 'core.fsmonitor'],
    ['[core]\n\tfsmonitor', 'core.fsmonitor'],
    ['[core] fsmonitor = /tmp/hook', 'core.fsmonitor'],
    ['[core]\n\tsshCommand = run', 'core.sshcommand'],
    ['[core]\n\tgitProxy = run', 'core.gitproxy'],
    ['[core]\n\thooksPath = /tmp', 'core.hookspath'],
    ['[include]\n\tpath = other', 'include.path'],
    ['[includeIf "gitdir:/x/"]\n\tpath = other', 'includeif.gitdir:/x/.path'],
    ['[gpg]\n\tprogram = run', 'gpg.program'],
    ['[core]\n\tbare = false \\\n\n[filter "x"]\n\tclean = run', 'filter.x.clean'],
  ])('flags %j', (text, key) => {
    expect(keysOf(text)).toContain(key);
  });

  it('treats a value that continues onto the next line as one value', () => {
    expect(keysOf('[remote "o"]\n\turl = a \\\n[filter "x"]\n')).toEqual([]);
  });

  it('refuses what it cannot read rather than guessing', () => {
    expect(parseGitConfig('[core\n\tbare = false').ok).toBe(false);
    expect(parseGitConfig('key = before any section').ok).toBe(false);
    expect(parseGitConfig('[core]\n\t%%% = x').ok).toBe(false);
  });
});

describe('guardRepoConfig', SLOW, () => {
  it('accepts a fresh repository and finds it from a sub-folder', async () => {
    const { dir } = repoWithSample();
    mkdirSync(join(dir, 'sub'));
    const r = await guardRepoConfig(join(dir, 'sub'));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.repo.workTree).toBe(dir);
    expect(locateRepo(tmpdir()) === null || locateRepo(tmpdir())?.workTree !== dir).toBe(true);
  });

  it('refuses a filter driver, and git never runs it', async () => {
    const { dir } = repoWithSample();
    const marker = join(dir, 'MARKER-filter');
    appendFileSync(join(dir, '.git/config'), `[filter "haunt"]\n\tclean = touch '${marker}'\n\tsmudge = touch '${marker}'\n`);
    appendFileSync(join(dir, 'ATTACK.md'), 'local edit\n');
    const r = await guardRepoConfig(dir);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.kind).toBe('unsafe-config');
      expect(r.message).toContain('filter.haunt.clean');
      expect(r.message).toContain('Clone it fresh');
    }
    const o = await openRepo(dir);
    expect(o.ok).toBe(false);
    expect(existsSync(marker)).toBe(false);
  });

  it('refuses core.fsmonitor, and git never runs it', async () => {
    const { dir } = repoWithSample();
    const marker = join(dir, 'MARKER-fsmonitor');
    appendFileSync(join(dir, '.git/config'), `[core]\n\tfsmonitor = ${markerScript(dir, marker)}\n`);
    const r = await openRepo(dir);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.message).toContain('core.fsmonitor');
    expect(existsSync(marker)).toBe(false);
  });

  it('refuses textconv and include keys, and a config it cannot parse', async () => {
    for (const [extra, key] of [['[diff "haunt"]\n\ttextconv = cat\n', 'diff.haunt.textconv'], ['[include]\n\tpath = /dev/null\n', 'include.path']] as const) {
      const { dir } = repoWithSample();
      appendFileSync(join(dir, '.git/config'), extra);
      const r = await guardRepoConfig(dir);
      expect(!r.ok && r.message).toContain(key);
    }
    const { dir } = repoWithSample();
    appendFileSync(join(dir, '.git/config'), '[broken\n');
    const r = await guardRepoConfig(dir);
    expect(!r.ok && r.kind).toBe('unreadable-config');
  });

  it('checks the config of a linked worktree (.git is a file)', async () => {
    const { dir } = repoWithSample();
    const wt = join(tmp(), 'wt');
    git(dir, ['worktree', 'add', '-q', wt]);
    expect((await guardRepoConfig(wt)).ok).toBe(true);
    appendFileSync(join(dir, '.git/config'), '[filter "haunt"]\n\tclean = cat\n');
    expect((await guardRepoConfig(wt)).ok).toBe(false);
  });

  it('refuses a folder that is not in a repository without running git', async () => {
    const d = tmp();
    const r = await guardRepoConfig(d);
    // tmpdir is not normally inside a repository; if it is, this check is moot.
    if (!r.ok) expect(r.kind).toBe('not-a-repo');
  });
});

describe('git only reads committed objects', SLOW, () => {
  it('findOriginCommit never triggers a filter driver or fsmonitor, even without the guard', async () => {
    const { dir, sha } = repoWithSample();
    const filterMarker = join(dir, 'MARKER-filter');
    const fsmMarker = join(dir, 'MARKER-fsmonitor');
    appendFileSync(join(dir, '.git/config'), [
      '[filter "haunt"]', `\tclean = touch '${filterMarker}'`, `\tsmudge = touch '${filterMarker}'`,
      '[diff "haunt"]', `\ttextconv = touch '${filterMarker}'`,
      '[core]', `\tfsmonitor = ${markerScript(dir, fsmMarker)}`, '',
    ].join('\n'));
    // A local edit above the threat, so the working tree differs from HEAD.
    writeFileSync(join(dir, 'ATTACK.md'), `new first line\n${execFileSync('cat', [SAMPLE], { encoding: 'utf8' })}`);

    const hit = await findOriginCommit(dir, 'ATTACK.md', 12, 'Ignore previous instructions');
    expect(hit.status === 'found' && hit.commit.sha).toBe(sha);
    const local = await findOriginCommit(dir, 'ATTACK.md', 1, 'new first line');
    expect(local.status).toBe('uncommitted');
    expect(existsSync(filterMarker)).toBe(false);
    expect(existsSync(fsmMarker)).toBe(false);

    // Control: the old way (blame of the working tree) does run the filter,
    // so the assertions above would catch a regression.
    // (The filter prints nothing, so this blame then fails; the marker is the point.)
    try { git(dir, ['blame', '--porcelain', '-L', '1,1', '--', 'ATTACK.md']); } catch { /* expected */ }
    expect(existsSync(filterMarker)).toBe(true);
  });
});

describe('mapLineToHead', () => {
  it('maps an unchanged line, a shifted line, and nothing for a new line', () => {
    const head = 'a\nb\nc\n';
    expect(mapLineToHead(head, head, 2)).toBe(2);
    expect(mapLineToHead('new\na\nb\nc\n', head, 3)).toBe(2);
    expect(mapLineToHead('a\nb\nnew\nc\n', head, 3)).toBeNull();
    expect(mapLineToHead('a\n', head, 9)).toBeNull();
    expect(mapLineToHead('x\ny\nx\n', 'y\nx\n', 3)).toBe(2);
  });
});
