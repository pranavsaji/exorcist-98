import { describe, it, expect, afterEach } from 'vitest';
import fc from 'fast-check';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanRepo } from '../scanner/orchestrator.js';
import { loadDefinitions } from '../definitions/loader.js';
import {
  findOriginCommit, gitRepoRoot, isBotAuthor, isShallowClone, sanitizeGitText,
} from '../origin.js';
import type { Finding } from '../types.js';
import { fromRoot } from './repo-root.js';

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function git(cwd: string, ...args: string[]): void {
  execFileSync('git', args, { cwd, stdio: 'ignore' });
}

/**
 * A throwaway repository with two commits: the first adds a clean README,
 * the second adds a defanged Haunted Repo sample (EX-002, instructions
 * addressed to an AI).
 */
async function makeTwoCommitRepo(): Promise<{ dir: string; first: string; second: string; findings: Finding[] }> {
  const dir = mkdtempSync(join(tmpdir(), 'exorcist-origin-'));
  dirs.push(dir);
  git(dir, 'init', '-q');
  git(dir, 'config', 'user.email', 'human@example.invalid');
  git(dir, 'config', 'user.name', 'Human Author');

  writeFileSync(join(dir, 'README.md'), 'A clean readme.\n');
  git(dir, 'add', 'README.md');
  git(dir, 'commit', '-q', '-m', 'start with a clean readme');
  const first = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();

  copyFileSync(fromRoot('fixtures/haunted-repo/EX-002-ai-instructions.md'), join(dir, 'ATTACK.md'));
  git(dir, 'add', 'ATTACK.md');
  git(dir, 'commit', '-q', '-m', 'add contributing guide');
  const second = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();

  const findings: Finding[] = [];
  for await (const ev of scanRepo(dir, { definitionsDir: fromRoot('definitions') })) {
    if (ev.type === 'finding' && ev.finding.file === 'ATTACK.md') findings.push(ev.finding);
  }
  return { dir, first, second, findings };
}

describe('sanitizeGitText', () => {
  it('removes terminal control sequences, bidi overrides and zero-width characters', () => {
    const hostile = 'evil\u0007subject\u202Ewith\u200Bhidden\u200Btext';
    expect(sanitizeGitText(hostile)).toBe('evilsubjectwithhiddentext');
    expect(sanitizeGitText('clean subject')).toBe('clean subject');
    expect(sanitizeGitText('  a\u200Bb  c\t\td ')).toBe('ab cd');
  });

  it('is idempotent and leaves ordinary Unicode untouched', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 40 }).noShrink(), (s) => {
        const once = sanitizeGitText(s);
        expect(sanitizeGitText(once)).toBe(once);
        for (const ch of once) {
          const cp = ch.codePointAt(0) ?? 0;
          expect(cp).toBeGreaterThan(0x1f);
          expect(cp).not.toBe(0x7f);
          expect(cp < 0x80 || cp > 0x9f).toBe(true);
          expect(cp < 0x200b || cp > 0x200f).toBe(true);
        }
      }),
      { numRuns: 100 },
    );
  });
});

describe('isBotAuthor', () => {
  it.each([
    ['dependabot[bot]', '49699333+dependabot[bot]@users.noreply.github.com', true],
    ['github-actions[bot]', 'bot@github.com', true],
    ['Renovate Bot', 'bot@renovate.example.invalid', true],
    ['Alice', 'alice@example.invalid', false],
    ['John Doe', 'john@company.example', false],
  ])('%s <%s> is labelled %s', (name, email, expected) => {
    expect(isBotAuthor(name, email)).toBe(expected);
  });
});

describe('findOriginCommit', () => {
  it('blames the commit that added the threat, not the earlier clean commit', async () => {
    const { dir, first, second, findings } = await makeTwoCommitRepo();
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      const hit = await findOriginCommit(dir, 'ATTACK.md', f.line, f.span);
      expect(hit.status).toBe('found');
      if (hit.status !== 'found') continue;
      expect(hit.commit.sha).toBe(second);
      expect(hit.commit.sha).not.toBe(first);
      expect(hit.commit.author).toBe('Human Author');
      expect(hit.commit.subject).toBe('add contributing guide');
    }
  });

  it('falls back to blaming the line when pickaxe finds no span', async () => {
    const { dir, second } = await makeTwoCommitRepo();
    const hit = await findOriginCommit(dir, 'ATTACK.md', 1, 'this span was never committed anywhere');
    expect(hit.status).toBe('found');
    if (hit.status === 'found') {
      expect(hit.method).toBe('blame');
      expect(hit.commit.sha).toBe(second);
    }
  });

  it('detects the repository root and shallow clones', async () => {
    const { dir } = await makeTwoCommitRepo();
    expect(await gitRepoRoot(dir)).toBe(realpathSync(dir));
    expect(await isShallowClone(dir)).toBe(false);

    const clone = mkdtempSync(join(tmpdir(), 'exorcist-shallow-'));
    dirs.push(clone);
    execFileSync('git', ['clone', '-q', '--depth', '1', `file://${dir}`, clone], { stdio: 'ignore' });
    expect(await isShallowClone(clone)).toBe(true);
  });

  it('still names a commit on a shallow clone, flagged as such', async () => {
    const { dir, second, findings } = await makeTwoCommitRepo();
    const clone = mkdtempSync(join(tmpdir(), 'exorcist-shallow-'));
    dirs.push(clone);
    execFileSync('git', ['clone', '-q', '--depth', '1', `file://${dir}`, clone], { stdio: 'ignore' });

    const f = findings[0];
    expect(f).toBeDefined();
    if (!f) return;
    const hit = await findOriginCommit(clone, 'ATTACK.md', f.line, f.span);
    expect(hit.status).toBe('found');
    if (hit.status === 'found') expect(hit.commit.sha).toBe(second);
  });

  it('sanitises a hostile commit subject and author name', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'exorcist-origin-'));
    dirs.push(dir);
    git(dir, 'init', '-q');
    git(dir, 'config', 'user.email', 'evil@example.invalid');
    git(dir, 'config', 'user.name', 'Evil\u202EAuthor\u0007');
    copyFileSync(fromRoot('fixtures/haunted-repo/EX-002-ai-instructions.md'), join(dir, 'ATTACK.md'));
    git(dir, 'add', 'ATTACK.md');
    // The subject carries a terminal bell, an escape sequence and bidi override.
    git(dir, 'commit', '-q', '-m', 'fix\u0007docs \u001b[31m\u202Edda');
    const findings: Finding[] = [];
    for await (const ev of scanRepo(dir, { definitionsDir: fromRoot('definitions') })) {
      if (ev.type === 'finding') findings.push(ev.finding);
    }
    expect(findings.length).toBeGreaterThan(0);
    const f = findings[0];
    if (!f) return;
    const hit = await findOriginCommit(dir, 'ATTACK.md', f.line, f.span);
    expect(hit.status).toBe('found');
    if (hit.status !== 'found') return;
    expect(hit.commit.subject).not.toMatch(/[\u0000-\u001f\u007f\u202a-\u202e\u200b-\u200f]/);
    expect(hit.commit.author).not.toMatch(/[\u0000-\u001f\u007f\u202a-\u202e\u200b-\u200f]/);
    expect(hit.commit.bot).toBe(false);
  });

  it('labels bot authors from git history', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'exorcist-origin-'));
    dirs.push(dir);
    git(dir, 'init', '-q');
    git(dir, 'config', 'user.email', '49699333+dependabot[bot]@users.noreply.github.com');
    git(dir, 'config', 'user.name', 'dependabot[bot]');
    copyFileSync(fromRoot('fixtures/haunted-repo/EX-002-ai-instructions.md'), join(dir, 'ATTACK.md'));
    git(dir, 'add', 'ATTACK.md');
    git(dir, 'commit', '-q', '-m', 'bump deps');
    const findings: Finding[] = [];
    for await (const ev of scanRepo(dir, { definitionsDir: fromRoot('definitions') })) {
      if (ev.type === 'finding') findings.push(ev.finding);
    }
    const f = findings[0];
    expect(f).toBeDefined();
    if (!f) return;
    const hit = await findOriginCommit(dir, 'ATTACK.md', f.line, f.span);
    expect(hit.status).toBe('found');
    if (hit.status === 'found') expect(hit.commit.bot).toBe(true);
  });

  it('loads definitions without an error (sanity for the test repos above)', async () => {
    expect((await loadDefinitions(fromRoot('definitions'))).length).toBeGreaterThan(0);
  });
});
