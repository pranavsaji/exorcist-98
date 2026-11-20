import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { parseGithubUrl } from '@/lib/github';

describe('parseGithubUrl', () => {
  it('accepts the plain form, .git and a trailing slash', () => {
    for (const u of [
      'https://github.com/owner/repo',
      'https://github.com/owner/repo.git',
      'https://github.com/owner/repo/',
      '  https://github.com/owner/repo  ',
    ]) {
      expect(parseGithubUrl(u)).toEqual({
        owner: 'owner',
        repo: 'repo',
        cloneUrl: 'https://github.com/owner/repo.git',
      });
    }
  });

  it('keeps dots, dashes and underscores in names', () => {
    expect(parseGithubUrl('https://github.com/a-b/c_d.e')?.repo).toBe('c_d.e');
  });

  it('rejects http, other hosts, credentials, queries, fragments and extra paths', () => {
    for (const u of [
      'http://github.com/o/r',
      'https://gitlab.com/o/r',
      'https://evil.com/github.com/o/r',
      'https://user:pw@github.com/o/r',
      'https://github.com.evil.com/o/r',
      'https://github.com/o/r?x=1',
      'https://github.com/o/r#frag',
      'https://github.com/o/r/blob/main/x.md',
      'https://github.com/o',
      'https://github.com//r',
      'https://github.com/../r',
      'https://github.com/o/..',
      'git@github.com:o/r.git',
      '--upload-pack=x',
      '',
    ]) {
      expect(parseGithubUrl(u), u).toBeNull();
    }
  });

  const name = fc.stringMatching(/^[A-Za-z0-9][A-Za-z0-9_-]{0,20}$/);

  it('PBT-WEB-04: accepted URLs always have the https://github.com/owner/repo shape', () => {
    fc.assert(
      fc.property(name, name, (o, r) => {
        const parsed = parseGithubUrl(`https://github.com/${o}/${r}`);
        expect(parsed).not.toBeNull();
        expect(parsed?.cloneUrl).toBe(`https://github.com/${o}/${r}.git`);
        return true;
      }),
    );
  });

  it('PBT-WEB-04: any suffix that adds a path, query, fragment or credentials is rejected', () => {
    const suffix = fc.constantFrom('/extra', '?x=1', '#h', '@evil', '/a/b', '%2e', ' x', ':80');
    fc.assert(
      fc.property(name, name, suffix, (o, r, s) => {
        expect(parseGithubUrl(`https://github.com/${o}/${r}${s}`)).toBeNull();
        return true;
      }),
    );
  });

  it('PBT-WEB-04: other hosts are rejected', () => {
    const host = fc.constantFrom('gitlab.com', 'github.io', 'raw.githubusercontent.com', 'example.invalid', 'localhost');
    fc.assert(
      fc.property(host, name, name, (h, o, r) => {
        expect(parseGithubUrl(`https://${h}/${o}/${r}`)).toBeNull();
        return true;
      }),
    );
  });
});

describe('W-020: branch, tag and commit links', () => {
  it('accepts /tree/<ref> and /commit/<sha>, keeping the ref', async () => {
    const { parseGithubUrl } = await import('@/lib/github');
    expect(parseGithubUrl('https://github.com/acme/widget/tree/release/2.0')).toMatchObject({ owner: 'acme', repo: 'widget', ref: 'release/2.0' });
    expect(parseGithubUrl('https://github.com/acme/widget/commit/9a72d8d')).toMatchObject({ ref: '9a72d8d' });
    expect(parseGithubUrl('https://github.com/acme/widget')?.ref).toBeUndefined();
  });
  it('refuses refs that could escape the path', async () => {
    const { parseGithubUrl } = await import('@/lib/github');
    for (const bad of ['../x', '-x', 'a//b', 'a b', 'a?b']) {
      expect(parseGithubUrl(`https://github.com/acme/widget/tree/${bad}`), bad).toBeNull();
    }
  });
});
