import { describe, it, expect } from 'vitest';
import { SCENARIO_IDS } from '@exorcist-98/shield/simulator';
import { LAB_SCENARIOS, parseDeepLink, repoFromParam, shareQuery } from '@/lib/deeplink';

describe('deep links', () => {
  it('names exactly the Possession Lab scenarios the simulator has', () => {
    expect([...LAB_SCENARIOS]).toEqual([...SCENARIO_IDS]);
  });

  it('?repo= starts a scan of a public GitHub repository, with an optional branch', () => {
    expect(parseDeepLink('?repo=octocat/Hello-World')).toEqual({ kind: 'repo', url: 'https://github.com/octocat/Hello-World', label: 'octocat/Hello-World' });
    expect(parseDeepLink('?repo=octocat%2FHello-World%2Ftree%2Fmain')).toEqual({ kind: 'repo', url: 'https://github.com/octocat/Hello-World/tree/main', label: 'octocat/Hello-World@main' });
    expect(parseDeepLink('?repo=o/r/tree/release/v1.2')).toMatchObject({ label: 'o/r@release/v1.2' });
  });

  it.each([
    'o', 'o/', '/o/r', 'o/r/blob/main/x', 'o/r?x=1', 'o/r#frag', 'u:p@o/r', '../etc/passwd', 'o/r/tree/../x', 'o/r/tree/-x',
    'https://github.com/o/r', 'o/r/tree/', '-o/r', 'o/r/tree/a//b', 'o r/x', `${'a'.repeat(101)}/r`, 'javascript:alert(1)',
  ])('ignores an invalid repo value %j', (v) => {
    expect(repoFromParam(v)).toBeNull();
    expect(parseDeepLink(`?repo=${encodeURIComponent(v)}`)).toBeNull();
  });

  it('?demo= scans the Haunted Repo or plays a lab scenario; anything else is ignored', () => {
    expect(parseDeepLink('?demo=haunted')).toEqual({ kind: 'haunted' });
    expect(parseDeepLink('?demo=rug-pull')).toEqual({ kind: 'lab', scenario: 'rug-pull' });
    expect(parseDeepLink('?demo=canary')).toEqual({ kind: 'lab', scenario: 'canary' });
    expect(parseDeepLink('?demo=hidden-web-text')).toEqual({ kind: 'lab', scenario: 'hidden-web-text' });
    expect(parseDeepLink('?demo=settings-tamper')).toEqual({ kind: 'lab', scenario: 'settings-tamper' });
    for (const bad of ['Haunted', 'rug_pull', 'toString', '__proto__', '', 'haunted ']) expect(parseDeepLink(`?demo=${encodeURIComponent(bad)}`)).toBeNull();
  });

  it('?open= opens a window; unknown targets and repeated keys are ignored', () => {
    for (const t of ['byoa', 'field', 'map'] as const) expect(parseDeepLink(`?open=${t}`)).toEqual({ kind: 'open', target: t });
    expect(parseDeepLink('?open=about')).toBeNull();
    expect(parseDeepLink('?open=byoa&open=field')).toBeNull();
    expect(parseDeepLink('?demo=haunted&demo=rug-pull')).toBeNull();
    expect(parseDeepLink('')).toBeNull();
    expect(parseDeepLink(`?repo=${'a'.repeat(700)}`)).toBeNull();
  });

  it('a valid repo wins over demo, and demo over open; an invalid one falls through', () => {
    expect(parseDeepLink('?repo=o/r&demo=haunted')).toMatchObject({ kind: 'repo' });
    expect(parseDeepLink('?repo=bad&demo=haunted')).toEqual({ kind: 'haunted' });
    expect(parseDeepLink('?demo=nope&open=field')).toEqual({ kind: 'open', target: 'field' });
  });

  it('shareQuery reproduces a scan, and round-trips through parseDeepLink', () => {
    expect(shareQuery({ kind: 'haunted' })).toBe('?demo=haunted');
    expect(shareQuery({ kind: 'zip' })).toBe('');
    expect(shareQuery({ kind: 'repo', url: 'https://github.com/o/r.git' })).toBe('?repo=o/r');
    const q = shareQuery({ kind: 'repo', url: 'https://github.com/o/r/commit/abc123' });
    expect(q).toBe('?repo=o/r/tree/abc123');
    expect(parseDeepLink(q)).toMatchObject({ kind: 'repo', label: 'o/r@abc123' });
    expect(shareQuery({ kind: 'repo', url: 'https://evil.example/o/r' })).toBe('');
  });
});
