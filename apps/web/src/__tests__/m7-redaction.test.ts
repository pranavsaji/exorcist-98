import { describe, expect, it, vi } from 'vitest';
import { join } from 'node:path';
import { scanTarget } from '@/lib/scan-service';
import { redactSnippet } from '@/lib/snippet';
import type { PatchEvent, ScanEventMsg } from '@/lib/protocol';

vi.spyOn(console, 'log').mockImplementation(() => undefined);

// m7-precision, requirement 1: the web API never sends a secret in full.
const B62 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
function fakeChars(n: number, seed: number): string {
  let x = seed; let out = '';
  for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) % 2147483648; out += B62[(x >> 8) % 62]; }
  return out;
}
const GITHUB = `ghp_${fakeChars(36, 31)}`;
const ZWSP = String.fromCharCode(0x200b);

describe('web scan stream', { timeout: 60_000 }, () => {
  it('sends redacted findings, snippets and patch for a repository holding a key', async () => {
    const events: ScanEventMsg[] = [];
    for await (const ev of scanTarget({ kind: 'github', display: 'o/r', owner: 'o', repo: 'r' }, {
      lookup: null,
      clone: async (_t, dir) => {
        const { mkdir, writeFile } = await import('node:fs/promises');
        await mkdir(dir, { recursive: true });
        // A key on a line next to a fixable hidden character, so it appears as diff context too.
        await writeFile(join(dir, 'AGENTS.md'), `Be${ZWSP} kind.\nGITHUB_TOKEN=${GITHUB}\nThanks.\n`);
      },
    })) events.push(ev);

    const finding = events.find((e) => e.type === 'finding' && e.finding.ruleId === 'EX-011');
    expect(finding, 'the key is still detected').toBeDefined();
    const patch = events.find((e): e is PatchEvent => e.type === 'patch');
    expect(patch?.patch).toContain('Be kind.');

    const wire = JSON.stringify(events);
    expect(wire).not.toContain(GITHUB);
    expect(wire).not.toContain(GITHUB.slice(0, 14));
    expect(wire).toContain('[redacted github-token: ghp_…');
    if (finding?.type === 'finding') {
      expect(finding.finding.file).toBe('AGENTS.md');
      expect(finding.finding.line).toBe(2);
    }
  });
});

describe('redactSnippet', () => {
  it('redacts each part, and drops the highlight when a secret straddles two parts', () => {
    const whole = redactSnippet({ lines: [{ n: 1, before: 'KEY=', match: GITHUB, after: ' tail' }] });
    expect(JSON.stringify(whole)).not.toContain(GITHUB);
    expect(whole.lines[0]?.match).toContain('[redacted');

    const split = redactSnippet({ lines: [{ n: 2, before: `x ${GITHUB.slice(0, 10)}`, match: GITHUB.slice(10), after: '' }] });
    expect(JSON.stringify(split)).not.toContain(GITHUB.slice(0, 14));
    expect(split.lines[0]?.match).toBe('');
  });

  it('leaves a clean line untouched', () => {
    const s = { lines: [{ n: 1, before: 'a', match: 'b', after: 'c' }] };
    expect(redactSnippet(s)).toEqual(s);
  });
});

// m7-exemption-bypasses, item 4: the body of a multi-line private key is not
// shown. The markers are built at run time so this file holds no PEM header.
describe('private key blocks are blanked on every line', () => {
  const PEM = ['PRIVATE', 'KEY'].join(' ');
  const begin = `-----BEGIN RSA ${PEM}-----`;
  const end = `-----END RSA ${PEM}-----`;
  const body = ['EXAMPLEBODYLINEONEDONOTUSE0000', 'EXAMPLEBODYLINETWODONOTUSE1111'];
  const file = ['# notes', begin, ...body, end, 'after'].join('\n');

  it('redactSnippet blanks body lines that do not carry the BEGIN or END marker', async () => {
    const { buildSnippet } = await import('@/lib/snippet');
    const snip = redactSnippet(buildSnippet(file, 3, 1, body[0] ?? ''), file);
    const text = JSON.stringify(snip);
    for (const b of body) expect(text).not.toContain(b);
    expect(snip.lines.map((l) => l.n)).toEqual([1, 2, 3, 4, 5]);
    expect(snip.lines[0]?.before).toBe('# notes');
  });

  it('redactSnippet without the file text still works for a single line', () => {
    const s = { lines: [{ n: 1, before: 'a', match: 'b', after: 'c' }] };
    expect(redactSnippet(s)).toEqual(s);
  });

  it('the patch keeps its lines and hides the key body', async () => {
    const { redactPatch } = await import('@/lib/scan-service');
    const patch = ['--- a/k', '+++ b/k', '@@ -1,4 +1,4 @@', ` ${begin}`, `-${body[0]}`, `+${body[1]}`, ` ${end}`, ' tail'].join('\n');
    const out = redactPatch(patch);
    for (const b of body) expect(out).not.toContain(b);
    expect(out.split('\n')).toHaveLength(patch.split('\n').length);
    expect(out).toContain('--- a/k');
    expect(out.split('\n').at(-1)).toBe(' tail');
  });
});
