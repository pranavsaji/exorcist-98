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

  it('redactSnippet blanks base64 lines next to a marker line even without the file text', () => {
    const b64 = fakeChars(64, 7);
    const s = { lines: [{ n: 5, before: b64, match: '', after: '' }, { n: 6, before: end, match: '', after: '' }, { n: 7, before: 'tail', match: '', after: '' }] };
    const out = redactSnippet(s);
    expect(JSON.stringify(out)).not.toContain(b64);
    expect(out.lines.map((l) => l.n)).toEqual([5, 6, 7]);
    expect(out.lines[2]?.before).toBe('tail');
  });

  it('redactSnippet without the file text still works for a single line', () => {
    const s = { lines: [{ n: 1, before: 'a', match: 'b', after: 'c' }] };
    expect(redactSnippet(s)).toEqual(s);
  });

  // Security review: a hunk can start in the middle of a key block, so its BEGIN
  // line is not in the diff text and the diff alone shows no key block.
  describe('a hunk that starts in the middle of a key block', () => {
    const lines = Array.from({ length: 6 }, (_, i) => fakeChars(64, 100 + i));
    const before = ['# notes', begin, ...lines, end, `Be${ZWSP} kind.`, 'after'].join('\n');
    const after = before.replace(ZWSP, '');
    // Context of 3 lines around line 10 (the changed one): lines 7..11, so the
    // hunk opens on key body line 6 (file line 7), 5 lines after BEGIN.
    const hunk = [
      'diff --git a/k.md b/k.md', '--- a/k.md', '+++ b/k.md', '@@ -7,5 +7,5 @@',
      ` ${lines[4]}`, ` ${lines[5]}`, ` ${end}`, `-Be${ZWSP} kind.`, '+Be kind.', ' after',
    ].join('\n');

    it('redactPatch blanks the key lines it can see, using the original file text', async () => {
      const { redactPatch } = await import('@/lib/scan-service');
      const out = redactPatch(hunk, [{ file: 'k.md', before, after }]);
      for (const l of lines) expect(out).not.toContain(l);
      expect(out.split('\n')).toHaveLength(hunk.split('\n').length);
      expect(out).toContain('+Be kind.');
      expect(out).toContain('@@ -7,5 +7,5 @@');
    });

    it('blanks long base64-only lines next to a blanked key line even without the source text', async () => {
      const { redactPatch } = await import('@/lib/scan-service');
      // Only the END line is recognisable here (an unmatched marker line), so the
      // base64 lines touching it are blanked by the backstop.
      const orphan = ['--- a/x', '+++ b/x', '@@ -1,4 +1,4 @@', ` ${lines[0]}`, ` ${lines[1]}`, ` ${end}`, ' tail'].join('\n');
      const out = redactPatch(orphan);
      expect(out).not.toContain(lines[0] ?? '');
      expect(out).not.toContain(lines[1] ?? '');
      expect(out.split('\n')).toHaveLength(orphan.split('\n').length);
      expect(out.split('\n').at(-1)).toBe(' tail');
    });

    it('the web stream hides the body when the hunk opens inside the block', async () => {
      const events: ScanEventMsg[] = [];
      const text = ['# notes', begin, ...lines, end, `Be${ZWSP} kind.`, 'after', ''].join('\n');
      for await (const ev of scanTarget({ kind: 'github', display: 'o/r', owner: 'o', repo: 'r' }, {
        lookup: null,
        clone: async (_t, dir) => {
          const { mkdir, writeFile } = await import('node:fs/promises');
          await mkdir(dir, { recursive: true });
          await writeFile(join(dir, 'AGENTS.md'), text);
        },
      })) events.push(ev);
      const patch = events.find((e): e is PatchEvent => e.type === 'patch');
      expect(patch?.patch).toContain('+Be kind.');
      const wire = JSON.stringify(events);
      for (const l of lines) expect(wire).not.toContain(l);
    });
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
