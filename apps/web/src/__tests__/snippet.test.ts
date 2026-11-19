import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { buildSnippet, revealHidden } from '@/lib/snippet';

const HIDDEN_RE = /[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}]/u;
const hiddenChar = fc.constantFrom(
  '\u200B', '\u200C', '\u200D', '\uFEFF', '\u202A', '\u202E', '\u2066', '\u2069',
  String.fromCodePoint(0xE0041), String.fromCodePoint(0xE007F),
);
// Text that may contain hidden characters but no newlines.
const lineText = fc
  .array(fc.oneof(fc.string({ maxLength: 8 }).map((s) => s.replace(/[\r\n]/g, ' ')), hiddenChar), { maxLength: 12 })
  .map((parts) => parts.join(''));

describe('revealHidden', () => {
  it('turns a zero-width space into a visible marker', () => {
    expect(revealHidden('a\u200Bb')).toBe('a[U+200B]b');
  });

  it('writes tag characters with six hex digits', () => {
    expect(revealHidden(String.fromCodePoint(0xE0041))).toBe('[U+E0041]');
  });

  it('PBT-WEB-02: output never contains a hidden code point', () => {
    fc.assert(
      fc.property(lineText, (t) => {
        expect(HIDDEN_RE.test(revealHidden(t))).toBe(false);
        return true;
      }),
    );
  });

  it('PBT-WEB-02: text without hidden characters is unchanged', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 60 }).filter((s) => !HIDDEN_RE.test(s)), (t) => {
        expect(revealHidden(t)).toBe(t);
        return true;
      }),
    );
  });
});

describe('buildSnippet', () => {
  const doc = ['one', 'two', 'three TARGET here', 'four', 'five', 'six'].join('\n');

  it('highlights the exact span with two lines of context each side', () => {
    const s = buildSnippet(doc, 3, 7, 'TARGET');
    expect(s.lines.map((l) => l.n)).toEqual([1, 2, 3, 4, 5]);
    expect(s.lines[2]).toEqual({ n: 3, before: 'three ', match: 'TARGET', after: ' here' });
    expect(s.lines[0]).toEqual({ n: 1, before: 'one', match: '', after: '' });
  });

  it('highlights a real hidden character for a unicode escape span', () => {
    const text = 'ab\u200Bcd';
    const s = buildSnippet(text, 1, 3, '\\u200B');
    expect(s.lines[0]).toEqual({ n: 1, before: 'ab', match: '[U+200B]', after: 'cd' });
  });

  it('highlights a supplementary-plane hidden character', () => {
    const tag = String.fromCodePoint(0xE0041);
    const text = `x${tag}y`;
    const s = buildSnippet(text, 1, 2, '\\u{E0041}');
    expect(s.lines[0]).toEqual({ n: 1, before: 'x', match: '[U+E0041]', after: 'y' });
  });

  it('handles a span truncated with an ellipsis', () => {
    const long = 'x'.repeat(130);
    const s = buildSnippet(`a ${long} b`, 1, 3, `${'x'.repeat(120)}…`);
    expect(s.lines[0]?.match.startsWith('x')).toBe(true);
    expect(s.lines[0]?.before).toBe('a ');
  });

  it('spreads a multi-line span across the lines it covers', () => {
    const text = 'a\n<!-- hidden\nmore -->\nz';
    const s = buildSnippet(text, 2, 1, '<!-- hidden\nmore -->');
    expect(s.lines[1]?.match).toBe('<!-- hidden');
    expect(s.lines[2]?.match).toBe('more -->');
  });

  it('returns no lines for a line number outside the file', () => {
    expect(buildSnippet('only', 5, 1, 'x').lines).toEqual([]);
  });

  it('keeps long lines short', () => {
    const text = `${'a'.repeat(500)}NEEDLE${'b'.repeat(500)}`;
    const l = buildSnippet(text, 1, 501, 'NEEDLE').lines[0];
    expect(l?.match).toBe('NEEDLE');
    expect((l?.before.length ?? 0) <= 121).toBe(true);
    expect((l?.after.length ?? 0) <= 121).toBe(true);
  });

  it('PBT-WEB-03: before + match + after equals the revealed line for any span on the line', () => {
    fc.assert(
      fc.property(lineText, fc.nat(40), fc.integer({ min: 1, max: 20 }), (line, a, len) => {
        // Cut on code point boundaries, as the engine does.
        const cps = Array.from(line);
        fc.pre(cps.length > 0);
        const i = a % cps.length;
        const span = cps.slice(i, i + len).join('');
        const col = cps.slice(0, i).join('').length + 1;
        fc.pre(span.length > 0 && !/^\\u/.test(span));
        const s = buildSnippet(line, 1, col, span);
        const l = s.lines[0];
        expect(l).toBeDefined();
        expect(`${l?.before}${l?.match}${l?.after}`).toBe(revealHidden(line));
        expect(l?.match).toBe(revealHidden(span));
        return true;
      }),
    );
  });
});
