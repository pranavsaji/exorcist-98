import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';
import { decodeHidden, encodeAsTags, encodeAsVariationSelectors } from '../ouija.js';
import { decodeHidden as decodeHiddenBrowser } from '../browser.js';

const printableAscii: fc.Arbitrary<string> = fc
  .integer({ min: 0x20, max: 0x7e })
  .map((cp) => String.fromCharCode(cp))
  .noBias();

/** Random visible filler text: emoji, letters, spaces, ordinary variation selectors. */
const visibleText: fc.Arbitrary<string> = fc.array(
  fc.constantFrom('hello ', '❤️ ', '⭐', 'a', '😀 ', ' "', '\n', '!', '?', 'café', '初めまして'),
  { maxLength: 20 },
).map((parts) => parts.join(''));

describe('PBT-OUI-01: tag smuggling round-trips', () => {
  it('decodes the hidden ASCII back out of random visible text', () => {
    fc.assert(
      fc.property(fc.array(printableAscii, { minLength: 2, maxLength: 40 }), visibleText, (chars, before, after) => {
        const secret = chars.join('');
        const text = `${before}${encodeAsTags(secret)}${after}`;
        const msgs = decodeHidden(text);
        expect(msgs.some((m) => m.kind === 'tag' && m.message === secret)).toBe(true);
        return true;
      }),
      { numRuns: 200 },
    );
  });
});

describe('PBT-OUI-02: variation-selector smuggling round-trips', () => {
  it('decodes the smuggled bytes back after a random base character', () => {
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 0, max: 255 }), { minLength: 4, maxLength: 64 }),
        fc.constantFrom('⭐', '❤', '😀', 'a', '*'),
        (bytes, base) => {
          const text = `${base}${encodeAsVariationSelectors(bytes)}`;
          const msgs = decodeHidden(text);
          const m = msgs.find((x) => x.kind === 'variation-selector');
          expect(m).toBeDefined();
          expect(m?.bytes).toEqual(bytes);
          return true;
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe('PBT-OUI-03: clean text decodes to nothing', () => {
  it('no tag characters and at most two adjacent variation selectors', () => {
    fc.assert(
      fc.property(visibleText, fc.integer({ min: 0, max: 2 }), (text, vs) => {
        const tail = '\uFE0F'.repeat(vs);
        const clean = `${text}${tail} more text`;
        expect(decodeHidden(clean)).toEqual([]);
        return true;
      }),
      { numRuns: 200 },
    );
  });
});

describe('Ouija decoder boundaries (REQ-01/02/04)', () => {
  it('a tag run of one character is not a message', () => {
    expect(decodeHidden('a\u{E0041}b')).toEqual([]);
  });

  it('drops U+E0001 and U+E007F but keeps the mapped characters', () => {
    const text = `\u{E0001}${encodeAsTags('hi')}\u{E007F}`;
    const msgs = decodeHidden(text);
    expect(msgs).toHaveLength(1);
    expect(msgs[0]?.message).toBe('hi');
  });

  it('a run of three variation selectors is not reported; four are', () => {
    expect(decodeHidden(`⭐${'\uFE00'.repeat(3)}`)).toEqual([]);
    const four = decodeHidden(`⭐${encodeAsVariationSelectors([0x68, 0x69, 0x21, 0x21])}`);
    expect(four).toHaveLength(1);
    expect(four[0]?.message).toBe('hi!!');
  });

  it('invalid UTF-8 bytes decode to hex pairs', () => {
    const msgs = decodeHidden(`⭐${encodeAsVariationSelectors([0xff, 0xfe, 0x01, 0x80])}`);
    expect(msgs).toHaveLength(1);
    expect(msgs[0]?.message).toBe('0xff 0xfe 0x01 0x80');
  });

  it('truncates long messages to 500 characters', () => {
    const secret = 'A'.repeat(600);
    const msgs = decodeHidden(encodeAsTags(secret));
    expect(msgs[0]?.message.length).toBeLessThanOrEqual(501);
    expect(msgs[0]?.message.startsWith('AAAA')).toBe(true);
  });

  it('caps the number of runs at 100', () => {
    const parts: string[] = [];
    for (let i = 0; i < 150; i++) parts.push(encodeAsTags('ab'));
    expect(decodeHidden(parts.join('x'))).toHaveLength(100);
  });

  it('finds runs inside ordinary words', () => {
    const text = `Read the do${encodeAsTags('rm -rf')}cs now`;
    const msgs = decodeHidden(text);
    expect(msgs[0]?.message).toBe('rm -rf');
  });

  it('is exported from the browser entry and is the same function', () => {
    expect(decodeHiddenBrowser(encodeAsTags('web'))[0]?.message).toBe('web');
  });
});
