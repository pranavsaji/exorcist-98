import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';
import {
  decodeHidden, decodeVsBytes, displayMessage, encodeAsTags, encodeAsVariationSelectors, truncateMessage,
  MAX_DECODED_CHARS, MAX_HIDDEN_RUNS, MAX_VS_BYTES,
} from '../ouija.js';
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
  it('decodes the hidden ASCII back out of random visible text, at the right offsets', () => {
    fc.assert(
      fc.property(fc.array(printableAscii, { minLength: 2, maxLength: 40 }), visibleText, visibleText, (chars, before, after) => {
        const secret = chars.join('');
        const hidden = encodeAsTags(secret);
        const text = `${before}${hidden}${after}`;
        const tags = decodeHidden(text).filter((m) => m.kind === 'tag');
        expect(tags).toHaveLength(1);
        expect(tags[0]?.message).toBe(secret);
        expect(text.slice(tags[0]?.start, tags[0]?.end)).toBe(hidden);
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
        fc.constantFrom('⭐', '❤', '😀', 'a', '*', '字'),
        visibleText,
        (bytes, base, after) => {
          const hidden = encodeAsVariationSelectors(bytes);
          const text = `${base}${hidden} ${after}`;
          const vs = decodeHidden(text).filter((m) => m.kind === 'variation-selector');
          expect(vs).toHaveLength(1);
          expect(vs[0]?.bytes).toEqual(bytes);
          expect(vs[0]?.message).toBe(decodeVsBytes(bytes));
          expect(text.slice(vs[0]?.start, vs[0]?.end)).toBe(hidden);
          return true;
        },
      ),
      { numRuns: 200 },
    );
  });

  it('valid UTF-8 bytes decode to the original text (any script)', () => {
    fc.assert(
      fc.property(fc.fullUnicodeString({ minLength: 2, maxLength: 30 }), (s) => {
        const bytes = Array.from(new TextEncoder().encode(s));
        fc.pre(bytes.length >= 4);
        const [m] = decodeHidden(`⭐${encodeAsVariationSelectors(bytes)}`);
        expect(m?.message).toBe(s);
        return true;
      }),
      { numRuns: 200 },
    );
  });
});

/** Any code point except tag characters (U+E0000-E007F) and lone surrogates. */
const noTagChar: fc.Arbitrary<string> = fc
  .integer({ min: 0, max: 0x10FFFF })
  .filter((cp) => !(cp >= 0xD800 && cp <= 0xDFFF) && !(cp >= 0xE0000 && cp <= 0xE007F))
  .map((cp) => String.fromCodePoint(cp));
const vsChar: fc.Arbitrary<string> = fc
  .oneof(fc.integer({ min: 0xFE00, max: 0xFE0F }), fc.integer({ min: 0xE0100, max: 0xE01EF }))
  .map((cp) => String.fromCodePoint(cp));
const isVs = (ch: string): boolean => {
  const cp = ch.codePointAt(0) ?? 0;
  return (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF);
};
/** Break up every run of more than two variation selectors with a space. */
function capVsRuns(chars: string[]): string {
  let out = '';
  let run = 0;
  for (const ch of chars) {
    run = isVs(ch) ? run + 1 : 0;
    if (run > 2) { out += ' '; run = 1; }
    out += ch;
  }
  return out;
}

describe('PBT-OUI-03: clean text decodes to nothing', () => {
  it('no tag characters and at most two adjacent variation selectors', () => {
    fc.assert(
      fc.property(fc.array(fc.oneof(noTagChar, vsChar, printableAscii), { maxLength: 80 }), (chars) => {
        expect(decodeHidden(capVsRuns(chars))).toEqual([]);
        return true;
      }),
      { numRuns: 300 },
    );
  });

  it('ordinary emoji text (one U+FE0F per emoji) decodes to nothing', () => {
    fc.assert(
      fc.property(visibleText, fc.integer({ min: 0, max: 2 }), (text, vs) => {
        expect(decodeHidden(`${text}${'\uFE0F'.repeat(vs)} more text`)).toEqual([]);
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

  it('truncates long messages to at most 500 characters, ending in an ellipsis', () => {
    const msgs = decodeHidden(encodeAsTags('A'.repeat(600)));
    expect(msgs[0]?.message).toHaveLength(MAX_DECODED_CHARS);
    expect(msgs[0]?.message.endsWith('…')).toBe(true);
    expect(decodeHidden(encodeAsTags('B'.repeat(500)))[0]?.message).toBe('B'.repeat(500));
    const long = decodeHidden(`⭐${encodeAsVariationSelectors(Array.from(new TextEncoder().encode('é'.repeat(400))))}`);
    expect(long[0]?.message.length).toBeLessThanOrEqual(MAX_DECODED_CHARS);
  });

  it('never splits a surrogate pair when truncating', () => {
    const cut = truncateMessage(`${'x'.repeat(498)}😀😀😀`);
    expect(cut.length).toBeLessThanOrEqual(MAX_DECODED_CHARS);
    expect(cut).toBe(`${'x'.repeat(498)}…`);
  });

  it('a very long run is bounded: bytes are capped and a character cut at the cap is dropped, not turned to hex', () => {
    const bytes = Array.from(new TextEncoder().encode('é'.repeat(5000)));
    const [m] = decodeHidden(`⭐${encodeAsVariationSelectors(bytes)}`);
    expect(m?.bytes?.length).toBe(MAX_VS_BYTES);
    expect(m?.message.startsWith('éé')).toBe(true);
  });

  // A quadratic decoder takes minutes on 1 MB; the loose bound keeps the test
  // stable on a busy CI runner while still catching that.
  it('decodes a 1 MB file quickly (linear time)', () => {
    const chunk = `text ${encodeAsTags('hidden')} more ⭐${encodeAsVariationSelectors([0x68, 0x69, 0x21, 0x21])}\n`;
    const big = chunk.repeat(Math.ceil(1_000_000 / chunk.length));
    const t0 = Date.now();
    expect(decodeHidden(big)).toHaveLength(MAX_HIDDEN_RUNS);
    expect(decodeHidden(`${'a❤️ '.repeat(250_000)}`)).toEqual([]);
    expect(Date.now() - t0).toBeLessThan(15_000);
  }, 30_000);

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

  it('stops at the 100th run without reading the rest of the text', () => {
    const parts: string[] = [];
    for (let i = 0; i < 150; i++) parts.push(`⭐${encodeAsVariationSelectors([0x61, 0x62, 0x63, 0x64])}`);
    const msgs = decodeHidden(parts.join(' '));
    expect(msgs).toHaveLength(MAX_HIDDEN_RUNS);
    expect(msgs.every((m) => m.message === 'abcd')).toBe(true);
  });

  it('a tag run made only of begin/cancel tags is not a message', () => {
    expect(decodeHidden('\u{E0001}\u{E007F}\u{E0001}')).toEqual([]);
  });
});

describe('REQ-04: a decoded message is display-only attacker text', () => {
  it('displayMessage turns terminal escapes, bidi controls and invisible characters into markers', () => {
    expect(displayMessage('\u001B[31mred\u202Eevil\u200B!')).toBe('[U+001B][31mred[U+202E]evil[U+200B]!');
    expect(displayMessage('a\nb\tc')).toBe('a[U+000A]b[U+0009]c');
    expect(displayMessage('a\nb\tc', { keepNewlines: true })).toBe('a\nb\tc');
    expect(displayMessage('plain text, café 字')).toBe('plain text, café 字');
  });

  it('output of displayMessage never contains a control or format character', () => {
    fc.assert(
      fc.property(fc.fullUnicodeString({ maxLength: 60 }), (s) => {
        expect(/[\p{Cc}\p{Cf}]/u.test(displayMessage(s))).toBe(false);
        return true;
      }),
      { numRuns: 300 },
    );
  });
});
