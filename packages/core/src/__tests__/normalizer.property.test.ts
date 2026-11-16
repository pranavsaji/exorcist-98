import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { normalize } from '../normalizer.js';

// Arbitrary that injects a zero-width char at a random position
const withZeroWidthArb = fc
  .tuple(fc.string({ maxLength: 100 }), fc.string({ maxLength: 100 }))
  .map(([a, b]) => `${a}\u200B${b}`);

// Printable ASCII only (no hidden chars)
const printableAsciiArb = fc.string({ maxLength: 200 }).filter(
  (s) => /^[\x20-\x7E\n\r\t]*$/.test(s),
);

describe('Normalizer property-based tests', () => {
  // PBT-NRM-01: normalize is idempotent on the plain field
  it('PBT-NRM-01: normalize is idempotent (plain field)', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 200 }), fc.constant('docs' as const), (text, role) => {
        const first  = normalize(text, role).plain;
        const second = normalize(first, role).plain;
        expect(second).toBe(first);
        return true;
      }),
    );
  });

  // PBT-NRM-02: a string containing a zero-width char always produces a hit
  it('PBT-NRM-02: a string with U+200B always produces a hiddenUnicode hit', () => {
    fc.assert(
      fc.property(withZeroWidthArb, (text) => {
        const result = normalize(text, 'docs');
        expect(result.hiddenUnicode.some(h => h.class === 'zero-width')).toBe(true);
        return true;
      }),
    );
  });

  // PBT-NRM-03: printable ASCII produces no hiddenUnicode hits
  it('PBT-NRM-03: printable ASCII produces no hiddenUnicode hits', () => {
    fc.assert(
      fc.property(printableAsciiArb, (text) => {
        const result = normalize(text, 'docs');
        expect(result.hiddenUnicode).toHaveLength(0);
        return true;
      }),
    );
  });

  // PBT-NRM-04: base64Candidates never contains strings shorter than 32 chars
  it('PBT-NRM-04: no base64Candidate is shorter than 32 characters', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 300 }), (text) => {
        const result = normalize(text, 'docs');
        for (const candidate of result.base64Candidates) {
          expect(candidate.length).toBeGreaterThanOrEqual(32);
        }
        return true;
      }),
    );
  });
});
