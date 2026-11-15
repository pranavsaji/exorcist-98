import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { findSecrets } from '../secrets-check.js';

const ALPHANUM_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const ALPHANUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

// Arbitrary that produces a string containing a valid AWS access key at a random position
const awsKeyEmbeddedArb = fc
  .tuple(
    fc.string({ maxLength: 50 }),
    fc.stringOf(fc.constantFrom(...ALPHANUM_UPPER.split('')), {
      minLength: 16,
      maxLength: 16,
    }),
    fc.string({ maxLength: 50 }),
  )
  .map(([prefix, keyBody, suffix]) => `${prefix}AKIA${keyBody}${suffix}`);

// Arbitrary for the placeholder wrapper pattern
const placeholderWrappedArb = fc
  .tuple(
    fc.string({ maxLength: 20 }),
    fc.string({ maxLength: 20 }),
  )
  .map(([a, b]) => `EXAMPLE_${a.replace(/[^A-Z0-9_]/gi, '_').toUpperCase()}_DO_NOT_USE`);

describe('findSecrets (property-based)', () => {
  // PBT-SEC-01: any string with an AWS key is always flagged
  it('PBT-SEC-01: a string containing an AWS access key is always flagged', () => {
    fc.assert(
      fc.property(awsKeyEmbeddedArb, (text) => {
        // Exclude inputs where fast-check accidentally generated a placeholder wrapper
        if (/EXAMPLE_[A-Z0-9_]*_DO_NOT_USE/.test(text)) return true;
        const hits = findSecrets(text);
        expect(hits.some((h) => h.pattern === 'aws-access-key')).toBe(true);
        return true;
      }),
    );
  });

  // PBT-SEC-02: placeholder strings are never flagged even if they embed a key-shaped substring
  it('PBT-SEC-02: placeholder values matching EXAMPLE_*_DO_NOT_USE are never flagged', () => {
    fc.assert(
      fc.property(placeholderWrappedArb, (placeholder) => {
        const hits = findSecrets(placeholder);
        expect(hits).toHaveLength(0);
        return true;
      }),
    );
  });

  // PBT-SEC-03: findSecrets is idempotent
  it('PBT-SEC-03: findSecrets is idempotent — same input returns same result', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 200 }), (text) => {
        const first = findSecrets(text);
        const second = findSecrets(text);
        expect(first).toEqual(second);
        return true;
      }),
    );
  });

  // PBT-SEC-04: empty string is never flagged
  it('PBT-SEC-04: an empty string is never flagged', () => {
    fc.assert(
      fc.property(fc.constant(''), (text) => {
        const hits = findSecrets(text);
        expect(hits).toHaveLength(0);
        return true;
      }),
      { numRuns: 1 },
    );
  });
});
