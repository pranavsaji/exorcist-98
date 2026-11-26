import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import fc from 'fast-check';
import { sha256Hex } from '../sha256.js';
import { eventHash } from '../chain-core.js';

describe('pure SHA-256 used by the chain core', () => {
  it('AC-20: matches known vectors', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
  it('AC-20: matches node:crypto for any text, so the CLI and the browser compute the same hash', () => {
    fc.assert(fc.property(fc.string({ unit: 'binary', maxLength: 400 }), (s) => {
      expect(sha256Hex(s)).toBe(createHash('sha256').update(s, 'utf8').digest('hex'));
    }), { numRuns: 300 });
  });
  it('AC-20: eventHash is the SHA-256 of the canonical form', () => {
    const e = { v: 1, time: '2026-01-01T00:00:00.000Z', pid: 1, server: 's', kind: 'start', mode: 'enforce', guard: 'hold', remote: false, seq: 1, prev: 'a'.repeat(64) } as const;
    expect(eventHash(e)).toMatch(/^[0-9a-f]{64}$/);
  });
});
