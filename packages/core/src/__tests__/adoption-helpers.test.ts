import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { plural, staleness, verdictFor, verdictForFindings } from '../index.js';

describe('plural', () => {
  it('uses the singular for 1 and the plural otherwise', () => {
    expect(plural(1, 'file')).toBe('1 file');
    expect(plural(0, 'file')).toBe('0 files');
    expect(plural(2, 'file')).toBe('2 files');
    expect(plural(2, 'ghost', 'ghosts!')).toBe('2 ghosts!');
  });

  // Validates: Requirements 6.2
  it('always starts with the count and is singular only for 1', () => {
    fc.assert(fc.property(fc.nat(100000), fc.stringMatching(/^[a-z]{1,10}$/), (n, word) => {
      const out = plural(n, word);
      expect(out.startsWith(`${n} ${word}`)).toBe(true);
      expect(out.endsWith('s')).toBe(n !== 1 || word.endsWith('s'));
    }));
  });
});

describe('verdict', () => {
  it('maps levels to words', () => {
    expect(verdictFor('clean').word).toBe('CLEAN');
    expect(verdictFor('low').word).toBe('HAUNTED');
    expect(verdictFor('medium').word).toBe('HAUNTED');
    expect(verdictFor('high').word).toBe('POSSESSED');
    expect(verdictFor('critical').word).toBe('POSSESSED');
  });

  it('uses the worst severity of the findings', () => {
    expect(verdictForFindings([]).word).toBe('CLEAN');
    expect(verdictForFindings([{ severity: 'low' }, { severity: 'medium' }]).word).toBe('HAUNTED');
    expect(verdictForFindings([{ severity: 'low' }, { severity: 'high' }, { severity: 'medium' }]).word).toBe('POSSESSED');
  });
});

describe('staleness', () => {
  const now = new Date('2026-12-01T00:00:00Z');
  it('is not stale within the window', () => {
    expect(staleness('2026-11-24', now)).toEqual({ stale: false, days: 7 });
    expect(staleness('2026-11-01', now).stale).toBe(false);
  });
  it('is stale past the window', () => {
    expect(staleness('2026-10-01', now)).toEqual({ stale: true, days: 61 });
    expect(staleness('2026-10-01', now, 90).stale).toBe(false);
  });
  it('treats an invalid date as not stale', () => {
    expect(staleness('not a date', now)).toEqual({ stale: false, days: 0 });
  });
});
