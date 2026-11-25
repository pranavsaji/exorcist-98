import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { applyBaseline, buildBaseline, fingerprintOf, parseBaseline, type Finding } from '../index.js';

const findingArb: fc.Arbitrary<Finding> = fc.record({
  source: fc.constant('signature' as const),
  ruleId: fc.constantFrom('EX-001', 'EX-005', 'EX-011'),
  title: fc.constant('t'),
  severity: fc.constant('high' as const),
  file: fc.constantFrom('a.md', 'b/c.json'),
  line: fc.integer({ min: 1, max: 500 }),
  col: fc.integer({ min: 1, max: 80 }),
  span: fc.constantFrom('alpha', 'beta  gamma', 'delta'),
  owasp: fc.constant([] as string[]),
  fix: fc.constant('fix'),
});

describe('baseline properties', () => {
  // Validates: Requirements 1.4
  it('the fingerprint ignores line and column', () => {
    fc.assert(fc.property(findingArb, fc.nat(1000), fc.nat(1000), (f, line, col) => {
      expect(fingerprintOf({ ...f, line, col })).toBe(fingerprintOf(f));
    }));
  });

  // Validates: Requirements 1.2, 1.4
  it('a baseline built from F matches F exactly, whatever the order', () => {
    fc.assert(fc.property(fc.array(findingArb, { maxLength: 30 }), fc.nat(), (fs, seed) => {
      const b = buildBaseline(fs);
      const shuffled = [...fs].sort((x, y) => ((x.line * 31 + seed) % 7) - ((y.line * 31 + seed) % 7));
      const r = applyBaseline(shuffled, b);
      expect(r.active).toHaveLength(0);
      expect(r.baselined).toEqual(shuffled);
    }));
  });

  // Validates: Requirements 1.5
  it('each finding lands in exactly one list and an extra copy stays active', () => {
    fc.assert(fc.property(fc.array(findingArb, { maxLength: 20 }), findingArb, (fs, extra) => {
      const b = buildBaseline(fs);
      const all = [...fs, extra];
      const r = applyBaseline(all, b);
      expect(r.active.length + r.baselined.length).toBe(all.length);
      expect(r.baselined).toHaveLength(fs.length);
      expect(r.active).toHaveLength(1);
    }));
  });

  // Validates: Requirements 1.8, 7.2
  it('buildBaseline output always parses back, and arbitrary text never throws', () => {
    fc.assert(fc.property(fc.array(findingArb, { maxLength: 20 }), (fs) => {
      const b = buildBaseline(fs);
      expect(parseBaseline(JSON.stringify(b))).toEqual({ ok: true, baseline: b });
    }));
    fc.assert(fc.property(fc.string(), (s) => {
      expect(typeof parseBaseline(s).ok).toBe('boolean');
    }));
  });
});
