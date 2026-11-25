import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { applyInline, NEVER_INLINE } from '../suppress.js';
import type { Finding } from '../types.js';

const RULES = ['EX-001', 'EX-002', 'EX-004', 'EX-011', 'EX-012'] as const;
const OPENERS = ['//', '#', '<!--', '/*', '--', ';'] as const;

const findingArb = fc.record({
  ruleId: fc.constantFrom(...RULES),
  line: fc.integer({ min: 1, max: 6 }),
  col: fc.integer({ min: 1, max: 40 }),
});
const toFinding = (x: { ruleId: string; line: number; col: number }): Finding => ({
  source: 'signature', ruleId: x.ruleId, title: 't', severity: 'high', file: 'f.txt', line: x.line, col: x.col, span: 'x', owasp: [], fix: 'f',
});

const lineArb = fc.oneof(
  fc.constant('plain text'),
  fc.tuple(fc.string({ maxLength: 8 }), fc.constantFrom(...OPENERS), fc.constantFrom(...RULES), fc.string({ maxLength: 20 }))
    .map(([pre, op, rule, why]) => `${pre.replace(/[\r\n]/g, '')} ${op} exorcist-ignore ${rule}: ${why.replace(/[\r\n]/g, '')}`),
);
const textArb = fc.array(lineArb, { minLength: 1, maxLength: 7 }).map((l) => l.join('\n'));

describe('applyInline properties', () => {
  /** Validates: Requirements 2.3 */
  it('EX-001 and EX-011 findings are never suppressed, whatever the directives say', () => {
    fc.assert(fc.property(fc.array(findingArb, { maxLength: 12 }), textArb, (xs, text) => {
      const r = applyInline(xs.map(toFinding), () => text);
      expect(r.suppressed.every((s) => !NEVER_INLINE.includes(s.ruleId))).toBe(true);
    }), { numRuns: 300 });
  });

  /** Validates: Requirements 2.1, 2.6 */
  it('every input finding lands in exactly one of active and suppressed', () => {
    fc.assert(fc.property(fc.array(findingArb, { maxLength: 12 }), textArb, (xs, text) => {
      const fs = xs.map(toFinding);
      const r = applyInline(fs, () => text);
      expect(r.active.length + r.suppressed.length).toBe(fs.length);
      const seen = new Set<Finding>();
      for (const f of [...r.active, ...r.suppressed.map((s) => s.finding)]) {
        expect(seen.has(f)).toBe(false);
        seen.add(f);
      }
      expect(fs.every((f) => seen.has(f))).toBe(true);
    }), { numRuns: 300 });
  });

  /** Validates: Requirements 2.4 */
  it('a finding at or after the opener on the directive line is never suppressed by that directive', () => {
    fc.assert(fc.property(
      fc.constantFrom(...OPENERS), fc.integer({ min: 0, max: 20 }), fc.integer({ min: 0, max: 30 }),
      (op, pad, extra) => {
        const line = `${' '.repeat(pad)}${op} exorcist-ignore EX-004: reviewed ok`;
        const r = applyInline([toFinding({ ruleId: 'EX-004', line: 1, col: pad + 1 + extra })], () => line);
        expect(r.suppressed).toHaveLength(0);
        expect(r.active).toHaveLength(1);
      },
    ), { numRuns: 200 });
  });

  /** Validates: Requirements 2.1 */
  it('a finding before the opener, or on the next line, is suppressed when rule and reason fit', () => {
    fc.assert(fc.property(
      fc.constantFrom(...OPENERS), fc.integer({ min: 1, max: 20 }), fc.integer({ min: 1, max: 40 }),
      (op, pad, col) => {
        const line = `${'a'.repeat(pad)}${op} exorcist-ignore EX-004: reviewed ok`;
        const same = applyInline([toFinding({ ruleId: 'EX-004', line: 1, col: pad })], () => line);
        expect(same.suppressed).toHaveLength(1);
        const next = applyInline([toFinding({ ruleId: 'EX-004', line: 2, col })], () => `${line}\nnext`);
        expect(next.suppressed).toHaveLength(1);
      },
    ), { numRuns: 200 });
  });
});
