import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { loadDefinitions } from '@exorcist-98/core';
import { SEVERITY_INFO, SEVERITY_ORDER, overallLevel, sortFindings } from '@/lib/severity';
import { hasPlainEntry, plainFor } from '@/lib/plain';
import { definitionsDir } from '@/lib/paths';
import type { Severity } from '@/lib/protocol';

const sev = fc.constantFrom<Severity>('critical', 'high', 'medium', 'low');
const finding = fc.record({
  severity: sev,
  file: fc.constantFrom('a.md', 'b.json', 'c.yaml'),
  line: fc.integer({ min: 1, max: 50 }),
});

describe('severity', () => {
  it('every level has a label and a distinct shape', () => {
    const shapes = SEVERITY_ORDER.map((s) => SEVERITY_INFO[s].shape);
    expect(new Set(shapes).size).toBe(SEVERITY_ORDER.length);
    for (const s of SEVERITY_ORDER) expect(SEVERITY_INFO[s].label).toBe(s.toUpperCase());
  });

  it('PBT-WEB-05: sorted findings are never out of severity order', () => {
    fc.assert(
      fc.property(fc.array(finding, { maxLength: 40 }), (list) => {
        const sorted = sortFindings(list);
        expect(sorted).toHaveLength(list.length);
        for (let i = 1; i < sorted.length; i++) {
          const a = sorted[i - 1];
          const b = sorted[i];
          if (!a || !b) throw new Error('unreachable');
          expect(SEVERITY_INFO[a.severity].rank).toBeLessThanOrEqual(SEVERITY_INFO[b.severity].rank);
        }
        return true;
      }),
    );
  });

  it('sortFindings does not mutate its input', () => {
    const input = [
      { severity: 'low' as const, file: 'a', line: 1 },
      { severity: 'critical' as const, file: 'a', line: 2 },
    ];
    const copy = structuredClone(input);
    sortFindings(input);
    expect(input).toEqual(copy);
  });

  it('overallLevel is the worst severity, or clean', () => {
    expect(overallLevel([])).toBe('clean');
    expect(overallLevel([{ severity: 'low' }, { severity: 'high' }, { severity: 'medium' }])).toBe('high');
  });
});

describe('plain-language text', () => {
  it('every definition in definitions/ has a plain-language entry', async () => {
    const defs = await loadDefinitions(definitionsDir());
    expect(defs.length).toBeGreaterThanOrEqual(12);
    const missing = defs.filter((d) => !hasPlainEntry(d.id)).map((d) => d.id);
    expect(missing).toEqual([]);
  });

  it('falls back to the rule title for unknown rules', () => {
    expect(plainFor('EX-999', 'Some title').headline).toBe('Some title');
  });

  it('EX-001 leads with the plain sentence required by the UI rules', () => {
    expect(plainFor('EX-001', 'x').headline).toBe('This file hides instructions for your AI');
  });
});
