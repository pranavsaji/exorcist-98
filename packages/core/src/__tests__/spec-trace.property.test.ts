/** m13-kiro-evidence: spec-trace properties and examples (tasks 10.1, 10.2, 10.4). */
import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';
import { detectIdPrefix, diffIds, extractRequirementIds, extractTestedIds, specTraceExitCode } from '../spec-trace.js';

const idSet = fc.uniqueArray(fc.integer({ min: 1, max: 60 }), { maxLength: 25 }).map((a) => new Set(a.map((n) => `KG-${n}`)));
const byNum = (a: string, b: string): number => Number(a.slice(3)) - Number(b.slice(3));

describe('spec-trace', () => {
  it('KE-22 KE-23 a spec that mentions EX-001 rule lines is not traced', () => {
    const md = '#### Acceptance Criteria\nEX-001 hidden unicode\n- EX-002 rule\n1. EX-003 THE scanner SHALL x.\n1. THE gate SHALL y.\n';
    expect(detectIdPrefix(md)).toBeNull();
    expect(extractRequirementIds(md, 'EX').size).toBe(0);
  });

  it('KE-22 extractRequirementIds reads IDs at the start of criteria lines and detectIdPrefix finds the prefix', () => {
    const md = '# R\n#### Acceptance Criteria\n1. KG-1 THE gate SHALL x.\n- KG-2 y mentions KG-9 inline\n2. no id here\n';
    expect(detectIdPrefix(md)).toBe('KG');
    expect([...extractRequirementIds(md, 'KG')]).toEqual(['KG-1', 'KG-2']);
    expect(detectIdPrefix('1. THE gate SHALL x.')).toBeNull();
  });

  it('KE-23 extractTestedIds counts the IDs a test name starts with, one or several, and not KG-1 inside KG-10', () => {
    const got = extractTestedIds(['KG-1 a', 'KG-2 KG-3 b', 'KG-4, KG-5: c', 'KG-10 d', 'no id KG-7', 'KG-12x'], 'KG');
    expect([...got].sort(byNum)).toEqual(['KG-1', 'KG-10', 'KG-2', 'KG-3', 'KG-4', 'KG-5'].sort(byNum));
  });

  // Feature: m13-kiro-evidence, Property 11: Requirement/test ID diff is exact in both directions
  it('KE-22 KE-23 Property 11: the diff is exactly the set difference in both directions, sorted and duplicate-free', () => {
    // **Validates: Requirements 5.1, 5.2**
    fc.assert(
      fc.property(idSet, idSet, (spec, tested) => {
        const d = diffIds(spec, tested);
        expect(new Set(d.missingTests)).toEqual(new Set([...spec].filter((i) => !tested.has(i))));
        expect(new Set(d.extraTests)).toEqual(new Set([...tested].filter((i) => !spec.has(i))));
        expect(d.missingTests.length).toBe(new Set(d.missingTests).size);
        expect(d.missingTests).toEqual([...d.missingTests].sort(byNum));
        expect(d.extraTests).toEqual([...d.extraTests].sort(byNum));
      }),
      { numRuns: 100 },
    );
  });

  it('KE-23 round trip: test names built from a set of IDs give back that set', () => {
    fc.assert(
      fc.property(idSet, (ids) => {
        const names = [...ids].map((i) => `${i} some title`);
        expect(extractTestedIds(names, 'KG')).toEqual(ids);
      }),
      { numRuns: 100 },
    );
  });

  // Feature: m13-kiro-evidence, Property 12: Exit code reflects the diff
  it('KE-24 Property 12: the exit code is 0 only when every diff is empty in both directions', () => {
    // **Validates: Requirements 5.3**
    fc.assert(
      fc.property(fc.array(fc.tuple(idSet, idSet), { maxLength: 5 }), (pairs) => {
        const diffs = pairs.map(([s, t]) => diffIds(s, t));
        const clean = diffs.every((d) => d.missingTests.length === 0 && d.extraTests.length === 0);
        expect(specTraceExitCode(diffs)).toBe(clean ? 0 : 1);
      }),
      { numRuns: 100 },
    );
  });
});
