/** m10-kiro-gate requirement 1.4 as properties. */
import { describe, it, expect, beforeAll } from 'vitest';
import * as fc from 'fast-check';
import { loadDefinitions } from '../definitions/loader.js';
import { gateFindings } from '../gate.js';
import type { VirusDefinition } from '../definitions/schema.js';
import { fromRoot } from './repo-root.js';

let defs: VirusDefinition[] = [];
beforeAll(async () => { defs = await loadDefinitions(fromRoot('definitions')); });

const HIDDEN = String.fromCodePoint(0xe0049, 0xe004e, 0xe0050);
const prose = fc.array(fc.stringMatching(/^[A-Za-z0-9 .,]{0,40}$/), { maxLength: 8 }).map((l) => l.join('\n'));

describe('gateFindings properties', () => {
  it('an unchanged file never adds a finding, whatever it holds', () => {
    fc.assert(fc.property(prose, prose, (a, b) => {
      const text = `${a}\nBe kind.${HIDDEN}\n${b}\n`;
      expect(gateFindings('.kiro/steering/a.md', text, text, defs)).toEqual([]);
    }), { numRuns: 40 });
  });
  it('text added around an old finding never makes it new', () => {
    fc.assert(fc.property(prose, prose, (a, b) => {
      const old = `Be kind.${HIDDEN}\n`;
      expect(gateFindings('.kiro/steering/a.md', old, `${a}\n${old}${b}\n`, defs)).toEqual([]);
    }), { numRuns: 40 });
  });
  it('hidden characters added to otherwise clean prose are always added', () => {
    fc.assert(fc.property(prose, prose, (a, b) => {
      const added = gateFindings('.kiro/steering/a.md', `${a}\n`, `${a}\nx${HIDDEN}\n${b}\n`, defs);
      expect(added.some((f) => f.ruleId === 'EX-001')).toBe(true);
    }), { numRuns: 40 });
  });
});
