import { beforeAll, describe, expect, it } from 'vitest';
import { loadDefinitions } from '../definitions/loader.js';
import { scanText } from '../scanner/scan-text.js';
import { exorciseFile } from '../exorcise.js';
import type { VirusDefinition } from '../definitions/schema.js';
import { fromRoot } from './repo-root.js';
let defs: VirusDefinition[] = [];
beforeAll(async () => { defs = await loadDefinitions(fromRoot('definitions')); });
describe('exorcise: a zero-width character left next to an emoji by a removed selector run', () => {
  it('leaves no EX-001 or EX-021 finding (regression from a property-test seed)', () => {
    const text = '\u2764\uFE0F\u200C\uFE0F\uFE0F\uFE0F\uFE0F';
    const findings = scanText(text, 'docs', defs, 'NOTES.md');
    const r = exorciseFile({ file: 'NOTES.md', text, findings, only: new Set(['EX-001', 'EX-021']) });
    expect(scanText(r.after, 'docs', defs).filter((f) => f.ruleId === 'EX-001' || f.ruleId === 'EX-021')).toEqual([]);
  });
});
