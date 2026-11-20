import { describe, expect, it } from 'vitest';
import { runSignatures } from '../scanner/signature-engine.js';
import { normalize } from '../normalizer.js';
import { VirusDefinitionSchema } from '../definitions/schema.js';
import type { RepoFile } from '../types.js';

const def = (id: string, regex: string) => VirusDefinitionSchema.parse({
  id, title: id, severity: 'high', applies_to: ['docs'], match: { regex }, owasp: ['x'], fix: 'Fix it.',
});
const file: RepoFile = { path: '/x/a.md', rel: 'a.md', role: 'docs', sizeBytes: 0 };

describe('L-004: rule regexes have a time limit', () => {
  it('stops a catastrophic regex, reports it, and keeps the other rules', () => {
    const text = `${'a'.repeat(40)}! and ignore this`;
    const t0 = Date.now();
    const out = runSignatures(file, normalize(text, 'docs'), [def('EX-901', '(a+)+$'), def('EX-902', 'ignore')], 300);
    expect(Date.now() - t0).toBeLessThan(3000);
    expect(out).toContainEqual(expect.objectContaining({ ruleId: 'EX-901', severity: 'medium', span: 'EX-901 ran out of time on this file' }));
    expect(out).toContainEqual(expect.objectContaining({ ruleId: 'EX-902', span: 'ignore' }));
  });
  it('gives the same results as before on ordinary text', () => {
    const out = runSignatures(file, normalize('one ignore two ignore', 'docs'), [def('EX-902', 'ignore')]);
    expect(out.map((f) => f.col)).toEqual([5, 16]);
  });
});
