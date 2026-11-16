import { describe, it, expect } from 'vitest';
import { toJson, ScanReportSchema } from '../reporters/json-reporter.js';
import { toSarif } from '../reporters/sarif-reporter.js';
import type { Finding, ScanStats } from '../types.js';

const stats: ScanStats = {
  filesScanned: 10, filesSkipped: 1, findingsTotal: 2, durationMs: 42,
};

const critFinding: Finding = {
  source: 'signature', ruleId: 'EX-001', title: 'Hidden Unicode',
  severity: 'critical', file: 'README.md', line: 3, col: 5,
  span: '\\u200B', owasp: ['LLM01'], fix: 'Remove the char.',
};

const medFinding: Finding = {
  source: 'signature', ruleId: 'EX-010', title: 'Unpinned MCP',
  severity: 'medium', file: 'mcp.json', line: 1, col: 1,
  span: 'npx some-server', owasp: ['ASI07'], fix: 'Pin the version.',
};

describe('toJson', () => {
  it('output validates against ScanReportSchema', () => {
    const report = toJson([critFinding], stats);
    expect(() => ScanReportSchema.parse(report)).not.toThrow();
  });

  it('zero findings produces findings: []', () => {
    const report = toJson([], { ...stats, findingsTotal: 0 });
    expect(report.findings).toEqual([]);
  });

  it('version is "1"', () => {
    expect(toJson([], stats).version).toBe('1');
  });

  it('createdAt is a valid ISO 8601 date', () => {
    const { createdAt } = toJson([], stats);
    expect(() => new Date(createdAt)).not.toThrow();
    expect(new Date(createdAt).toISOString()).toBe(createdAt);
  });
});

describe('toSarif', () => {
  it('a critical finding maps to level error', () => {
    const sarif = toSarif([critFinding], '/repo');
    expect(sarif.runs[0]?.results[0]?.level).toBe('error');
  });

  it('a medium finding maps to level warning', () => {
    const sarif = toSarif([medFinding], '/repo');
    expect(sarif.runs[0]?.results[0]?.level).toBe('warning');
  });

  it('URIs are relative (do not start with /)', () => {
    const sarif = toSarif([critFinding], '/repo');
    const uri = sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri;
    expect(uri).toBeDefined();
    expect(uri?.startsWith('/')).toBe(false);
  });

  it('SARIF version is 2.1.0', () => {
    expect(toSarif([], '/repo').version).toBe('2.1.0');
  });
});
