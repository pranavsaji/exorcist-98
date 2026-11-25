import { describe, it, expect } from 'vitest';
import { toSarif, toJson, ScanReportSchema } from '../index.js';
import type { Finding, SarifSuppression } from '../index.js';

const mk = (line: number, span = 'x'): Finding => ({
  source: 'signature', ruleId: 'EX-001', title: 'Hidden', severity: 'high',
  file: 'a.md', line, col: 1, span, owasp: [], fix: 'remove',
} as Finding);
const stats = { filesScanned: 1, filesSkipped: 0, findingsTotal: 2, durationMs: 1 };

describe('SARIF suppressions', () => {
  it('adds suppressions only to marked results', () => {
    const a = mk(1), b = mk(2);
    const marks = new Map<Finding, SarifSuppression>([
      [a, { kind: 'external', justification: 'In the baseline (.exorcist-baseline.json)' }],
    ]);
    const r = toSarif([a, b], '/r', marks).runs[0]!.results;
    expect(r[0]!.suppressions).toEqual([
      { kind: 'external', status: 'accepted', justification: 'In the baseline (.exorcist-baseline.json)' },
    ]);
    expect('suppressions' in r[1]!).toBe(false);
  });
  it('still redacts secrets in the message', () => {
    const f = mk(1, `key ${'ghp' + '_'}abcdefghijklmnopqrstuvwxyz0123456789`);
    const marks = new Map<Finding, SarifSuppression>([[f, { kind: 'inSource', justification: 'ok' }]]);
    const text = toSarif([f], '/r', marks).runs[0]!.results[0]!.message.text;
    expect(text).not.toContain('abcdefghijklmnopqrstuvwxyz0123456789');
  });
});

describe('JSON suppressed', () => {
  it('validates with and without suppressed', () => {
    const plain = toJson([mk(1)], stats);
    expect(plain.suppressed).toBeUndefined();
    const withS = toJson([mk(1)], stats, {
      suppressed: {
        baseline: 2,
        inline: [{ ruleId: 'EX-001', file: 'a.md', line: 3, reason: 'fine' }],
        rejected: [{ ruleId: 'EX-002', file: 'a.md', line: 4, cause: 'no reason' }],
      },
    });
    expect(ScanReportSchema.safeParse(withS).success).toBe(true);
    expect(withS.suppressed?.baseline).toBe(2);
  });
});
