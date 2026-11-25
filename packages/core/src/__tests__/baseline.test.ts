import { describe, expect, it } from 'vitest';
import {
  applyBaseline, buildBaseline, fingerprintOf, parseBaseline,
  type Baseline, type Finding,
} from '../index.js';

function mk(over: Partial<Finding> = {}): Finding {
  return {
    source: 'signature', ruleId: 'EX-005', title: 't', severity: 'high', file: 'a/b.md',
    line: 3, col: 1, span: 'do not tell the user', owasp: [], fix: 'remove it', ...over,
  } as Finding;
}

describe('baseline', () => {
  // Validates: Requirements 1.4
  it('keeps a match when the finding moves to another line', () => {
    const b = buildBaseline([mk({ line: 3 })]);
    const r = applyBaseline([mk({ line: 40, col: 7 })], b);
    expect(r.active).toHaveLength(0);
    expect(r.baselined).toHaveLength(1);
  });

  // Validates: Requirements 1.5
  it('treats a changed span as new', () => {
    const b = buildBaseline([mk()]);
    const r = applyBaseline([mk({ span: 'do not tell anyone' })], b);
    expect(r.active).toHaveLength(1);
    expect(r.baselined).toHaveLength(0);
  });

  // Validates: Requirements 1.5
  it('treats the extra duplicate as new, the later one in (line, col) order', () => {
    const b = buildBaseline([mk({ line: 3 })]);
    const first = mk({ line: 3 });
    const second = mk({ line: 9 });
    const r = applyBaseline([second, first], b);
    expect(r.baselined).toEqual([first]);
    expect(r.active).toEqual([second]);
  });

  // Validates: Requirements 1.4
  it('matches on rule id and file as well', () => {
    const b = buildBaseline([mk()]);
    expect(applyBaseline([mk({ ruleId: 'EX-006' })], b).active).toHaveLength(1);
    expect(applyBaseline([mk({ file: 'other.md' })], b).active).toHaveLength(1);
  });

  // Validates: Requirements 1.2
  it('ignores whitespace differences in the span and excludes line from the fingerprint', () => {
    expect(fingerprintOf(mk({ span: 'a  b\n c' }))).toBe(fingerprintOf(mk({ span: 'a b c', line: 99 })));
    expect(fingerprintOf(mk())).toMatch(/^[0-9a-f]{32}$/);
  });

  // Validates: Requirements 1.2
  it('sorts entries, has version 1 and no timestamp', () => {
    const b = buildBaseline([mk({ file: 'z.md' }), mk({ file: 'a.md', line: 5 }), mk({ file: 'a.md', line: 2 })]);
    expect(b.version).toBe(1);
    expect(Object.keys(b)).toEqual(['version', 'entries']);
    expect(b.entries.map(e => `${e.file}:${e.line}`)).toEqual(['a.md:2', 'a.md:5', 'z.md:3']);
  });

  // Validates: Requirements 1.2, 1.3, 7.1
  it('stores no span text and no secret', () => {
    const key = ['sk', 'ant', 'api03', 'Zq9'.repeat(14)].join('-');
    const f = mk({ ruleId: 'EX-011', span: `token = ${key}` });
    const text = JSON.stringify(buildBaseline([f, mk()]));
    expect(text).not.toContain(key);
    expect(text).not.toContain('Zq9Zq9');
    expect(text).not.toContain('do not tell the user');
  });

  // Validates: Requirements 1.8, 7.2
  it('round-trips through parseBaseline', () => {
    const b = buildBaseline([mk()]);
    expect(parseBaseline(JSON.stringify(b))).toEqual({ ok: true, baseline: b });
  });

  // Validates: Requirements 1.8, 7.2
  it('returns ok:false and never throws on bad input', () => {
    const good: Baseline = buildBaseline([mk()]);
    const bad = [
      '', '{not json', 'null', '[]', '42', '{}',
      JSON.stringify({ ...good, version: 2 }),
      JSON.stringify({ ...good, extra: true }),
      JSON.stringify({ version: 1, entries: [{ ...good.entries[0], span: 'leak' }] }),
      JSON.stringify({ version: 1, entries: [{ ruleId: 'EX-005', file: 'a', fingerprint: 'zz', line: 1 }] }),
      JSON.stringify({ version: 1, entries: 'x' }),
    ];
    for (const t of bad) {
      const r = parseBaseline(t);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.length).toBeGreaterThan(0);
    }
  });
});
