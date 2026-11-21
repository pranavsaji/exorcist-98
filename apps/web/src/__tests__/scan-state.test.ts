import { describe, it, expect } from 'vitest';
import { initialScanState, scanReducer, MAX_LOG_LINES } from '@/lib/scan-state';
import type { ScanAction } from '@/lib/scan-state';
import type { ScanEventMsg, WebFinding } from '@/lib/protocol';

const finding: WebFinding = {
  source: 'signature', ruleId: 'EX-001', title: 'Hidden Unicode instructions',
  severity: 'critical', file: 'a.md', line: 3, col: 5, span: '\\u200B',
  owasp: ['LLM01'], fix: 'Remove it.',
};
const ev = (event: ScanEventMsg): ScanAction => ({ type: 'event', event });
const run = (actions: ScanAction[]) => actions.reduce(scanReducer, initialScanState);

describe('scanReducer', () => {
  it('reset starts a clean running scan with a first log line', () => {
    const s = run([{ type: 'reset', target: 'o/r' }]);
    expect(s.status).toBe('running');
    expect(s.target).toBe('o/r');
    expect(s.log[0]?.text).toContain('o/r');
    expect(s.findings).toEqual([]);
  });

  it('counts files and logs each one', () => {
    const s = run([
      { type: 'reset', target: 't' },
      ev({ type: 'file', rel: 'a.md', role: 'docs' }),
      ev({ type: 'file', rel: 'b.md', role: 'docs' }),
    ]);
    expect(s.filesSeen).toBe(2);
    expect(s.log.filter((l) => l.kind === 'file').map((l) => l.text)).toEqual(['scanning a.md', 'scanning b.md']);
  });

  it('a finding adds an entry, a threat log line with the plain headline and bumps threatSeq', () => {
    const s = run([
      { type: 'reset', target: 't' },
      ev({ type: 'finding', finding, snippet: { lines: [] } }),
    ]);
    expect(s.findings).toHaveLength(1);
    expect(s.threatSeq).toBe(1);
    const line = s.log.at(-1);
    expect(line?.kind).toBe('threat');
    expect(line?.text).toContain('[CRITICAL]');
    expect(line?.text).toContain('This file hides instructions for your AI');
  });

  it('finding entry ids and log ids are unique', () => {
    const s = run([
      { type: 'reset', target: 't' },
      ev({ type: 'finding', finding, snippet: { lines: [] } }),
      ev({ type: 'finding', finding: { ...finding, line: 4 }, snippet: { lines: [] } }),
      ev({ type: 'file', rel: 'x', role: 'docs' }),
    ]);
    const ids = [...s.log.map((l) => l.id), ...s.findings.map((f) => f.id)];
    expect(s.log.map((l) => l.id).length).toBe(new Set(s.log.map((l) => l.id)).size);
    expect(s.findings.map((f) => f.id).length).toBe(new Set(s.findings.map((f) => f.id)).size);
    expect(ids.length).toBeGreaterThan(0);
  });

  it('done stores stats and finishes; fatal fails with a notice', () => {
    const done = run([
      { type: 'reset', target: 't' },
      ev({ type: 'done', stats: { filesScanned: 2, filesSkipped: 0, findingsTotal: 1, durationMs: 12 } }),
    ]);
    expect(done.status).toBe('done');
    expect(done.stats?.filesScanned).toBe(2);

    const fatal = run([{ type: 'reset', target: 't' }, ev({ type: 'fatal', message: 'The scan could not be completed.' })]);
    expect(fatal.status).toBe('failed');
    expect(fatal.notice).toBe('The scan could not be completed.');
  });

  it('a general error (no file) becomes the notice; a file error does not', () => {
    const general = run([{ type: 'reset', target: 't' }, ev({ type: 'error', file: '', message: 'Too many findings.' })]);
    expect(general.notice).toBe('Too many findings.');
    const perFile = run([{ type: 'reset', target: 't' }, ev({ type: 'error', file: 'x.md', message: 'could not read' })]);
    expect(perFile.notice).toBeNull();
    expect(perFile.log.at(-1)?.text).toBe('could not read x.md');
  });

  it('keeps the log bounded', () => {
    let s = scanReducer(initialScanState, { type: 'reset', target: 't' });
    for (let i = 0; i < MAX_LOG_LINES + 50; i++) {
      s = scanReducer(s, ev({ type: 'file', rel: `f${i}`, role: 'docs' }));
    }
    expect(s.log.length).toBe(MAX_LOG_LINES);
    expect(s.filesSeen).toBe(MAX_LOG_LINES + 50);
  });

  it('cancelled and failed actions set the status', () => {
    expect(run([{ type: 'reset', target: 't' }, { type: 'cancelled' }]).status).toBe('cancelled');
    const failed = run([{ type: 'reset', target: 't' }, { type: 'failed', message: 'nope' }]);
    expect(failed.status).toBe('failed');
    expect(failed.notice).toBe('nope');
  });
});

describe('W-010: real progress', () => {
  it('records the total the server counted and resets it for the next scan', async () => {
    const { scanReducer, initialScanState } = await import('@/lib/scan-state');
    let s = scanReducer(initialScanState, { type: 'reset', target: 'x' });
    s = scanReducer(s, { type: 'event', event: { type: 'total', files: 20 } });
    expect(s.totalFiles).toBe(20);
    s = scanReducer(s, { type: 'reset', target: 'y' });
    expect(s.totalFiles).toBeNull();
  });
});

describe('log: repeated lines are counted, not repeated', () => {
  it('shows one line with a count when a rule hits one line several times', async () => {
    const { scanReducer, initialScanState } = await import('@/lib/scan-state');
    let s = scanReducer(initialScanState, { type: 'reset', target: 'x' });
    const ev = (col: number) => ({ type: 'event' as const, event: { type: 'finding' as const, snippet: { lines: [] }, finding: { source: 'signature' as const, ruleId: 'EX-001', title: 'Hidden', severity: 'critical' as const, file: 'a.md', line: 3, col, span: 'x', owasp: [], fix: '' } } });
    s = scanReducer(s, ev(1)); s = scanReducer(s, ev(5)); s = scanReducer(s, ev(9));
    const lines = s.log.filter((l) => l.text.includes('a.md:3'));
    expect(lines).toHaveLength(1);
    expect(lines[0]?.text).toMatch(/\(x3\)$/);
    expect(s.findings).toHaveLength(3);
  });
});
