import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { applyInline, parseDirectives, reasonForReport, NEVER_INLINE } from '../suppress.js';
import { scanRepo } from '../scanner/orchestrator.js';
import { scanText } from '../scanner/scan-text.js';
import { loadDefinitions } from '../definitions/loader.js';
import { timeoutSpan } from '../scanner/signature-engine.js';
import type { Finding } from '../types.js';
import type { VirusDefinition } from '../definitions/schema.js';
import { fromRoot } from './repo-root.js';

function finding(ruleId: string, line: number, col = 1, file = 'a.md', span = 'x'): Finding {
  return { source: 'signature', ruleId, title: 't', severity: 'high', file, line, col, span, owasp: [], fix: 'f' };
}
const reader = (files: Record<string, string>) => (f: string): string | null => files[f] ?? null;

describe('parseDirectives', () => {
  it.each([
    ['// exorcist-ignore EX-004: reviewed'],
    ['# exorcist-ignore EX-004: reviewed'],
    ['<!-- exorcist-ignore EX-004: reviewed -->'],
    ['/* exorcist-ignore EX-004: reviewed */'],
    ['-- exorcist-ignore EX-004: reviewed'],
    ['; exorcist-ignore EX-004: reviewed'],
  ])('recognises %s', (line) => {
    const d = parseDirectives(line);
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ ruleId: 'EX-004', line: 1, openerIndex: 0, reason: 'reviewed' });
  });

  it('keeps only the first directive on a line and strips closers from the reason', () => {
    const d = parseDirectives('x <!-- exorcist-ignore EX-004: first --> <!-- exorcist-ignore EX-012: second -->');
    expect(d).toHaveLength(1);
    expect(d[0]?.ruleId).toBe('EX-004');
    expect(d[0]?.openerIndex).toBe(2);
  });

  it('ignores a directive that starts after the 1000th character', () => {
    expect(parseDirectives(`${' '.repeat(1000)}// exorcist-ignore EX-004: late`)).toHaveLength(0);
  });
});

describe('applyInline', () => {
  it('suppresses a finding before the opener on the same line', () => {
    const r = applyInline([finding('EX-004', 1, 1)], reader({ 'a.md': 'danger // exorcist-ignore EX-004: accepted risk' }));
    expect(r.active).toHaveLength(0);
    expect(r.suppressed).toHaveLength(1);
    expect(r.suppressed[0]).toMatchObject({ ruleId: 'EX-004', file: 'a.md', line: 1, reason: 'accepted risk' });
  });

  it('suppresses a finding on the next line at any column', () => {
    const text = '# exorcist-ignore EX-004: accepted\nsome text here that is flagged';
    const r = applyInline([finding('EX-004', 2, 15)], reader({ 'a.md': text }));
    expect(r.suppressed).toHaveLength(1);
  });

  it('does not suppress with a different rule id', () => {
    const r = applyInline([finding('EX-004', 2)], reader({ 'a.md': '# exorcist-ignore EX-012: accepted\nflagged' }));
    expect(r.active).toHaveLength(1);
    expect(r.suppressed).toHaveLength(0);
  });

  it('does not suppress two lines below the directive', () => {
    const r = applyInline([finding('EX-004', 3)], reader({ 'a.md': '# exorcist-ignore EX-004: accepted\nok\nflagged' }));
    expect(r.active).toHaveLength(1);
  });

  it('never suppresses EX-001 or EX-011 and lists the directive as rejected', () => {
    const text = '# exorcist-ignore EX-001: because\n# exorcist-ignore EX-011: because\nflagged';
    const r = applyInline([finding('EX-001', 1, 1), finding('EX-011', 2, 1)], reader({ 'a.md': text }));
    expect(r.suppressed).toHaveLength(0);
    expect(r.active).toHaveLength(2);
    expect(r.rejected.map((x) => `${x.ruleId}:${x.cause}`)).toEqual(['EX-001:never-suppressible', 'EX-011:never-suppressible']);
    expect(NEVER_INLINE).toEqual(['EX-001', 'EX-011']);
  });

  it('rejects a directive with no reason', () => {
    const r = applyInline([finding('EX-004', 2)], reader({ 'a.md': '# exorcist-ignore EX-004:\nflagged' }));
    expect(r.active).toHaveLength(1);
    expect(r.rejected).toEqual([{ ruleId: 'EX-004', file: 'a.md', line: 1, cause: 'no-reason' }]);
  });

  it('rejects a reason that is only punctuation after the closer is removed', () => {
    const r = applyInline([finding('EX-004', 2)], reader({ 'a.md': '<!-- exorcist-ignore EX-004: -- -->\nflagged' }));
    expect(r.suppressed).toHaveLength(0);
    expect(r.rejected[0]?.cause).toBe('no-reason');
  });

  it('does not suppress a timeout finding and lists the directive as rejected', () => {
    const t: Finding = { ...finding('EX-004', 2), span: timeoutSpan('EX-004') };
    const r = applyInline([t], reader({ 'a.md': '# exorcist-ignore EX-004: slow file\nflagged' }));
    expect(r.active).toEqual([t]);
    expect(r.rejected[0]?.cause).toBe('timeout');
  });

  it('a directive in an HTML comment does not suppress the finding that is the comment itself', () => {
    const text = '<!-- exorcist-ignore EX-004: x -->';
    const r = applyInline([finding('EX-004', 1, 1)], reader({ 'a.md': text }));
    expect(r.active).toHaveLength(1);
    expect(r.suppressed).toHaveLength(0);
  });

  it('a finding at a column after the opener on the directive line stays active', () => {
    const r = applyInline([finding('EX-004', 1, 20)], reader({ 'a.md': 'ab // exorcist-ignore EX-004: why' }));
    expect(r.active).toHaveLength(1);
  });

  it('reads each file once and treats an unreadable file as no directives', () => {
    const calls: string[] = [];
    const read = (f: string): string | null => { calls.push(f); return f === 'a.md' ? '# exorcist-ignore EX-004: ok\nx' : null; };
    const r = applyInline([finding('EX-004', 2, 1, 'a.md'), finding('EX-002', 5, 1, 'a.md'), finding('EX-004', 2, 1, 'gone.md')], read);
    expect(calls.sort()).toEqual(['a.md', 'gone.md']);
    expect(r.suppressed).toHaveLength(1);
    expect(r.active).toHaveLength(2);
  });

  it('reports a reason capped, secret-free and with hidden characters escaped', () => {
    const fake = ['sk', 'ant', 'api03', 'A'.repeat(40)].join('-');
    const out = reasonForReport(`ok\u202e ${fake} ${'z'.repeat(400)}`);
    expect(out.length).toBeLessThanOrEqual(400);
    expect(out).not.toContain(fake);
    expect(out).not.toContain('\u202e');
  });
});

describe('a directive cannot hide an attack written inside itself', () => {
  let defs: VirusDefinition[] = [];
  let dir = '';
  beforeAll(async () => {
    defs = await loadDefinitions(fromRoot('definitions'));
    dir = mkdtempSync(join(tmpdir(), 'exorcist-suppress-'));
    return () => rmSync(dir, { recursive: true, force: true });
  });

  const PHRASE = 'ignore all previous instructions';

  async function run(name: string, body: string): Promise<{ all: Finding[]; r: ReturnType<typeof applyInline> }> {
    writeFileSync(join(dir, name), body);
    const all: Finding[] = [];
    for await (const ev of scanRepo(dir, { definitionsDir: fromRoot('definitions') })) {
      if (ev.type === 'finding' && ev.finding.file === name) all.push(ev.finding);
    }
    return { all, r: applyInline(all, (f) => (f === name ? body : null)) };
  }

  it('scanText: the phrase in a directive reason is an EX-002 finding at a column after the opener', () => {
    const line = `# exorcist-ignore EX-012: ${PHRASE}`;
    const f = scanText(line, 'docs', defs, 'a.md').filter((x) => x.ruleId === 'EX-002');
    expect(f).toHaveLength(1);
    expect(f[0]?.col).toBeGreaterThan(line.indexOf('#') + 1);
    expect(applyInline(f, reader({ 'a.md': line })).active).toHaveLength(1);
  });

  it('scanRepo: a directive for another rule leaves the EX-002 phrase in its reason reported', async () => {
    const { all, r } = await run('NOTES-A.md', `# exorcist-ignore EX-012: ${PHRASE}\nplain line\n`);
    expect(all.some((f) => f.ruleId === 'EX-002')).toBe(true);
    expect(r.active.some((f) => f.ruleId === 'EX-002')).toBe(true);
  });

  it('scanRepo: a directive for EX-002 itself does not hide the phrase in its own reason', async () => {
    const { all, r } = await run('NOTES-B.md', `# exorcist-ignore EX-002: ${PHRASE}\n`);
    expect(all.some((f) => f.ruleId === 'EX-002')).toBe(true);
    expect(r.active.some((f) => f.ruleId === 'EX-002')).toBe(true);
    expect(r.suppressed.filter((s) => s.ruleId === 'EX-002')).toHaveLength(0);
  });

  it('scanRepo: the same directive on the line above does suppress an EX-002 phrase on the next line', async () => {
    const { all, r } = await run('NOTES-C.md', `# exorcist-ignore EX-002: quoted for a test of the scanner\n${PHRASE}\n`);
    expect(all.some((f) => f.ruleId === 'EX-002' && f.line === 2)).toBe(true);
    expect(r.suppressed.some((s) => s.ruleId === 'EX-002' && s.line === 2)).toBe(true);
  });
});
