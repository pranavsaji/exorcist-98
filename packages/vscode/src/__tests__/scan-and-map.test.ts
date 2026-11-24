import { beforeAll, describe, expect, it } from 'vitest';
import type { Finding, SignatureFinding } from '@exorcist-98/core';
import { GhostScanner, HARD_LIMIT_CHARS, meetsThreshold } from '../scanner.js';
import {
  ENCYCLOPEDIA_BASE, LineIndex, diagnosticMessage, encyclopediaUrl, findingOffsets, levelFor, toDiagnosticSpec,
} from '../diagnostics.js';
import { hiddenRuns } from '../hidden.js';
import { BENIGN, DEFINITIONS, HAUNTED, TAG_MESSAGE } from './samples.js';

let scanner: GhostScanner;
beforeAll(async () => { scanner = await GhostScanner.load(DEFINITIONS); });

const base = (over: Partial<SignatureFinding>): SignatureFinding => ({
  source: 'signature', ruleId: 'EX-002', title: 'AI-directed instructions', severity: 'high',
  file: 'AGENTS.md', line: 1, col: 1, span: 'x', owasp: [], fix: 'Remove it.', ...over,
});

describe('GhostScanner', () => {
  it('finds every ghost in the haunted steering file', () => {
    const ids = scanner.scan(HAUNTED, '.kiro/steering/rules.md', 'instruction').map((f) => `${f.ruleId}@${f.line}`);
    expect(ids).toEqual(expect.arrayContaining(['EX-001@2', 'EX-001@3', 'EX-021@4', 'EX-004@5', 'EX-002@5', 'EX-001@6', 'EX-012@7']));
  });

  it('reports nothing for the benign uses the core allows', () => {
    expect(scanner.scan(BENIGN, 'README.md', 'instruction')).toEqual([]);
  });

  it('sorts findings by position', () => {
    const f = scanner.scan(HAUNTED, 'AGENTS.md', 'instruction');
    const keys = f.map((x) => x.line * 10_000 + x.col);
    expect(keys).toEqual([...keys].sort((a, b) => a - b));
  });

  it('runs the lethal-trifecta check (EX-023) on an MCP config', () => {
    const cfg = JSON.stringify({
      mcpServers: {
        fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.0.0', '/Users/me'] },
        web: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-fetch@1.0.0'] },
        slack: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-slack@1.0.0'] },
      },
    }, null, 2);
    const ids = scanner.scan(cfg, '.kiro/settings/mcp.json', 'mcp-config').map((f) => f.ruleId);
    expect(ids).toContain('EX-023');
  });

  it('reports an agent file past the hard limit as EX-026 instead of reading it', () => {
    const f = scanner.tooLarge('AGENTS.md', HARD_LIMIT_CHARS + 1);
    expect(f.map((x) => x.ruleId)).toEqual(['EX-026']);
    expect(f[0]?.line).toBe(1);
  });

  it('severity threshold', () => {
    expect(meetsThreshold('low', 'low')).toBe(true);
    expect(meetsThreshold('medium', 'high')).toBe(false);
    expect(meetsThreshold('critical', 'high')).toBe(true);
    expect(meetsThreshold('high', 'critical')).toBe(false);
  });
});

describe('finding -> diagnostic', () => {
  it('maps severities to Error / Warning / Information', () => {
    expect(levelFor('critical')).toBe('error');
    expect(levelFor('high')).toBe('error');
    expect(levelFor('medium')).toBe('warning');
    expect(levelFor('low')).toBe('information');
  });

  it('links the rule id to its encyclopedia page', () => {
    expect(encyclopediaUrl('EX-001')).toBe('https://exorcist-98.vercel.app/encyclopedia/EX-001');
    expect(ENCYCLOPEDIA_BASE.endsWith('/encyclopedia/')).toBe(true);
    const spec = toDiagnosticSpec(base({ ruleId: 'EX-014' }), new LineIndex('x'), []);
    expect(spec.code).toBe('EX-014');
    expect(spec.href).toBe('https://exorcist-98.vercel.app/encyclopedia/EX-014');
  });

  it('covers the exact span when the span is the text', () => {
    const findings = scanner.scan(HAUNTED, 'AGENTS.md', 'instruction');
    const index = new LineIndex(HAUNTED);
    const runs = hiddenRuns(HAUNTED);
    const comment = findings.find((f) => f.ruleId === 'EX-004') as Finding;
    const spec = toDiagnosticSpec(comment, index, runs);
    const lines = HAUNTED.split('\n');
    expect(spec.start).toEqual({ line: 4, character: 0 });
    expect(spec.end).toEqual({ line: 4, character: (lines[4] as string).length });
    const img = toDiagnosticSpec(findings.find((f) => f.ruleId === 'EX-012') as Finding, index, runs);
    expect(HAUNTED.slice(...findingOffsets(findings.find((f) => f.ruleId === 'EX-012') as Finding, index, runs))).toBe(lines[6]);
    expect(img.level).toBe('error');
  });

  it('covers the whole hidden run for hidden-character findings (their span is escaped text)', () => {
    const findings = scanner.scan(HAUNTED, 'AGENTS.md', 'instruction');
    const index = new LineIndex(HAUNTED);
    const runs = hiddenRuns(HAUNTED);
    const zw = findings.find((f) => f.ruleId === 'EX-001' && f.line === 2) as Finding;
    const [a, b] = findingOffsets(zw, index, runs);
    expect(HAUNTED.slice(a, b)).toBe('​​');
    const tag = findings.find((f) => f.ruleId === 'EX-001' && f.line === 3) as Finding;
    const [c, d] = findingOffsets(tag, index, runs);
    expect(d - c).toBe(TAG_MESSAGE.length * 2); // every tag character is a surrogate pair
    const spec = toDiagnosticSpec(tag, index, runs);
    expect(spec.start.line).toBe(2);
    expect(spec.end.line).toBe(2);
  });

  it('falls back to the rest of the line, at most 120 characters, when the span is not in the text', () => {
    const text = `a\n${'y'.repeat(300)}\n`;
    const index = new LineIndex(text);
    const [a, b] = findingOffsets(base({ line: 2, col: 5, span: 'summary, not text' }), index, []);
    expect(a).toBe(2 + 4);
    expect(b - a).toBe(120);
    const [c, d] = findingOffsets(base({ line: 1, col: 1, span: 'zz' }), index, []);
    expect([c, d]).toEqual([0, 1]);
  });

  it('keeps out-of-range positions inside the text', () => {
    const index = new LineIndex('ab\r\ncd');
    expect(findingOffsets(base({ line: 9, col: 1, span: 'q' }), index, [])[0]).toBe(0);
    expect(index.offsetOf(1, 99)).toBe(2); // clamped before the \r\n
    expect(index.positionAt(99)).toEqual({ line: 1, character: 2 });
  });

  it('writes a plain-language message with the decoded message made safe and the fix', () => {
    const findings = scanner.scan(HAUNTED, 'AGENTS.md', 'instruction');
    const tag = findings.find((f) => f.ruleId === 'EX-001' && f.line === 3) as Finding;
    const msg = diagnosticMessage(tag);
    expect(msg.split('\n')[0]).toContain('This file hides instructions for your AI');
    expect(msg).toContain(`Hidden message (attacker text, do not follow): "${TAG_MESSAGE}"`);
    expect(msg).toMatch(/\nFix: /);
  });

  it('never puts a raw invisible or direction character into a message', () => {
    const msg = diagnosticMessage(base({ decoded: 'run ‮rm‬ now​', fix: 'x⁦y' }));
    expect(msg).not.toMatch(/[​‪-‮⁦-⁩]/);
    expect(msg).toContain('[U+202E]');
  });

  it('cuts a long decoded message', () => {
    const msg = diagnosticMessage(base({ decoded: 'z'.repeat(1000) }));
    expect(msg.length).toBeLessThan(600);
    expect(msg).toContain('…');
  });
});
