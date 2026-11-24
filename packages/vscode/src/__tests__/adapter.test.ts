import { describe, expect, it } from 'vitest';
import type * as vscode from 'vscode';
import * as mock from './vscode-mock.js';
import { countGhosts, ruleIdOf, statusText, toDiagnostic, toSeverity, toWorkspaceEdit } from '../adapter.js';
import { LineIndex, SOURCE } from '../diagnostics.js';
import type { DiagnosticSpec } from '../diagnostics.js';

const spec: DiagnosticSpec = {
  start: { line: 2, character: 4 }, end: { line: 2, character: 9 },
  level: 'warning', code: 'EX-001', href: 'https://exorcist-98.vercel.app/encyclopedia/EX-001', message: 'm', severity: 'medium',
};

describe('adapter (vscode glue, with a mocked vscode module)', () => {
  it('builds a Diagnostic with range, severity, source and a linked code', () => {
    const d = toDiagnostic(spec) as unknown as mock.Diagnostic;
    expect(d.range.start).toEqual({ line: 2, character: 4 });
    expect(d.range.end).toEqual({ line: 2, character: 9 });
    expect(d.severity).toBe(mock.DiagnosticSeverity.Warning);
    expect(d.source).toBe(SOURCE);
    expect(d.code).toEqual({ value: 'EX-001', target: mock.Uri.parse(spec.href) });
    expect(ruleIdOf(d as unknown as vscode.Diagnostic)).toBe('EX-001');
  });

  it('maps every level', () => {
    expect(toSeverity('error')).toBe(mock.DiagnosticSeverity.Error);
    expect(toSeverity('warning')).toBe(mock.DiagnosticSeverity.Warning);
    expect(toSeverity('information')).toBe(mock.DiagnosticSeverity.Information);
  });

  it('ignores other extensions\' diagnostics', () => {
    const other = new mock.Diagnostic(new mock.Range(0, 0, 0, 1), 'x', mock.DiagnosticSeverity.Error);
    other.source = 'eslint';
    other.code = 'no-undef';
    expect(ruleIdOf(other as unknown as vscode.Diagnostic)).toBeNull();
  });

  it('turns text edits into one WorkspaceEdit of deletes and replaces at the right positions', () => {
    const text = 'ab\ncd​ef';
    const uri = mock.Uri.parse('file:///w/AGENTS.md');
    const we = toWorkspaceEdit(uri as unknown as vscode.Uri, new LineIndex(text), [
      { start: 5, end: 6, newText: '' },
      { start: 0, end: 1, newText: 'A' },
    ]) as unknown as mock.WorkspaceEdit;
    expect(we.ops).toHaveLength(2);
    expect(we.ops[0]).toMatchObject({ op: 'delete', range: { start: { line: 1, character: 2 }, end: { line: 1, character: 3 } } });
    expect(we.ops[1]).toMatchObject({ op: 'replace', text: 'A', range: { start: { line: 0, character: 0 }, end: { line: 0, character: 1 } } });
  });

  it('counts ghosts for the status bar', () => {
    const d = (s: mock.DiagnosticSeverity): mock.Diagnostic => new mock.Diagnostic(new mock.Range(0, 0, 0, 1), 'm', s);
    const entries: Array<[mock.Uri, mock.Diagnostic[]]> = [
      [mock.Uri.parse('file:///a'), [d(mock.DiagnosticSeverity.Error), d(mock.DiagnosticSeverity.Warning)]],
      [mock.Uri.parse('file:///b'), []],
      [mock.Uri.parse('file:///c'), [d(mock.DiagnosticSeverity.Information)]],
    ];
    const collection = { forEach: (cb: (u: mock.Uri, x: mock.Diagnostic[]) => void) => entries.forEach(([u, x]) => cb(u, x)) };
    const n = countGhosts(collection as unknown as vscode.DiagnosticCollection);
    expect(n).toEqual({ total: 3, files: 2, errors: 1, warnings: 1 });
    expect(statusText(n, true).text).toBe('👻 3');
    expect(statusText(n, true).tooltip).toContain('3 ghosts in 2 agent files (1 high or critical)');
    expect(statusText(n, false).tooltip).toContain('Restricted Mode');
    expect(statusText({ total: 0, files: 0, errors: 0, warnings: 0 }, true).tooltip).toContain('no ghosts');
  });
});
