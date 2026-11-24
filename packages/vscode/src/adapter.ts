/**
 * The only conversions from the pure modules' plain data to `vscode` objects.
 * Kept one to one so the logic stays testable without an editor; tested with
 * a mocked `vscode` module.
 */
import * as vscode from 'vscode';
import type { DiagnosticLevel, DiagnosticSpec, LineIndex } from './diagnostics.js';
import { SOURCE } from './diagnostics.js';
import type { TextEdit } from './fixes.js';

export function toSeverity(level: DiagnosticLevel): vscode.DiagnosticSeverity {
  if (level === 'error') return vscode.DiagnosticSeverity.Error;
  if (level === 'warning') return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

export function toDiagnostic(spec: DiagnosticSpec): vscode.Diagnostic {
  const range = new vscode.Range(spec.start.line, spec.start.character, spec.end.line, spec.end.character);
  const d = new vscode.Diagnostic(range, spec.message, toSeverity(spec.level));
  d.source = SOURCE;
  d.code = { value: spec.code, target: vscode.Uri.parse(spec.href) };
  return d;
}

export function toRange(index: LineIndex, start: number, end: number): vscode.Range {
  const a = index.positionAt(start);
  const b = index.positionAt(end);
  return new vscode.Range(a.line, a.character, b.line, b.character);
}

/** One undoable WorkspaceEdit holding every edit for the document. */
export function toWorkspaceEdit(uri: vscode.Uri, index: LineIndex, edits: readonly TextEdit[]): vscode.WorkspaceEdit {
  const we = new vscode.WorkspaceEdit();
  for (const e of edits) {
    if (e.newText === '') we.delete(uri, toRange(index, e.start, e.end));
    else we.replace(uri, toRange(index, e.start, e.end), e.newText);
  }
  return we;
}

/** The rule id of one of our diagnostics, or null for anyone else's. */
export function ruleIdOf(d: vscode.Diagnostic): string | null {
  if (d.source !== SOURCE) return null;
  const c = d.code;
  if (typeof c === 'object' && c !== null && 'value' in c) return String(c.value);
  return typeof c === 'string' || typeof c === 'number' ? String(c) : null;
}

export type GhostCount = { total: number; files: number; errors: number; warnings: number };

/** Count our diagnostics across the collection. */
export function countGhosts(collection: vscode.DiagnosticCollection): GhostCount {
  const n: GhostCount = { total: 0, files: 0, errors: 0, warnings: 0 };
  collection.forEach((_uri, diags) => {
    if (diags.length === 0) return;
    n.files++;
    for (const d of diags) {
      n.total++;
      if (d.severity === vscode.DiagnosticSeverity.Error) n.errors++;
      else if (d.severity === vscode.DiagnosticSeverity.Warning) n.warnings++;
    }
  });
  return n;
}

/** Status bar text and tooltip for a count. */
export function statusText(n: GhostCount, trusted: boolean): { text: string; tooltip: string } {
  const text = n.total === 0 ? '👻 0' : `👻 ${n.total}`;
  const lines = [
    n.total === 0
      ? 'Exorcist 98: no ghosts in the agent files scanned.'
      : `Exorcist 98: ${n.total} ghost${n.total === 1 ? '' : 's'} in ${n.files} agent file${n.files === 1 ? '' : 's'}` +
        (n.errors > 0 ? ` (${n.errors} high or critical)` : '') + '.',
    'Click to open the Problems view.',
  ];
  if (!trusted) lines.push('Restricted Mode: scanning is read-only, and workspace settings that could hide findings are ignored.');
  return { text, tooltip: lines.join('\n') };
}
