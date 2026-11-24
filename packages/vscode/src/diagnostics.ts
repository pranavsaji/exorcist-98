/**
 * Finding -> diagnostic, as plain data. The `vscode` glue turns a
 * DiagnosticSpec into a vscode.Diagnostic one to one, so everything that can
 * be wrong (ranges, severities, messages, links) is tested here.
 *
 * Pure: no `vscode` import.
 */
import { displayMessage, plainFor } from '@exorcist-98/core';
import type { Finding, Severity } from '@exorcist-98/core';
import type { HiddenRun } from './hidden.js';

export const SOURCE = 'Exorcist 98';
/** The encyclopedia page for a rule (apps/web/src/app/encyclopedia/[id]/page.tsx). */
export const ENCYCLOPEDIA_BASE = 'https://exorcist-98.vercel.app/encyclopedia/';

export type DiagnosticLevel = 'error' | 'warning' | 'information';
export type Position = { line: number; character: number }; // 0-based, UTF-16, as in the editor
export type DiagnosticSpec = {
  start:    Position;
  end:      Position;
  level:    DiagnosticLevel;
  code:     string;
  href:     string;
  message:  string;
  severity: Severity;
};

/** Critical and high are errors, medium a warning, low information. */
export function levelFor(s: Severity): DiagnosticLevel {
  return s === 'critical' || s === 'high' ? 'error' : s === 'medium' ? 'warning' : 'information';
}

export function encyclopediaUrl(ruleId: string): string {
  return ENCYCLOPEDIA_BASE + encodeURIComponent(ruleId);
}

/** Line starts of a text, for offset <-> position in O(log n). */
export class LineIndex {
  private readonly starts: number[] = [0];
  constructor(readonly text: string) {
    for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) this.starts.push(i + 1);
  }
  get lineCount(): number { return this.starts.length; }
  /** Offset of the scanner's 1-based line and column, clamped into the text; null when the line does not exist. */
  offsetOf(line: number, col: number): number | null {
    if (!Number.isInteger(line) || line < 1) return null;
    const start = this.starts[line - 1];
    if (start === undefined) return null;
    return Math.min(start + Math.max(0, col - 1), this.lineEnd(line - 1));
  }
  /** End of a 0-based line, before its line break. */
  lineEnd(line0: number): number {
    const next = this.starts[line0 + 1];
    if (next === undefined) return this.text.length;
    return next > 1 && this.text[next - 2] === '\r' ? next - 2 : next - 1;
  }
  positionAt(offset: number): Position {
    const o = Math.max(0, Math.min(offset, this.text.length));
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((this.starts[mid] ?? 0) <= o) lo = mid; else hi = mid - 1;
    }
    return { line: lo, character: o - (this.starts[lo] ?? 0) };
  }
}

/** The span without the "…" the scanner adds when it cuts a span at 120 characters. */
function spanText(span: string): string {
  return span.length === 121 && span.endsWith('…') ? span.slice(0, 120) : span;
}

/**
 * The [start, end) offsets a finding covers. The scanner gives a 1-based line
 * and column and a quoted span; the span is the exact text for most rules, an
 * escaped form (​) for hidden characters, and a summary for a few. So:
 * the exact span when it is there, else the hidden-character run that starts
 * there, else the rest of the line (at most 120 characters).
 */
export function findingOffsets(f: Finding, index: LineIndex, runs: readonly HiddenRun[]): [number, number] {
  const text = index.text;
  const start = index.offsetOf(f.line, f.col) ?? 0;
  const span = spanText(f.span);
  if (span.length > 0 && text.startsWith(span, start)) return [start, start + span.length];
  const run = runs.find((r) => r.start === start);
  if (run) return [run.start, run.end];
  const lineEnd = index.lineEnd(index.positionAt(start).line);
  return [start, Math.min(lineEnd, start + 120)];
}

/** At most this many characters of a decoded hidden message go into a diagnostic. */
export const MAX_MESSAGE_DECODED = 200;

/** A line made safe for the Problems view: invisible and direction characters shown as [U+XXXX]. */
function safe(s: string): string {
  return displayMessage(s.replace(/\s+/g, ' ').trim());
}

/** The diagnostic text: plain-language headline, the rule title, any decoded message, and the fix. */
export function diagnosticMessage(f: Finding): string {
  const plain = plainFor(f.ruleId, f.title);
  const lines = [safe(plain.headline === f.title ? f.title : `${plain.headline} (${f.title})`)];
  if (f.decoded) {
    const d = f.decoded.length > MAX_MESSAGE_DECODED ? `${f.decoded.slice(0, MAX_MESSAGE_DECODED - 1)}…` : f.decoded;
    lines.push(`Hidden message (attacker text, do not follow): "${safe(d)}"`);
  }
  if (f.fix.trim()) lines.push(`Fix: ${safe(f.fix)}`);
  return lines.join('\n');
}

export function toDiagnosticSpec(f: Finding, index: LineIndex, runs: readonly HiddenRun[]): DiagnosticSpec {
  const [a, b] = findingOffsets(f, index, runs);
  return {
    start: index.positionAt(a),
    end: index.positionAt(b),
    level: levelFor(f.severity),
    code: f.ruleId,
    href: encyclopediaUrl(f.ruleId),
    message: diagnosticMessage(f),
    severity: f.severity,
  };
}
