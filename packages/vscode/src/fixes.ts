/**
 * Quick fixes, computed by the core's exorcise logic (`exorciseFile`, the same
 * code as `exorcist exorcise`) and turned into the smallest set of text edits,
 * so applying one keeps the cursor, folds and undo history sensible. Only the
 * offline fixes are offered: EX-010 (pinning a version) needs a registry
 * lookup, and the extension makes no network calls.
 *
 * Pure: no `vscode` import.
 */
import { exorciseFile, isFixableRule } from '@exorcist-98/core';
import type { Finding } from '@exorcist-98/core';

/** Replace [start, end) of the original text (UTF-16 offsets) with `newText`. */
export type TextEdit = { start: number; end: number; newText: string };

export const HIDDEN_RULES: ReadonlySet<string> = new Set(['EX-001', 'EX-021']);
/** One-finding fixes offered per diagnostic. */
export const SINGLE_FIX_RULES: ReadonlySet<string> = new Set(['EX-002', 'EX-004', 'EX-012']);

export const HIDDEN_FIX_TITLE = 'Exorcise: remove hidden characters';

export function singleFixTitle(ruleId: string): string {
  if (ruleId === 'EX-012') return 'Exorcise: replace the data-leaking image with its alt text';
  return 'Exorcise: remove the hidden HTML comment';
}

export type Exorcism = {
  edits:  TextEdit[];
  /** How many changes the core made (characters removed, comments removed, ...). */
  changeCount: number;
  /** Why a fixable finding was left alone, from the core. */
  notes:  string[];
  after:  string;
};

/** A name `exorciseFile` accepts (relative, no `..`, no control characters); it only labels the result. */
export function patchName(rel: string): string {
  const segs = rel.replace(/\\/g, '/').split('/').filter((s) => s !== '' && s !== '.' && s !== '..');
  const clean = segs.map((s) => s.replace(/[\u0000-\u001F\u007F-\u009F]/g, '_')).join('/');
  return clean === '' || /^[A-Za-z]:/.test(clean) ? 'file' : clean;
}

/** Remove every hidden character EX-001 and EX-021 report in this text. */
export function exorciseHidden(text: string, rel: string, findings: readonly Finding[]): Exorcism {
  return run(text, rel, findings.filter((f) => HIDDEN_RULES.has(f.ruleId)), HIDDEN_RULES);
}

/** The core's fix for one finding (EX-002, EX-004 or EX-012). */
export function exorciseOne(text: string, rel: string, finding: Finding): Exorcism {
  if (!isFixableRule(finding.ruleId) || !SINGLE_FIX_RULES.has(finding.ruleId)) {
    return { edits: [], changeCount: 0, notes: [], after: text };
  }
  return run(text, rel, [finding], new Set([finding.ruleId]));
}

function run(text: string, rel: string, findings: readonly Finding[], only: ReadonlySet<string>): Exorcism {
  if (findings.length === 0) return { edits: [], changeCount: 0, notes: [], after: text };
  const r = exorciseFile({ file: patchName(rel), text, findings, only });
  return {
    edits: r.after === text ? [] : editsBetween(text, r.after),
    changeCount: r.changeCount,
    notes: r.notes.map((n) => `${n.ruleId} line ${n.line}: ${n.message}`),
    after: r.after,
  };
}

/** Apply edits (non-overlapping, any order) to a text. */
export function applyEdits(text: string, edits: readonly TextEdit[]): string {
  const sorted = [...edits].sort((a, b) => b.start - a.start);
  let out = text;
  for (const e of sorted) out = out.slice(0, e.start) + e.newText + out.slice(e.end);
  return out;
}

/**
 * Edits that turn `before` into `after`. When `after` is `before` with code
 * points taken out (every hidden-character fix, and comment removal), the
 * edits are exactly those deletions, merged where adjacent; otherwise one
 * replacement of the part that differs. Every result is checked by applying
 * it; a mismatch falls back to replacing the whole text, which is always right.
 */
export function editsBetween(before: string, after: string): TextEdit[] {
  if (before === after) return [];
  const deletions = deletionEdits(before, after);
  if (deletions && applyEdits(before, deletions) === after) return deletions;
  const single = middleEdit(before, after);
  if (applyEdits(before, [single]) === after) return [single];
  return [{ start: 0, end: before.length, newText: after }];
}

/** Deletions of whole code points, or null when `after` is not a subsequence of `before`. */
function deletionEdits(before: string, after: string): TextEdit[] | null {
  if (after.length >= before.length) return null;
  const edits: TextEdit[] = [];
  let i = 0; // UTF-16 index in before
  let j = 0; // UTF-16 index in after
  while (i < before.length) {
    const cp = before.codePointAt(i) as number;
    const len = cp > 0xFFFF ? 2 : 1;
    if (j < after.length && after.codePointAt(j) === cp) {
      i += len;
      j += len;
      continue;
    }
    const last = edits[edits.length - 1];
    if (last && last.end === i) last.end = i + len;
    else edits.push({ start: i, end: i + len, newText: '' });
    i += len;
  }
  return j === after.length ? edits : null;
}

/** One edit replacing the differing middle, never splitting a surrogate pair. */
function middleEdit(before: string, after: string): TextEdit {
  const max = Math.min(before.length, after.length);
  let p = 0;
  while (p < max && before.charCodeAt(p) === after.charCodeAt(p)) p++;
  if (p > 0 && isHigh(before.charCodeAt(p - 1))) p--;
  let s = 0;
  while (s < max - p && before.charCodeAt(before.length - 1 - s) === after.charCodeAt(after.length - 1 - s)) s++;
  if (s > 0 && isLow(before.charCodeAt(before.length - s))) s--;
  return { start: p, end: before.length - s, newText: after.slice(p, after.length - s) };
}

const isHigh = (c: number): boolean => c >= 0xD800 && c <= 0xDBFF;
const isLow = (c: number): boolean => c >= 0xDC00 && c <= 0xDFFF;
