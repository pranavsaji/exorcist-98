/**
 * Exorcise (Disinfect): the fixes that have one safe, mechanical answer.
 *
 *   EX-001  remove hidden characters (the normalizer's benign uses are kept:
 *           emoji ZWJ sequences, U+FE0F, joining-script spelling, a leading BOM,
 *           subdivision flags)
 *   EX-021  remove runs of 4+ variation selectors (smuggled bytes); one to
 *           three, as in emoji and CJK presentation, are never touched
 *   EX-002  remove an HTML comment that holds instructions addressed to an AI
 *   EX-004  remove a smuggled HTML comment
 *   EX-010  pin `npx pkg` / `uvx pkg` to the exact current version (the version
 *           is looked up first, see exorcise-registry.ts; skipped with a note
 *           when it cannot be)
 *   EX-012  replace a data-carrying remote image with its alt text and a comment
 *
 * Everything else is reported, never edited. The fixers are pure: text and the
 * scan's findings in, new text plus a list of changes out. Every edit is checked
 * against the text before it is made; an edit that cannot be placed exactly is
 * skipped with a note instead of guessed.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createTwoFilesPatch } from 'diff';
import { findHiddenUnicode, isHiddenCodePoint, normalize } from './normalizer.js';
import type { UnicodeClass, UnicodeHit } from './normalizer.js';
import { fencedRanges, inMarkdownCode } from './scanner/context.js';
import { runSignatures } from './scanner/signature-engine.js';
import { deduplicate } from './scanner/orchestrator.js';
import { typosquatOf } from './known-packages.js';
import { classifyFile } from './walker.js';
import type { Finding } from './types.js';
import type { VirusDefinition } from './definitions/schema.js';

// ── Types ─────────────────────────────────────────────────────────────────────

export const FIXABLE_RULES = ['EX-001', 'EX-002', 'EX-004', 'EX-010', 'EX-012', 'EX-021'] as const;
export type FixableRule = (typeof FIXABLE_RULES)[number];
export const isFixableRule = (id: string): id is FixableRule => (FIXABLE_RULES as readonly string[]).includes(id);

/** One edit that was made. `line`/`col` are in the original file. */
export type ExorciseChange = { ruleId: FixableRule; line: number; col: number; summary: string };
/** A fixable finding that was left alone, and why. */
export type ExorciseNote = { ruleId: FixableRule; line: number; col: number; message: string };

export type FileExorcism = {
  file:    string;
  before:  string;
  after:   string;
  /** At most MAX_LISTED_CHANGES; past that the last entry summarises the rest. */
  changes: ExorciseChange[];
  /** How many changes were really made (counted before the list was capped). */
  changeCount: number;
  notes:   ExorciseNote[];
};

/** Changes (and notes) listed per file; a file with more gets one summary line for the rest. */
export const MAX_LISTED_CHANGES = 500;

export type Ecosystem = 'npm' | 'pypi';
export type PinRequest = { ecosystem: Ecosystem; name: string };
export type VersionAnswer = { ok: true; version: string } | { ok: false; reason: string };
/** Answers keyed by `pinKey`. */
export type VersionTable = ReadonlyMap<string, VersionAnswer>;
export type VersionLookup = (req: PinRequest) => Promise<VersionAnswer>;
export const pinKey = (r: PinRequest): string => `${r.ecosystem}:${r.name}`;

export const IMAGE_COMMENT = '<!-- exorcised: remote image removed -->';

// ── Positions ─────────────────────────────────────────────────────────────────

/**
 * Line starts of one text, computed once, so turning offsets into line and
 * column (and back) costs a binary search instead of a pass over the text.
 */
class LineIndex {
  private readonly starts: number[] = [0];
  constructor(private readonly text: string) {
    for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) this.starts.push(i + 1);
  }
  /** UTF-16 offset of a 1-based line and column, or null when it is outside the text. */
  offset(line: number, col: number): number | null {
    if (!Number.isInteger(line) || !Number.isInteger(col) || line < 1 || col < 1) return null;
    const start = this.starts[line - 1];
    if (start === undefined) return null;
    const at = start + col - 1;
    return at <= this.text.length ? at : null;
  }
  /** 1-based line and column of an offset (the scanner's convention). */
  position(offset: number): { line: number; col: number } {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((this.starts[mid] ?? 0) <= offset) lo = mid; else hi = mid - 1;
    }
    return { line: lo + 1, col: offset - (this.starts[lo] ?? 0) + 1 };
  }
}

/** UTF-16 offset of a 1-based line and column (the scanner's convention), or null. */
export function positionToOffset(text: string, line: number, col: number): number | null {
  return new LineIndex(text).offset(line, col);
}

/**
 * True for a path that is safe to name in a patch and to write: relative, no
 * `.`/`..`/empty segments, no backslash and no control characters (C0, DEL,
 * C1). A newline in a name could otherwise add diff headers of its own.
 */
export function isSafePatchPath(p: string): boolean {
  return p.length > 0 && p.length <= 4096 && !/[\u0000-\u001F\u007F-\u009F\\]/.test(p) && !p.startsWith('/')
    && !/^[A-Za-z]:/.test(p) && p.split('/').every((seg) => seg !== '' && seg !== '.' && seg !== '..');
}

/** A path as git writes it in a diff header: bare when plain, else C-quoted with octal UTF-8 bytes. */
export function gitQuotePath(p: string): string {
  if (/^[A-Za-z0-9._\/@+,=~-]+$/.test(p)) return p;
  let out = '"';
  for (const byte of Buffer.from(p, 'utf8')) {
    if (byte === 0x22) out += '\\"';
    else if (byte === 0x5c) out += '\\\\';
    else if (byte === 0x09) out += '\\t';
    else if (byte === 0x0a) out += '\\n';
    else if (byte < 0x20 || byte >= 0x7f) out += `\\${byte.toString(8).padStart(3, '0')}`;
    else out += String.fromCharCode(byte);
  }
  return `${out}"`;
}

const stripHidden = (s: string): string => Array.from(s).filter((c) => !isHiddenCodePoint(c.codePointAt(0) ?? 0)).join('');

/** A finding's span without the "…" the scanner adds when it cuts a span at 120 characters. */
function spanBase(span: string): { text: string; cut: boolean } {
  return span.length === 121 && span.endsWith('…') ? { text: span.slice(0, 120), cut: true } : { text: span, cut: false };
}

function sameSpan(found: string, span: string): boolean {
  const b = spanBase(span);
  const f = stripHidden(found);
  const s = stripHidden(b.text);
  return b.cut ? f.startsWith(s) : f === s;
}

const isTimeoutFinding = (f: Finding): boolean => f.span === `${f.ruleId} ran out of time on this file`;

// ── EX-001 / EX-021 hidden characters ─────────────────────────────────────────

/** The character classes each rule reports. */
const RULE_CLASSES: Record<'EX-001' | 'EX-021', readonly UnicodeClass[]> = {
  'EX-001': ['zero-width', 'bidi-override', 'tag-block'],
  'EX-021': ['variation-selector'],
};
const ALL_CLASSES: ReadonlySet<UnicodeClass> = new Set([...RULE_CLASSES['EX-001'], ...RULE_CLASSES['EX-021']]);
const ruleOfClass = (c: UnicodeClass): 'EX-001' | 'EX-021' => (c === 'variation-selector' ? 'EX-021' : 'EX-001');

export type HiddenRemoval = {
  text:    string;
  /** The removed characters, with offsets in the input text, in order. */
  removed: UnicodeHit[];
};

/**
 * Remove every hidden character EX-001 and EX-021 report (or only those of
 * `classes`). Only zero-width, bidi-control, tag and variation-selector
 * characters are ever removed, so the visible text is unchanged, and the
 * normalizer's benign uses (an emoji ZWJ sequence, a single U+FE0F or any run
 * of one to three variation selectors, a joining-script spelling, a leading
 * BOM, a subdivision flag) stay exactly as they are.
 */
export function removeHiddenUnicode(text: string, classes: ReadonlySet<UnicodeClass> = ALL_CLASSES): HiddenRemoval {
  let cur = text;
  // index in `cur` -> index in `text` (null while they are the same)
  let toOrig: number[] | null = null;
  const removed: UnicodeHit[] = [];
  // Removing a character never makes another one hidden, so this loop ends
  // after one round; the bound is a guard, not a tuning knob.
  for (let round = 0; round < 4; round++) {
    const hits = findHiddenUnicode(cur).filter((h) => classes.has(h.class));
    if (hits.length === 0) break;
    const parts: string[] = [];
    const nextOrig: number[] = [];
    let last = 0;
    const keep = (from: number, to: number): void => {
      parts.push(cur.slice(from, to));
      for (let i = from; i < to; i++) nextOrig.push(toOrig ? (toOrig[i] ?? i) : i);
    };
    for (const h of hits) {
      keep(last, h.offset);
      removed.push({ ...h, offset: toOrig ? (toOrig[h.offset] ?? h.offset) : h.offset });
      last = h.offset + h.char.length;
    }
    keep(last, cur.length);
    cur = parts.join('');
    toOrig = nextOrig;
  }
  removed.sort((a, b) => a.offset - b.offset);
  return { text: cur, removed };
}

/** Map an offset in the original text to the text with `removed` taken out. */
function shiftThrough(removed: readonly UnicodeHit[]): (o: number) => number {
  if (removed.length === 0) return (o) => o;
  const starts = removed.map((h) => h.offset);
  const cum: number[] = [];
  let acc = 0;
  for (const h of removed) { acc += h.char.length; cum.push(acc); }
  return (o) => {
    let lo = 0;
    let hi = starts.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if ((starts[mid] ?? 0) < o) lo = mid + 1; else hi = mid; }
    return o - (lo === 0 ? 0 : (cum[lo - 1] ?? 0));
  };
}

const cpName = (cp: number): string => `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;

function hiddenChanges(lines: LineIndex, removed: readonly UnicodeHit[]): ExorciseChange[] {
  const out: ExorciseChange[] = [];
  let run: UnicodeHit[] = [];
  const flush = (): void => {
    const first = run[0];
    if (!first) return;
    const { line, col } = lines.position(first.offset);
    const names = [...new Set(run.map((h) => cpName(h.codePoint)))];
    const list = names.length > 4 ? `${names.slice(0, 4).join(' ')} ...` : names.join(' ');
    const ruleId = ruleOfClass(first.class);
    const what = ruleId === 'EX-021' ? 'variation selector' : 'hidden character';
    out.push({ ruleId, line, col, summary: `removed ${run.length} ${what}${run.length === 1 ? '' : 's'} (${list})` });
    run = [];
  };
  for (const h of removed) {
    const prev = run[run.length - 1];
    if (prev && (h.offset !== prev.offset + prev.char.length || ruleOfClass(prev.class) !== ruleOfClass(h.class))) flush();
    run.push(h);
  }
  flush();
  return out;
}

// ── EX-010 pin targets ────────────────────────────────────────────────────────

const RUNNERS: Record<string, Ecosystem> = { npx: 'npm', bunx: 'npm', pnpx: 'npm', uvx: 'pypi' };
const UNPINNED = /^(@[a-z0-9._-]+\/)?[a-z0-9][a-z0-9._-]*$/i;

type PinTarget = PinRequest & { viaFrom: boolean; plain: boolean };

/** The same argument `packageArg` in the signature engine picks, with how it was given. */
function packageArgOf(args: unknown[]): { name: string; viaFrom: boolean; plain: boolean } | null {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (typeof a !== 'string') return null;
    if (a === '--package' || a === '-p' || a === '--from') {
      const v = args[i + 1];
      return typeof v === 'string' ? { name: v, viaFrom: a === '--from', plain: true } : null;
    }
    const eq = /^--(package|from)=(.+)$/.exec(a);
    if (eq) return { name: eq[2] ?? '', viaFrom: eq[1] === 'from', plain: false };
    if (a.startsWith('-')) continue;
    return { name: a, viaFrom: false, plain: true };
  }
  return null;
}

/** Every unpinned package a runner is told to run, in document order. */
function pinTargets(text: string): PinTarget[] {
  let json: unknown;
  try { json = JSON.parse(text); } catch { return []; }
  const out: PinTarget[] = [];
  const visit = (node: unknown, depth: number): void => {
    if (depth > 64 || node === null || typeof node !== 'object') return;
    if (Array.isArray(node)) { for (const v of node) visit(v, depth + 1); return; }
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (k === 'mcpServers' && v && typeof v === 'object' && !Array.isArray(v)) {
        for (const server of Object.values(v as Record<string, unknown>)) {
          if (!server || typeof server !== 'object') continue;
          const s = server as Record<string, unknown>;
          const eco = typeof s['command'] === 'string' ? RUNNERS[s['command']] : undefined;
          if (!eco || !Array.isArray(s['args'])) continue;
          const arg = packageArgOf(s['args']);
          if (arg && UNPINNED.test(arg.name)) out.push({ ecosystem: eco, name: arg.name, viaFrom: arg.viaFrom, plain: arg.plain });
        }
      }
      visit(v, depth + 1);
    }
  };
  visit(json, 0);
  return out;
}

const signatureFindings = (findings: readonly Finding[], rule: FixableRule): Finding[] =>
  findings.filter((f) => f.source === 'signature' && f.ruleId === rule && !isTimeoutFinding(f));

/** The version lookups a file's EX-010 findings need. */
export function pinRequests(text: string, findings: readonly Finding[]): PinRequest[] {
  const wanted = new Set(signatureFindings(findings, 'EX-010').map((f) => f.span));
  if (wanted.size === 0) return [];
  const seen = new Map<string, PinRequest>();
  for (const t of pinTargets(text)) {
    if (!wanted.has(t.name) || !t.plain || typosquatOf(t.name) !== null) continue;
    seen.set(pinKey(t), { ecosystem: t.ecosystem, name: t.name });
  }
  return [...seen.values()];
}

// ── Edits ─────────────────────────────────────────────────────────────────────

type Edit = { start: number; end: number; replacement: string; change: ExorciseChange };

/** The comment [start, end) widened to whole lines when nothing else is on them. */
function commentRemoval(text: string, start: number, end: number): [number, number] {
  const lineStart = text.lastIndexOf('\n', start - 1) + 1;
  const nl = text.indexOf('\n', end);
  const lineEnd = nl === -1 ? text.length : nl;
  if (/^[ \t]*$/.test(text.slice(lineStart, start)) && /^[ \t\r]*$/.test(text.slice(end, lineEnd))) {
    return [lineStart, nl === -1 ? text.length : nl + 1];
  }
  return [start, end];
}

export type ExorciseFileInput = {
  file:      string;
  text:      string;
  findings:  readonly Finding[];
  /** Fixes to run (default: all of FIXABLE_RULES). */
  only?:     ReadonlySet<string>;
  /** Versions for EX-010, from `pinRequests` and a lookup. Missing means "not looked up". */
  versions?: VersionTable;
};

/** Apply every safe fix for one file's findings. Pure. */
export function exorciseFile(input: ExorciseFileInput): FileExorcism {
  const { file, text: original } = input;
  const only = input.only ?? new Set<string>(FIXABLE_RULES);
  const { findings } = input;
  const changes: ExorciseChange[] = [];
  const notes: ExorciseNote[] = [];
  const note = (f: Finding, ruleId: FixableRule, message: string): void => {
    notes.push({ ruleId, line: f.line, col: f.col, message });
  };
  if (!isSafePatchPath(file)) {
    const first = findings.find((f) => isFixableRule(f.ruleId));
    return {
      file, before: original, after: original, changes: [], changeCount: 0,
      notes: first && isFixableRule(first.ruleId)
        ? [{ ruleId: first.ruleId, line: first.line, col: first.col, message: 'the file name has control characters or is not a plain relative path, so it was not changed; needs a human' }]
        : [],
    };
  }
  const originalLines = new LineIndex(original);

  // 1. Hidden characters first; later edits are placed through the offset map.
  //    When both rules are on, everything either reports goes, so taking out a
  //    zero-width character can never leave a new run of selectors behind.
  let text = original;
  let shift = (o: number): number => o;
  // Taking out a smuggled run of selectors can also leave a zero-width
  // character next to an emoji that the scan had let pass, so it then counts
  // as hidden. Both rules on: either finding clears both kinds.
  const has001 = signatureFindings(findings, 'EX-001').length > 0;
  const has021 = signatureFindings(findings, 'EX-021').length > 0;
  const fix001 = only.has('EX-001') && (has001 || (has021 && only.has('EX-021')));
  const fix021 = only.has('EX-021') && (has021 || fix001);
  const hiddenClasses = new Set<UnicodeClass>([...(fix001 ? RULE_CLASSES['EX-001'] : []), ...(fix021 ? RULE_CLASSES['EX-021'] : [])]);
  if (hiddenClasses.size > 0) {
    const r = removeHiddenUnicode(original, hiddenClasses);
    text = r.text;
    shift = shiftThrough(r.removed);
    changes.push(...hiddenChanges(originalLines, r.removed));
  }
  const at = (f: Finding): number | null => {
    const o = originalLines.offset(f.line, f.col);
    return o === null ? null : shift(o);
  };

  const edits: Edit[] = [];
  let fences: Array<[number, number]> | null = null;

  // 2. HTML comments flagged by EX-004 (the match is the comment) or EX-002 (a phrase inside one).
  for (const rule of ['EX-004', 'EX-002'] as const) {
    if (!only.has(rule)) continue;
    for (const f of signatureFindings(findings, rule)) {
      const o = at(f);
      if (o === null) { note(f, rule, 'could not be located in the file; left for a human'); continue; }
      let start: number;
      if (rule === 'EX-004') {
        if (!text.startsWith('<!--', o)) { note(f, rule, 'the comment could not be located exactly; left for a human'); continue; }
        start = o;
      } else {
        start = text.lastIndexOf('<!--', o);
        if (start === -1) continue; // not inside a comment: not a mechanical fix
        const closeBefore = text.indexOf('-->', start + 4);
        if (closeBefore !== -1 && closeBefore < o) continue; // the comment ended before the phrase
        fences ??= fencedRanges(text);
        if (inMarkdownCode(text, start, fences)) continue; // a comment shown as code is not hidden
      }
      const close = text.indexOf('-->', start + 4);
      if (close === -1) { note(f, rule, 'the comment is never closed; left for a human'); continue; }
      const end = close + 3;
      const comment = text.slice(start, end);
      const spanOk = rule === 'EX-004'
        ? sameSpan(comment, f.span)
        : stripHidden(comment).includes(stripHidden(spanBase(f.span).text));
      if (!spanOk) { note(f, rule, 'the flagged text could not be matched exactly; left for a human'); continue; }
      const [a, b] = commentRemoval(text, start, end);
      const lines = (comment.match(/\n/g) ?? []).length + 1;
      edits.push({
        start: a, end: b, replacement: '',
        change: { ruleId: rule, line: f.line, col: f.col, summary: `removed a hidden HTML comment (${lines} line${lines === 1 ? '' : 's'})` },
      });
    }
  }

  // 3. EX-012: a remote image that carries data becomes its alt text.
  if (only.has('EX-012')) {
    for (const f of signatureFindings(findings, 'EX-012')) {
      const o = at(f);
      const re = /!\[([^\]]*)\]\(([^)\s]*)\)/y;
      re.lastIndex = o ?? 0;
      const m = o === null ? null : re.exec(text);
      if (!m || !sameSpan(m[0], f.span)) { note(f, 'EX-012', 'the image could not be located exactly; left for a human'); continue; }
      const alt = (m[1] ?? '').replace(/<!--|-->/g, '').trim();
      edits.push({
        start: m.index, end: m.index + m[0].length,
        replacement: alt ? `${alt} ${IMAGE_COMMENT}` : IMAGE_COMMENT,
        change: { ruleId: 'EX-012', line: f.line, col: f.col, summary: `replaced a remote image${alt ? ` with its alt text "${alt.slice(0, 40)}"` : ''}` },
      });
    }
  }

  // 4. EX-010: pin the package to the version that was looked up.
  if (only.has('EX-010')) {
    const targets = pinTargets(original);
    const used = new Map<string, number>();
    for (const f of signatureFindings(findings, 'EX-010')) {
      const n = used.get(f.span) ?? 0;
      used.set(f.span, n + 1);
      const t = targets.filter((x) => x.name === f.span)[n];
      if (!t) { note(f, 'EX-010', 'the server entry could not be found; left for a human'); continue; }
      if (!t.plain) { note(f, 'EX-010', `"${t.name}" is given inside a --package= or --from= option; pin it by hand`); continue; }
      if (typosquatOf(t.name) !== null) { note(f, 'EX-010', `"${t.name}" looks like a misspelled package (EX-013); pinning it would keep the wrong package. Fix the name by hand`); continue; }
      const answer = input.versions?.get(pinKey(t));
      if (!answer) { note(f, 'EX-010', `the current version of "${t.name}" was not looked up (offline); left for a human`); continue; }
      if (!answer.ok) { note(f, 'EX-010', `${answer.reason}; left for a human`); continue; }
      const quoted = JSON.stringify(t.name);
      const o = at(f);
      const raw = originalLines.offset(f.line, f.col);
      if (o === null || raw === null || !original.startsWith(quoted, raw) || !text.startsWith(quoted, o)) {
        note(f, 'EX-010', 'the package name could not be located exactly; left for a human');
        continue;
      }
      const pinned = t.ecosystem === 'pypi' && t.viaFrom ? `${t.name}==${answer.version}` : `${t.name}@${answer.version}`;
      edits.push({
        start: o, end: o + quoted.length, replacement: JSON.stringify(pinned),
        change: { ruleId: 'EX-010', line: f.line, col: f.col, summary: `pinned ${t.name} to ${answer.version} (current version on ${t.ecosystem === 'npm' ? 'npm' : 'PyPI'})` },
      });
    }
  }

  // 5. Apply the edits, latest first. Two edits that overlap are one problem;
  //    the first is kept (an EX-002 and an EX-004 finding on one comment).
  edits.sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: Edit[] = [];
  for (const e of edits) {
    const prev = kept[kept.length - 1];
    if (prev && e.start < prev.end) continue;
    kept.push(e);
  }
  for (let i = kept.length - 1; i >= 0; i--) {
    const e = kept[i];
    if (e) text = text.slice(0, e.start) + e.replacement + text.slice(e.end);
  }
  changes.push(...kept.map((e) => e.change));

  // 6. A last check: nothing hidden is left behind by the edits.
  if (hiddenClasses.size > 0) {
    const again = removeHiddenUnicode(text, hiddenClasses);
    if (again.removed.length > 0) {
      changes.push(...hiddenChanges(new LineIndex(text), again.removed));
      text = again.text;
    }
  }

  changes.sort((a, b) => a.line - b.line || a.col - b.col);
  return { file, before: original, after: text, changes: capChanges(changes), changeCount: changes.length, notes: capNotes(notes) };
}

function capChanges(changes: ExorciseChange[]): ExorciseChange[] {
  if (changes.length <= MAX_LISTED_CHANGES) return changes;
  const kept = changes.slice(0, MAX_LISTED_CHANGES - 1);
  const rest = changes.slice(MAX_LISTED_CHANGES - 1);
  const first = rest[0] as ExorciseChange;
  const last = rest[rest.length - 1] as ExorciseChange;
  kept.push({ ...first, summary: `and ${rest.length} more changes in this file (lines ${first.line}-${last.line})` });
  return kept;
}

function capNotes(notes: ExorciseNote[]): ExorciseNote[] {
  if (notes.length <= MAX_LISTED_CHANGES) return notes;
  const rest = notes.slice(MAX_LISTED_CHANGES - 1);
  const first = rest[0] as ExorciseNote;
  return [...notes.slice(0, MAX_LISTED_CHANGES - 1), { ...first, message: `and ${rest.length} more findings left for a human in this file` }];
}

// ── Several files ─────────────────────────────────────────────────────────────

export type ExorciseOptions = {
  only?:   readonly string[];
  /** How to find current versions for EX-010. Null or missing: no network, pins are skipped with a note. */
  lookup?: VersionLookup | null;
  /** At most this many distinct packages are looked up in one run. */
  maxLookups?: number;
};

export type ExorciseInput = { file: string; text: string; findings: readonly Finding[] };

/** Look up every version the inputs need, then fix each file. Files with nothing to say are left out. */
export async function exorciseTexts(inputs: readonly ExorciseInput[], opts: ExorciseOptions = {}): Promise<FileExorcism[]> {
  const only = new Set<string>(opts.only ?? FIXABLE_RULES);
  const requests = new Map<string, PinRequest>();
  if (only.has('EX-010')) {
    for (const i of inputs) for (const r of pinRequests(i.text, i.findings)) requests.set(pinKey(r), r);
  }
  const versions = new Map<string, VersionAnswer>();
  const max = opts.maxLookups ?? 50;
  const reqs = [...requests.values()];
  await Promise.all(reqs.map(async (r, i) => {
    let answer: VersionAnswer;
    if (!opts.lookup) answer = { ok: false, reason: `the current version of "${r.name}" was not looked up (offline)` };
    else if (i >= max) answer = { ok: false, reason: `more than ${max} packages to look up in one run` };
    else {
      try { answer = await opts.lookup(r); } catch { answer = { ok: false, reason: `could not look up "${r.name}"` }; }
    }
    versions.set(pinKey(r), answer);
  }));
  return inputs
    .map((i) => exorciseFile({ ...i, only, versions }))
    .filter((r) => r.changes.length > 0 || r.notes.length > 0);
}

/**
 * Read and fix every file under `root` that has a fixable finding. A file that
 * is not valid UTF-8 is left alone (rewriting it could change bytes nobody
 * meant to touch).
 */
export async function exorciseRepo(root: string, findings: readonly Finding[], opts: ExorciseOptions = {}): Promise<FileExorcism[]> {
  const only = new Set<string>(opts.only ?? FIXABLE_RULES);
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.source !== 'signature' || !isFixableRule(f.ruleId) || !only.has(f.ruleId)) continue;
    const list = byFile.get(f.file) ?? [];
    list.push(f);
    byFile.set(f.file, list);
  }
  const inputs: ExorciseInput[] = [];
  const notUtf8: FileExorcism[] = [];
  for (const [file, list] of [...byFile.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    let bytes: Buffer;
    try { bytes = await readFile(join(root, file)); } catch { continue; }
    const text = bytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(bytes)) {
      const first = list[0];
      if (first && isFixableRule(first.ruleId)) {
        notUtf8.push({ file, before: text, after: text, changes: [], changeCount: 0, notes: [{ ruleId: first.ruleId, line: first.line, col: first.col, message: 'the file is not valid UTF-8, so it was not changed' }] });
      }
      continue;
    }
    inputs.push({ file, text, findings: list });
  }
  return [...await exorciseTexts(inputs, opts), ...notUtf8].sort((a, b) => a.file.localeCompare(b.file));
}

// ── Diff and re-scan ──────────────────────────────────────────────────────────

export type ExorcismPatch = {
  patch:   string;
  /** Files in the patch. */
  files:   number;
  /** Changes in the files that are in the patch. */
  fixes:   number;
  /** Files left out because the patch reached `maxBytes`. */
  omitted: number;
  /** Changed files left out because their path is unsafe (see isSafePatchPath). */
  unsafe:  number;
};

/** One git-style unified diff (`git apply` and `patch -p1` both read it) for every changed file. */
export function toUnifiedDiff(results: readonly FileExorcism[], opts: { maxBytes?: number } = {}): ExorcismPatch {
  const max = opts.maxBytes ?? Number.POSITIVE_INFINITY;
  const parts: string[] = [];
  let size = 0;
  let files = 0;
  let fixes = 0;
  let omitted = 0;
  let unsafe = 0;
  for (const r of [...results].sort((a, b) => a.file.localeCompare(b.file))) {
    if (r.after === r.before) continue;
    if (!isSafePatchPath(r.file)) { unsafe++; continue; }
    const a = gitQuotePath(`a/${r.file}`);
    const b = gitQuotePath(`b/${r.file}`);
    const body = createTwoFilesPatch(a, b, r.before, r.after, undefined, undefined, { context: 3 })
      .replace(/^=+\n/, '');
    const part = `diff --git ${a} ${b}\n${body}`;
    const bytes = Buffer.byteLength(part, 'utf8');
    if (size + bytes > max) { omitted++; continue; }
    parts.push(part);
    size += bytes;
    files++;
    fixes += r.changeCount;
  }
  return { patch: parts.join(''), files, fixes, omitted, unsafe };
}

/** Signature findings for texts that are not (or no longer) what is on disk, as `scanRepo` would report them. */
export function rescanTexts(entries: ReadonlyArray<{ file: string; text: string }>, defs: VirusDefinition[]): Finding[] {
  return deduplicate(entries.flatMap((e) => {
    const role = classifyFile(e.file);
    return runSignatures({ path: e.file, rel: e.file, role, sizeBytes: Buffer.byteLength(e.text, 'utf8') }, normalize(e.text, role), defs);
  }));
}
