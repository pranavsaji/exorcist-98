import { displayMessage } from './ouija.js';
import { redactSecretText } from './redact-secrets.js';
import { isTimeoutFinding } from './scanner/signature-engine.js';
import type { Finding } from './types.js';

/** Rules an inline directive can never silence: hidden characters and secrets. */
export const NEVER_INLINE: readonly string[] = ['EX-001', 'EX-011'];

/** A line is cut to this many characters before the directive is looked for. */
export const MAX_DIRECTIVE_LINE = 1000;
/** A reported reason is cut to this many characters. */
export const MAX_REASON = 200;

// One alternation of fixed openers, then fixed words. No nested quantifiers: the only
// repeats are single `\s*` / `\s+` runs between literals and one `.*` to the end of the line.
const DIRECTIVE_RE = /(?:\/\/|#|<!--|\/\*|--|;)\s*exorcist-ignore\s+(EX-\d{3})\s*:(.*)$/;

export type Directive = {
  ruleId: string;
  /** 1-based line the comment is on. */
  line: number;
  /** 0-based index of the comment opener on that line. */
  openerIndex: number;
  /** The reason as written, closers removed, trimmed. Untrusted: print only through `reasonForReport`. */
  reason: string;
};

/** Remove one trailing HTML or block comment closer and trim. */
function stripCloser(raw: string): string {
  const t = raw.trim();
  if (t.endsWith('-->')) return t.slice(0, -3).trim();
  if (t.endsWith('*/')) return t.slice(0, -2).trim();
  return t;
}

const HAS_WORD_CHAR = /[\p{L}\p{N}]/u;

/** Find the first directive on each line. Pure; lines are numbered from 1. */
export function parseDirectives(text: string): Directive[] {
  const out: Directive[] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i] ?? '';
    if (line.length > MAX_DIRECTIVE_LINE) line = line.slice(0, MAX_DIRECTIVE_LINE);
    if (!line.includes('exorcist-ignore')) continue;
    if (line.endsWith('\r')) line = line.slice(0, -1);
    const m = DIRECTIVE_RE.exec(line);
    if (m === null) continue;
    out.push({ ruleId: m[1] ?? '', line: i + 1, openerIndex: m.index, reason: stripCloser(m[2] ?? '') });
  }
  return out;
}

/** The reason made safe to print: secrets redacted, capped, control and hidden characters escaped. */
export function reasonForReport(reason: string): string {
  const capped = redactSecretText(reason).slice(0, MAX_REASON);
  return displayMessage(capped);
}

export type SuppressedFinding = { finding: Finding; ruleId: string; file: string; line: number; reason: string };
export type RejectCause = 'no-reason' | 'never-suppressible' | 'timeout';
export type RejectedDirective = { ruleId: string; file: string; line: number; cause: RejectCause };
export type InlineResult = {
  active: Finding[];
  suppressed: SuppressedFinding[];
  rejected: RejectedDirective[];
};

type FileDirectives = { byLine: Map<number, Directive>; usable: Set<Directive> };

function indexDirectives(text: string): FileDirectives {
  const byLine = new Map<number, Directive>();
  for (const d of parseDirectives(text)) byLine.set(d.line, d);
  return { byLine, usable: new Set() };
}

const validReason = (d: Directive): boolean => HAS_WORD_CHAR.test(d.reason);
const suppressible = (d: Directive): boolean => !NEVER_INLINE.includes(d.ruleId) && validReason(d);

/** The directive that covers this finding by position and rule id, or undefined. */
function coveringDirective(f: Finding, dirs: FileDirectives): Directive | undefined {
  const own = dirs.byLine.get(f.line);
  // Own line: only a finding that starts before the comment opener (col is 1-based).
  if (own !== undefined && own.ruleId === f.ruleId && f.col <= own.openerIndex) return own;
  const prev = dirs.byLine.get(f.line - 1);
  if (prev !== undefined && prev.ruleId === f.ruleId) return prev;
  return undefined;
}

/**
 * Split findings into active and suppressed by inline directives. Each file that has a
 * finding is read once through `readText` (null means unreadable: nothing is suppressed
 * there). Every input finding lands in exactly one of `active` and `suppressed`.
 */
export function applyInline(findings: readonly Finding[], readText: (file: string) => string | null): InlineResult {
  const perFile = new Map<string, FileDirectives | null>();
  const dirsFor = (file: string): FileDirectives | null => {
    if (perFile.has(file)) return perFile.get(file) ?? null;
    const text = readText(file);
    const d = text === null ? null : indexDirectives(text);
    perFile.set(file, d);
    return d;
  };

  const active: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  const timeoutHit = new Map<string, Set<Directive>>();

  for (const f of findings) {
    const dirs = dirsFor(f.file);
    const d = dirs === null ? undefined : coveringDirective(f, dirs);
    if (d === undefined || dirs === null) {
      active.push(f);
      continue;
    }
    if (isTimeoutFinding(f)) {
      const set = timeoutHit.get(f.file) ?? new Set<Directive>();
      set.add(d);
      timeoutHit.set(f.file, set);
      active.push(f);
      continue;
    }
    if (!suppressible(d)) {
      active.push(f);
      continue;
    }
    dirs.usable.add(d);
    suppressed.push({ finding: f, ruleId: f.ruleId, file: f.file, line: f.line, reason: reasonForReport(d.reason) });
  }

  const rejected: RejectedDirective[] = [];
  for (const [file, dirs] of perFile) {
    if (dirs === null) continue;
    for (const d of dirs.byLine.values()) {
      let cause: RejectCause | null = null;
      if (NEVER_INLINE.includes(d.ruleId)) cause = 'never-suppressible';
      else if (!validReason(d)) cause = 'no-reason';
      else if (timeoutHit.get(file)?.has(d) === true) cause = 'timeout';
      if (cause !== null) rejected.push({ ruleId: d.ruleId, file, line: d.line, cause });
    }
  }
  rejected.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
  return { active, suppressed, rejected };
}
