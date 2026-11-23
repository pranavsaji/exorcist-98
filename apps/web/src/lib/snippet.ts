import type { Snippet, SnippetLine } from './protocol';

// Same classes the engine detects: zero-width, bidi override, tag block, and
// runs of four or more variation selectors (EX-021). A single U+FE0F after an
// emoji is ordinary text and stays as it is.
const HIDDEN = /[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}]|[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]{4,}/gu;
const HIDDEN_ONE = /^[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}\uFE00-\uFE0F\u{E0100}-\u{E01EF}]$/u;

const MAX_SIDE = 120;    // characters kept before and after a match on one line
const MAX_MATCH = 240;   // characters kept inside a highlight
const MAX_LINES = 14;

/** Replace each hidden code point with a visible marker such as [U+200B]. */
export function revealHidden(text: string): string {
  return text.replace(HIDDEN, (run) =>
    Array.from(run, (c) => `[U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}]`).join(''),
  );
}

type Range = { start: number; end: number };

function resolveRange(original: string, start: number, span: string, lineStart: number, lineEnd: number): Range | null {
  if (span.length === 0) return null;
  if (original.startsWith(span, start)) return { start, end: start + span.length };

  // Span was truncated by the engine (ends with an ellipsis).
  if (span.endsWith('…') && span.length > 1 && original.startsWith(span.slice(0, -1), start)) {
    return { start, end: start + span.length - 1 };
  }

  // unicode_class findings carry one or more escapes such as \u200B or
  // \u{E0041}\u{E0042}, one per adjacent hidden character (maybe truncated).
  if (/^(?:\\u(?:\{[0-9A-F]{4,6}\}|[0-9A-F]{4}))+…?$/.test(span)) {
    let end = start;
    for (;;) {
      const cp = original.codePointAt(end);
      if (cp === undefined) break;
      const ch = String.fromCodePoint(cp);
      if (!HIDDEN_ONE.test(ch)) break;
      end += ch.length;
    }
    return end > start ? { start, end } : null;
  }

  // Fall back to the first occurrence on the same line. JSON findings carry the
  // decoded string, while the file holds the escaped form (\" and \\), so try
  // that too. A truncated span (ending in an ellipsis) is matched without it.
  const core = span.endsWith('…') ? span.slice(0, -1) : span;
  const lineText = original.slice(lineStart, lineEnd);
  for (const cand of new Set([span, core, JSON.stringify(core).slice(1, -1)])) {
    if (cand.length === 0) continue;
    const idx = lineText.indexOf(cand);
    if (idx !== -1) return { start: lineStart + idx, end: lineStart + idx + cand.length };
  }
  return null;
}

function trimBefore(s: string): string {
  return s.length > MAX_SIDE ? `…${s.slice(-MAX_SIDE)}` : s;
}
function trimAfter(s: string): string {
  return s.length > MAX_SIDE ? `${s.slice(0, MAX_SIDE)}…` : s;
}
function trimMatch(s: string): string {
  return s.length > MAX_MATCH ? `${s.slice(0, MAX_MATCH)}…` : s;
}

/**
 * Build a small code snippet around a finding. `before + match + after` of the
 * finding line equals revealHidden(line) when the line is short enough not to
 * be trimmed. The highlight is the engine's exact span.
 */
export function buildSnippet(
  original: string,
  line: number,
  col: number,
  span: string,
  context = 2,
): Snippet {
  const lines = original.split('\n');
  if (line < 1 || line > lines.length) return { lines: [] };

  const starts: number[] = [];
  let acc = 0;
  for (const l of lines) {
    starts.push(acc);
    acc += l.length + 1;
  }

  const lineText = lines[line - 1] ?? '';
  const lineStart = starts[line - 1] ?? 0;
  const start = lineStart + Math.max(0, col - 1);
  const range = resolveRange(original, start, span, lineStart, lineStart + lineText.length);

  let endLine = line;
  if (range) {
    for (let i = line; i < lines.length; i++) {
      if ((starts[i] ?? Infinity) < range.end) endLine = i + 1;
      else break;
    }
  }

  const first = Math.max(1, line - context);
  const last = Math.min(lines.length, endLine + context, first + MAX_LINES - 1);

  const out: SnippetLine[] = [];
  for (let n = first; n <= last; n++) {
    const text = lines[n - 1] ?? '';
    const ls = starts[n - 1] ?? 0;
    const le = ls + text.length;
    if (range && text.length > 0 && range.start < le && range.end > ls) {
      const a = Math.max(range.start, ls) - ls;
      const b = Math.min(range.end, le) - ls;
      out.push({
        n,
        before: revealHidden(trimBefore(text.slice(0, a))),
        match:  revealHidden(trimMatch(text.slice(a, b))),
        after:  revealHidden(trimAfter(text.slice(b))),
      });
    } else {
      out.push({ n, before: revealHidden(trimAfter(text)), match: '', after: '' });
    }
  }
  return { lines: out };
}
