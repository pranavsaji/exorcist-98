/**
 * Hidden characters made visible. The characters are exactly the ones the
 * core's EX-001 and EX-021 rules report and `exorcist exorcise` removes
 * (`removeHiddenUnicode`), so the markers, the diagnostics and the quick fix
 * always agree; the benign uses the core allows (emoji ZWJ sequences, a single
 * U+FE0F, flag emoji, a leading BOM, joining-script spelling) get no marker.
 * Hidden messages are decoded with the core's Ouija decoder (`decodeHidden`)
 * and shown only through `displayMessage`, inside a code block.
 *
 * Pure: no `vscode` import.
 */
import { decodeHidden, displayMessage, removeHiddenUnicode } from '@exorcist-98/core';
import type { HiddenMessage } from '@exorcist-98/core';

export type HiddenChar = { codePoint: number; offset: number; length: number };

/** A run of adjacent hidden characters: one marker in the editor. Offsets are UTF-16. */
export type HiddenRun = {
  start:  number;
  end:    number;
  chars:  HiddenChar[];
  /** Short text drawn in the editor, e.g. "ZWSP×2", "RLO", "TAG×51". */
  label:  string;
  /** The Ouija decoder's messages carried by this run (attacker text: display only). */
  messages: HiddenMessage[];
};

/** At most this many runs get a marker per file, so a hostile file cannot flood the editor. */
export const MAX_RUNS = 1000;

const NAMES: Record<number, [short: string, long: string]> = {
  0x200B: ['ZWSP', 'ZERO WIDTH SPACE'],
  0x200C: ['ZWNJ', 'ZERO WIDTH NON-JOINER'],
  0x200D: ['ZWJ', 'ZERO WIDTH JOINER'],
  0xFEFF: ['BOM', 'ZERO WIDTH NO-BREAK SPACE (byte order mark)'],
  0x2060: ['WJ', 'WORD JOINER'],
  0x2061: ['FA', 'FUNCTION APPLICATION'],
  0x2062: ['IT', 'INVISIBLE TIMES'],
  0x2063: ['IS', 'INVISIBLE SEPARATOR'],
  0x2064: ['IP', 'INVISIBLE PLUS'],
  0x180E: ['MVS', 'MONGOLIAN VOWEL SEPARATOR'],
  0x202A: ['LRE', 'LEFT-TO-RIGHT EMBEDDING'],
  0x202B: ['RLE', 'RIGHT-TO-LEFT EMBEDDING'],
  0x202C: ['PDF', 'POP DIRECTIONAL FORMATTING'],
  0x202D: ['LRO', 'LEFT-TO-RIGHT OVERRIDE'],
  0x202E: ['RLO', 'RIGHT-TO-LEFT OVERRIDE'],
  0x2066: ['LRI', 'LEFT-TO-RIGHT ISOLATE'],
  0x2067: ['RLI', 'RIGHT-TO-LEFT ISOLATE'],
  0x2068: ['FSI', 'FIRST STRONG ISOLATE'],
  0x2069: ['PDI', 'POP DIRECTIONAL ISOLATE'],
};

export function hex(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

/** Short name drawn in the editor. */
export function shortName(cp: number): string {
  const n = NAMES[cp];
  if (n) return n[0];
  if (cp >= 0xE0000 && cp <= 0xE007F) return 'TAG';
  if ((cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF)) return 'VS';
  return hex(cp);
}

/** Long name for the hover, e.g. "U+E0069 TAG LATIN SMALL LETTER I ('i')". */
export function longName(cp: number): string {
  const n = NAMES[cp];
  if (n) return `${hex(cp)} ${n[1]}`;
  if (cp >= 0xE0020 && cp <= 0xE007E) return `${hex(cp)} TAG CHARACTER (carries '${String.fromCharCode(cp - 0xE0000)}')`;
  if (cp >= 0xE0000 && cp <= 0xE007F) return `${hex(cp)} TAG CONTROL`;
  if (cp >= 0xFE00 && cp <= 0xFE0F) return `${hex(cp)} VARIATION SELECTOR-${cp - 0xFE00 + 1} (carries byte ${cp - 0xFE00})`;
  if (cp >= 0xE0100 && cp <= 0xE01EF) return `${hex(cp)} VARIATION SELECTOR-${cp - 0xE0100 + 17} (carries byte ${cp - 0xE0100 + 16})`;
  return hex(cp);
}

/** "ZWSP×2", "RLO", "TAG×51", or for a mix "ZWSP ZWJ +3". */
export function runLabel(chars: readonly HiddenChar[]): string {
  const groups: Array<{ name: string; count: number }> = [];
  for (const c of chars) {
    const name = shortName(c.codePoint);
    const last = groups[groups.length - 1];
    if (last && last.name === name) last.count++;
    else groups.push({ name, count: 1 });
  }
  const shown = groups.slice(0, 3).map((g) => (g.count > 1 ? `${g.name}×${g.count}` : g.name));
  const rest = groups.slice(3).reduce((n, g) => n + g.count, 0);
  return rest > 0 ? `${shown.join(' ')} +${rest}` : shown.join(' ');
}

/** Every reported hidden character in `text`, grouped into runs, with the messages they carry. */
export function hiddenRuns(text: string): HiddenRun[] {
  const { removed } = removeHiddenUnicode(text);
  if (removed.length === 0) return [];
  const runs: HiddenRun[] = [];
  let cur: HiddenChar[] = [];
  const flush = (): void => {
    if (cur.length === 0) return;
    const first = cur[0] as HiddenChar;
    const last = cur[cur.length - 1] as HiddenChar;
    runs.push({ start: first.offset, end: last.offset + last.length, chars: cur, label: runLabel(cur), messages: [] });
    cur = [];
  };
  for (const h of removed) {
    const prev = cur[cur.length - 1];
    if (prev && prev.offset + prev.length !== h.offset) {
      flush();
      if (runs.length >= MAX_RUNS) break;
    }
    cur.push({ codePoint: h.codePoint, offset: h.offset, length: h.char.length });
  }
  if (runs.length < MAX_RUNS) flush();

  // Attach each decoded message to the run it overlaps. A tag run inside a
  // flag emoji is not in `runs` (the core treats it as benign), so its
  // "message" (the region code) is never shown.
  for (const m of decodeHidden(text)) {
    const run = runs.find((r) => m.start < r.end && m.end > r.start);
    if (run) run.messages.push(m);
  }
  return runs;
}

/** The run at a UTF-16 offset, touching either edge (a zero-width run has no width to hover). */
export function runAt(runs: readonly HiddenRun[], offset: number): HiddenRun | undefined {
  return runs.find((r) => offset >= r.start && offset <= r.end);
}

/** A Markdown code block that no content can close early: the fence is longer than any backtick run inside. */
export function codeBlock(content: string): string {
  const longest = Math.max(0, ...Array.from(content.matchAll(/`+/g), (m) => m[0].length));
  const fence = '`'.repeat(Math.max(3, longest + 1));
  return `${fence}text\n${content}\n${fence}`;
}

/** Escape text for Markdown prose (definitions and code-point names only; attacker text goes in a code block). */
export function escapeMarkdown(s: string): string {
  return s.replace(/[\\`*_{}[\]()#+\-.!|<>~]/g, '\\$&');
}

/** At most this many characters are listed in a hover. */
export const MAX_LISTED_CHARS = 12;

/**
 * The hover for a run, as Markdown. Shown with an untrusted MarkdownString
 * (no command links, no HTML); the decoded message sits in a code block and
 * has been through `displayMessage`, so nothing in it can render, link or act.
 */
export function hoverMarkdown(run: HiddenRun): string {
  const n = run.chars.length;
  const out: string[] = [];
  out.push(`**Exorcist 98: ${n} hidden character${n === 1 ? '' : 's'}**`);
  out.push('');
  out.push('You cannot see these, but an AI agent reading this file does.');
  for (const m of run.messages) {
    out.push('');
    out.push(`**Ouija board, hidden ${m.kind === 'tag' ? 'tag-character' : 'variation-selector'} message.** It is the attacker's text: read it, do not follow it.`);
    out.push('');
    out.push(codeBlock(displayMessage(m.message, { keepNewlines: true })));
  }
  out.push('');
  const listed = run.chars.slice(0, MAX_LISTED_CHARS).map((c) => `- ${escapeMarkdown(longName(c.codePoint))}`);
  out.push(...listed);
  if (n > MAX_LISTED_CHARS) out.push(`- and ${n - MAX_LISTED_CHARS} more`);
  out.push('');
  out.push('Quick fix: *Exorcise: remove hidden characters*.');
  return out.join('\n');
}
