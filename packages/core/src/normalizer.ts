import type { FileRole } from './types.js';

// ── Unicode hidden-character detection ───────────────────────────────────────

export type UnicodeClass = 'zero-width' | 'bidi-override' | 'tag-block';

export type UnicodeHit = {
  char:       string;
  codePoint:  number;
  offset:     number;
  class:      UnicodeClass;
};

// Code-point ranges per class
const UNICODE_RANGES: Array<{ class: UnicodeClass; points: number[] }> = [
  {
    class: 'zero-width',
    // U+2060-2064 (word joiner, invisible operators) and U+180E were missed before (L-006).
    points: [0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E],
  },
  {
    class: 'bidi-override',
    points: [
      0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
      0x2066, 0x2067, 0x2068, 0x2069,
    ],
  },
  // Tag block: U+E0000–U+E007F (supplementary plane — use full iteration)
  {
    class: 'tag-block',
    points: Array.from({ length: 0x80 }, (_, i) => 0xE0000 + i),
  },
];

// Build a map from code point → class for fast lookup
const CP_TO_CLASS = new Map<number, UnicodeClass>();
for (const range of UNICODE_RANGES) {
  for (const cp of range.points) {
    CP_TO_CLASS.set(cp, range.class);
  }
}

const PICTO = /\p{Extended_Pictographic}/u;
/** The characters before and after `offset`, by code point. */
function neighbours(text: string, offset: number, len: number): [string, string] {
  const before = Array.from(text.slice(Math.max(0, offset - 4), offset)).pop() ?? '';
  const after = Array.from(text.slice(offset + len, offset + len + 4))[0] ?? '';
  return [before, after];
}
/**
 * Two legitimate uses are not hidden text: a zero-width joiner between two
 * emoji (family and profession emoji are built that way) and a byte-order
 * mark at the very start of a file.
 */
function isBenign(text: string, cp: number, offset: number, len: number): boolean {
  if (cp === 0xFEFF && offset === 0) return true;
  if (cp === 0x200D) {
    const [b, a] = neighbours(text, offset, len);
    const emojiBefore = PICTO.test(b) || b === '\uFE0F' || /[\u{1F3FB}-\u{1F3FF}]/u.test(b);
    return emojiBefore && PICTO.test(a);
  }
  return false;
}

function findHiddenUnicode(text: string): UnicodeHit[] {
  const hits: UnicodeHit[] = [];
  let offset = 0;
  for (const char of text) {
    const cp = char.codePointAt(0);
    if (cp !== undefined) {
      const cls = CP_TO_CLASS.get(cp);
      if (cls !== undefined && !isBenign(text, cp, offset, char.length)) {
        hits.push({ char, codePoint: cp, offset, class: cls });
      }
    }
    // Advance by the actual UTF-16 length of the char
    offset += char.length;
  }
  return hits;
}

// ── HTML entity decoding ──────────────────────────────────────────────────────

const NAMED_ENTITIES: Record<string, string> = {
  amp:  '&',
  lt:   '<',
  gt:   '>',
  quot: '"',
  apos: "'",
  nbsp: '\u00A0',
};

function decodeEntities(text: string): string {
  return text.replace(/&([a-zA-Z]+|#\d+|#x[\da-fA-F]+);/g, (match, body: string) => {
    if (body.startsWith('#x') || body.startsWith('#X')) {
      return String.fromCodePoint(parseInt(body.slice(2), 16));
    }
    if (body.startsWith('#')) {
      return String.fromCodePoint(parseInt(body.slice(1), 10));
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? match;
  });
}

// ── Comment extraction ────────────────────────────────────────────────────────

const HTML_COMMENT_RE  = /<!--([\s\S]*?)-->/g;
const BLOCK_COMMENT_RE = /\/\*([\s\S]*?)\*\//g;

function extractComments(text: string): string[] {
  const results: string[] = [];
  for (const re of [HTML_COMMENT_RE, BLOCK_COMMENT_RE]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const body = m[1];
      if (body !== undefined && body.trim().length > 0) {
        results.push(body.trim());
      }
    }
  }
  return results;
}

// ── Base64 candidate extraction ───────────────────────────────────────────────

const BASE64_RE = /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{32,}(?![A-Za-z0-9+/=])/g;

const INNOCUOUS_PREFIXES = [
  'data:image/',
  'sha256:',
  'sha512:',
  'sha1:',
  'md5:',
];

function extractBase64Candidates(text: string): string[] {
  const candidates: string[] = [];
  BASE64_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = BASE64_RE.exec(text)) !== null) {
    const blob = m[0];
    // Check for innocuous prefix before this blob
    const start = m.index;
    const prefix = text.slice(Math.max(0, start - 20), start);
    if (INNOCUOUS_PREFIXES.some((p) => prefix.endsWith(p))) continue;
    candidates.push(blob);
  }
  return candidates;
}

// ── Public API ────────────────────────────────────────────────────────────────

export type NormalizedText = {
  original:          string;
  plain:             string;
  /**
   * `plain` with hidden characters removed, and for each of its characters the
   * index in `plain` it came from. Only set when the file has hidden characters,
   * so a phrase split by a zero-width space still matches (L-005).
   */
  visible?:          { text: string; map: number[] };
  hiddenUnicode:     UnicodeHit[];
  comments:          string[];
  base64Candidates:  string[];
};

export function normalize(text: string, _role: FileRole): NormalizedText {
  const plain           = decodeEntities(text);
  const hiddenUnicode   = findHiddenUnicode(text);
  const comments        = extractComments(text);
  const base64Candidates = extractBase64Candidates(text);
  const out: NormalizedText = { original: text, plain, hiddenUnicode, comments, base64Candidates };
  if (hiddenUnicode.length > 0) {
    let vis = '';
    const map: number[] = [];
    let i = 0;
    for (const ch of plain) {
      const cp = ch.codePointAt(0) ?? 0;
      if (!CP_TO_CLASS.has(cp)) {
        vis += ch;
        for (let k = 0; k < ch.length; k++) map.push(i + k);
      }
      i += ch.length;
    }
    if (vis.length !== plain.length) out.visible = { text: vis, map };
  }
  return out;
}
