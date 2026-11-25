/**
 * Tool descriptions in MCP server source code (m9-adoption, requirements 4.1 to 4.3 and 4.6).
 *
 * A small hand-written scanner finds registration sites with fixed-prefix searches and
 * reads string literals with a bounded reader. Nothing is evaluated, no regex has a nested
 * quantifier, and every step is bounded (MAX_SITES sites per file, MAX_AHEAD characters per
 * site), so the work is linear in the size of the file. Anything that cannot be read is
 * skipped; the functions never throw. Pure: no file access.
 *
 * Not covered (see L-051): descriptions built at run time (concatenation, template
 * substitution, variables), other languages, and a file with more than MAX_SITES sites
 * (the later ones are not looked at).
 */
import { scanText } from './scanner/scan-text.js';
import type { RepoFile, SignatureFinding } from './types.js';
import type { VirusDefinition } from './definitions/schema.js';

export type SourceLang = 'ts' | 'py' | 'go';

export type ToolString = {
  /** The string value, with escapes resolved. */
  text: string;
  /** Offset in the file (UTF-16) of the first character of the string content. */
  offset: number;
  /** Offset in the file just after the last character of the string content. */
  end: number;
};

/** Registration sites looked at per file. */
export const MAX_SITES = 100;
/** Characters read ahead of a site. */
export const MAX_AHEAD = 20_000;

const TS_EXT = ['.ts', '.tsx', '.js', '.mjs', '.cjs', '.mts'];

/** The language of a source file from its extension, or null. */
export function languageOf(relPath: string): SourceLang | null {
  const lower = String(relPath).toLowerCase();
  if (TS_EXT.some((e) => lower.endsWith(e))) return 'ts';
  if (lower.endsWith('.py')) return 'py';
  if (lower.endsWith('.go')) return 'go';
  return null;
}

// ── String literals ───────────────────────────────────────────────────────────

type Lit = {
  value: string;
  /** For each UTF-16 unit of `value`, the file offset it came from; one extra entry for the end. */
  map: number[];
  start: number;
  contentEnd: number;
  next: number;
};

const isIdent = (c: string | undefined): boolean => c !== undefined && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c === '_' || c === '$');
const isHex = (s: string): boolean => s.length > 0 && [...s].every((c) => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
const isQuote = (c: string | undefined): boolean => c === '"' || c === "'" || c === '`';

function fromCode(code: number): string | null {
  if (!Number.isInteger(code) || code < 0 || code > 0x10ffff) return null;
  return String.fromCodePoint(code);
}

/** Resolve one escape that starts at `i` (a backslash). Returns the text and how many source characters it used. */
function readEscape(text: string, i: number, lang: SourceLang, limit: number): { out: string; len: number } | null {
  const n = text[i + 1];
  if (n === undefined || i + 1 >= limit) return null;
  if (n === '\n') return { out: '', len: 2 };
  if (n === '\r') return { out: '', len: text[i + 2] === '\n' ? 3 : 2 };
  const simple: Record<string, string> = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', v: '\v', a: '\x07' };
  if (n === 'u' && text[i + 2] === '{' && lang === 'ts') {
    const close = text.indexOf('}', i + 3);
    const hex = close === -1 || close - i > 12 ? '' : text.slice(i + 3, close);
    const ch = isHex(hex) ? fromCode(parseInt(hex, 16)) : null;
    return ch === null ? null : { out: ch, len: close - i + 1 };
  }
  const widths: Record<string, number> = { x: 2, u: 4 };
  const w = n === 'U' && lang !== 'ts' ? 8 : widths[n];
  if (w !== undefined) {
    const hex = text.slice(i + 2, i + 2 + w);
    const ch = hex.length === w && isHex(hex) ? fromCode(parseInt(hex, 16)) : null;
    return ch === null ? { out: lang === 'py' ? `\\${n}` : n, len: 2 } : { out: ch, len: 2 + w };
  }
  if (lang === 'go' && n >= '0' && n <= '7') {
    const oct = text.slice(i + 1, i + 4);
    if (oct.length === 3 && [...oct].every((c) => c >= '0' && c <= '7')) return { out: String.fromCharCode(parseInt(oct, 8)), len: 4 };
  }
  const s = simple[n];
  if (s !== undefined) return { out: s, len: 2 };
  if (n === '0' && lang !== 'go') return { out: '\0', len: 2 };
  // Python keeps the backslash of an unknown escape; the others drop it.
  return { out: lang === 'py' && n !== '\\' && n !== '"' && n !== "'" ? `\\${n}` : n, len: 2 };
}

/**
 * Read the string literal whose opening quote is at `q`. Null when it is unterminated,
 * has a newline inside a one-line string, or (TypeScript) contains `${` substitution.
 */
function readLiteral(text: string, q: number, lang: SourceLang, limit: number, raw = false): Lit | null {
  const quote = text[q];
  if (!isQuote(quote) || quote === undefined) return null;
  if (quote === '`' && lang === 'py') return null;
  if (quote === "'" && lang === 'go') return null;
  const triple = lang === 'py' && text[q + 1] === quote && text[q + 2] === quote;
  const open = triple ? 3 : 1;
  const goRaw = lang === 'go' && quote === '`';
  const start = q + open;
  let value = '';
  const map: number[] = [];
  const push = (s: string, at: number): void => {
    for (let k = 0; k < s.length; k++) { value += s[k]; map.push(at); }
  };
  let i = start;
  while (i < limit) {
    const c = text[i];
    if (c === undefined) return null;
    if (triple ? (c === quote && text[i + 1] === quote && text[i + 2] === quote) : c === quote) {
      map.push(i);
      return { value, map, start, contentEnd: i, next: i + open };
    }
    if (c === '\n' && !triple && !goRaw && quote !== '`') return null;
    if (lang === 'ts' && quote === '`' && c === '$' && text[i + 1] === '{') return null;
    if (c === '\\' && !goRaw && !raw) {
      const e = readEscape(text, i, lang, limit);
      if (e === null) return null;
      push(e.out, i);
      i += e.len;
      continue;
    }
    push(c, i);
    i++;
  }
  return null;
}

/** Index just after a string whose opening quote is at `q`, read leniently (no value). -1 when unterminated. */
function skipQuoted(text: string, q: number, lang: SourceLang, limit: number): number {
  const quote = text[q];
  if (quote === undefined) return -1;
  const triple = lang === 'py' && text[q + 1] === quote && text[q + 2] === quote;
  let i = q + (triple ? 3 : 1);
  while (i < limit) {
    const c = text[i];
    if (c === '\\' && !(lang === 'go' && quote === '`')) { i += 2; continue; }
    if (triple ? (c === quote && text[i + 1] === quote && text[i + 2] === quote) : c === quote) return i + (triple ? 3 : 1);
    if (c === '\n' && !triple && quote !== '`') return -1;
    i++;
  }
  return -1;
}

/** A Python string literal with an optional prefix (`r`, `u`, `b`, `f`, in any case, up to two letters) starting at `p`. */
function readPyString(text: string, p: number, limit: number): Lit | null {
  let i = p;
  let raw = false;
  while (i < p + 2 && 'rRuUbBfF'.includes(text[i] ?? '#')) { if (text[i] === 'r' || text[i] === 'R') raw = true; i++; }
  return readLiteral(text, i, 'py', limit, raw);
}

/** Skip whitespace and comments. */
function skipTrivia(text: string, p: number, lang: SourceLang, limit: number): number {
  let i = p;
  while (i < limit) {
    const c = text[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue; }
    if (lang === 'py' && c === '#') { i = lineEnd(text, i); continue; }
    if (lang !== 'py' && c === '/' && text[i + 1] === '/') { i = lineEnd(text, i); continue; }
    if (lang !== 'py' && c === '/' && text[i + 1] === '*') {
      const close = text.indexOf('*/', i + 2);
      if (close === -1 || close >= limit) return limit;
      i = close + 2;
      continue;
    }
    break;
  }
  return i;
}

function lineEnd(text: string, i: number): number {
  const nl = text.indexOf('\n', i);
  return nl === -1 ? text.length : nl + 1;
}

/** From `p`, the index of the `,` or closing bracket that ends the current argument (depth 0), or -1. */
function skipArgument(text: string, p: number, lang: SourceLang, limit: number): number {
  let depth = 0;
  let i = p;
  while (i < limit) {
    const c = text[i];
    if (isQuote(c)) {
      const j = skipQuoted(text, i, lang, limit);
      if (j < 0) return -1;
      i = j;
      continue;
    }
    if ((lang === 'py' && c === '#') || (lang !== 'py' && c === '/' && (text[i + 1] === '/' || text[i + 1] === '*'))) {
      const j = skipTrivia(text, i, lang, limit);
      i = j > i ? j : i + 1;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) return i;
      depth--;
    } else if (c === ',' && depth === 0) return i;
    i++;
  }
  return -1;
}

/**
 * Inside the bracket at `open`, the string value of the key `description` that sits directly in
 * it (depth 1). `sep` is ':' (object literal) or '=' (Python keyword argument). Also returns the
 * index just after the closing bracket.
 */
function findKeyString(text: string, open: number, lang: SourceLang, limit: number, sep: ':' | '='): { lit: Lit | null; after: number } {
  let depth = 0;
  let i = open;
  let lit: Lit | null = null;
  const valueAt = (p: number): Lit | null => {
    const v = skipTrivia(text, p, lang, limit);
    return lang === 'py' ? readPyString(text, v, limit) : readLiteral(text, v, lang, limit);
  };
  const sepAt = (p: number): number => {
    const j = skipTrivia(text, p, lang, limit);
    if (text[j] !== sep || (sep === '=' && text[j + 1] === '=')) return -1;
    return j + 1;
  };
  while (i < limit) {
    const c = text[i];
    if (c === undefined) break;
    if (isQuote(c)) {
      const l = lang === 'ts' && depth === 1 ? readLiteral(text, i, lang, limit) : null;
      if (l && l.value === 'description' && lit === null) {
        const s = sepAt(l.next);
        if (s >= 0) lit = valueAt(s);
      }
      const j = l ? l.next : skipQuoted(text, i, lang, limit);
      if (j < 0) return { lit, after: -1 };
      i = j;
      continue;
    }
    if ((lang === 'py' && c === '#') || (lang !== 'py' && c === '/' && (text[i + 1] === '/' || text[i + 1] === '*'))) {
      const j = skipTrivia(text, i, lang, limit);
      i = j > i ? j : i + 1;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth <= 0) return { lit, after: i + 1 };
    } else if (depth === 1 && isIdent(c) && !isIdent(text[i - 1]) && text[i - 1] !== '.') {
      let j = i;
      while (j < limit && isIdent(text[j])) j++;
      if (j - i === 'description'.length && text.startsWith('description', i) && lit === null) {
        const s = sepAt(j);
        if (s >= 0) lit = valueAt(s);
      }
      i = j;
      continue;
    }
    i++;
  }
  return { lit, after: -1 };
}

// ── Extraction per language ───────────────────────────────────────────────────

type Found = ToolString & { map: number[] };

const toFound = (l: Lit): Found => ({ text: l.value, offset: l.start, end: l.contentEnd, map: l.map });

function indexesOf(text: string, needle: string, budget: { left: number }): number[] {
  const out: number[] = [];
  let from = 0;
  while (budget.left > 0) {
    const i = text.indexOf(needle, from);
    if (i === -1) break;
    out.push(i);
    budget.left--;
    from = i + needle.length;
  }
  return out;
}

const lim = (text: string, from: number): number => Math.min(text.length, from + MAX_AHEAD);

function extractTs(text: string, budget: { left: number }, out: Found[]): void {
  for (const at of indexesOf(text, '.tool(', budget)) {
    const limit = lim(text, at);
    const first = skipTrivia(text, at + 6, 'ts', limit);
    const e = skipArgument(text, first, 'ts', limit);
    if (e < 0 || text[e] !== ',') continue;
    const p = skipTrivia(text, e + 1, 'ts', limit);
    const l = isQuote(text[p]) ? readLiteral(text, p, 'ts', limit) : null;
    if (l) out.push(toFound(l));
  }
  for (const needle of ['registerTool(', 'registerTool<']) {
    for (const at of indexesOf(text, needle, budget)) {
      const limit = lim(text, at);
      let paren = at + needle.length - 1;
      if (needle.endsWith('<')) {
        paren = text.indexOf('(', at + needle.length);
        if (paren === -1 || paren > at + 300) continue;
      }
      const first = skipTrivia(text, paren + 1, 'ts', limit);
      const e = skipArgument(text, first, 'ts', limit);
      if (e < 0 || text[e] !== ',') continue;
      const p = skipTrivia(text, e + 1, 'ts', limit);
      if (text[p] !== '{') continue;
      const { lit } = findKeyString(text, p, 'ts', limit, ':');
      if (lit) out.push(toFound(lit));
    }
  }
}

/** The docstring of the function that follows a decorator ending at `from`. */
function docstringAfter(text: string, from: number, limit: number): Lit | null {
  let i = from;
  let def = -1;
  while (i < limit) {
    const nl = text.indexOf('\n', i);
    if (nl === -1 || nl + 1 >= limit) return null;
    let p = nl + 1;
    while (text[p] === ' ' || text[p] === '\t') p++;
    if (text.startsWith('def ', p) || text.startsWith('async def ', p)) { def = p; break; }
    if (text.startsWith('class ', p)) return null;
    i = nl + 1;
  }
  if (def < 0) return null;
  // End of the signature: the colon at bracket depth 0.
  let depth = 0;
  let j = def;
  let colon = -1;
  while (j < limit) {
    const c = text[j];
    if (isQuote(c)) { const k = skipQuoted(text, j, 'py', limit); if (k < 0) return null; j = k; continue; }
    if (c === '#') { j = lineEnd(text, j); continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ':' && depth === 0) { colon = j; break; }
    j++;
  }
  if (colon < 0) return null;
  const p = skipTrivia(text, colon + 1, 'py', limit);
  return readPyString(text, p, limit);
}

function extractPy(text: string, budget: { left: number }, out: Found[]): void {
  for (const name of ['@mcp.tool', '@server.tool', '@app.tool']) {
    for (const at of indexesOf(text, name, budget)) {
      // The decorator must start its line.
      let b = at - 1;
      while (b >= 0 && (text[b] === ' ' || text[b] === '\t')) b--;
      if (b >= 0 && text[b] !== '\n') continue;
      const nameEnd = at + name.length;
      if (isIdent(text[nameEnd]) || text[nameEnd] === '.') continue;
      const limit = lim(text, at);
      let after = nameEnd;
      let lit: Lit | null = null;
      if (text[nameEnd] === '(') {
        const r = findKeyString(text, nameEnd, 'py', limit, '=');
        lit = r.lit;
        if (r.after > 0) after = r.after;
      }
      lit ??= docstringAfter(text, after, limit);
      if (lit) out.push(toFound(lit));
    }
  }
}

function extractGo(text: string, budget: { left: number }, out: Found[]): void {
  for (const at of indexesOf(text, 'WithDescription(', budget)) {
    if (isIdent(text[at - 1])) continue;
    const limit = lim(text, at);
    const p = skipTrivia(text, at + 'WithDescription('.length, 'go', limit);
    const l = text[p] === '"' || text[p] === '`' ? readLiteral(text, p, 'go', limit) : null;
    if (l) out.push(toFound(l));
  }
}

function extract(text: string, lang: SourceLang): Found[] {
  const out: Found[] = [];
  const budget = { left: MAX_SITES };
  if (lang === 'ts') extractTs(text, budget, out);
  else if (lang === 'py') extractPy(text, budget, out);
  else extractGo(text, budget, out);
  const seen = new Set<number>();
  return out.filter((f) => !seen.has(f.offset) && seen.add(f.offset)).sort((a, b) => a.offset - b.offset);
}

/**
 * The description strings of tool registrations in `text`, in file order.
 * Never throws; unreadable input gives an empty list.
 */
export function extractToolDescriptions(text: string, lang: SourceLang): ToolString[] {
  try {
    if (typeof text !== 'string' || text.length === 0) return [];
    return extract(text, lang).map(({ text: t, offset, end }) => ({ text: t, offset, end }));
  } catch {
    return [];
  }
}

// ── Scanning ──────────────────────────────────────────────────────────────────

function positionOf(text: string, offset: number): { line: number; col: number } {
  let line = 1;
  let lastNl = -1;
  let i = text.indexOf('\n');
  while (i !== -1 && i < offset) { line++; lastNl = i; i = text.indexOf('\n', i + 1); }
  return { line, col: offset - lastNl };
}

/** Index in `s` of 1-based line and column (as the signature engine counts them). */
function indexOfLineCol(s: string, line: number, col: number): number {
  let start = 0;
  for (let l = 1; l < line; l++) {
    const nl = s.indexOf('\n', start);
    if (nl === -1) return 0;
    start = nl + 1;
  }
  return start + col - 1;
}

/** A hit that only says "do X before using/calling this tool": an ordering hint, common in honest descriptions. */
const ORDER_HINT = /^(?:before using this tool|(?:prior to|before) (?:invoking|calling|running|using) (?:this|any|the))\b/i;
/** Concealment wording or a sensitive target. Plain "read" is deliberately not a signal. */
const SENSITIVE_TARGET = /~\/\.ssh|id_rsa|\.env\b|\bcredentials?\b|\bprivate key\b|\bapi[ _-]?key\b|\btoken\b|\bpassword\b/i;
const CONCEALMENT =
  /\b(?:do not|don't|dont) (?:tell|inform|mention|notify)\b|\bwithout (?:telling|informing|notifying|asking)\b|\b(?:secret|hidden|silently)\b/i;
const SEND_VERB = /\b(?:send|upload|forward|exfiltrate|post|include|attach)(?:s|es|ed|ing)?\b/i;
const URL_OR_HOST = /https?:\/\/|\bwww\.|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|dev|xyz|invalid|test|example)\b/i;
/** Longest stretch searched on each side of a hint for the end of its sentence, to keep the work linear. */
const SENTENCE_WINDOW = 500;
/** The sentence (split on . ! ? newline) around [from, to) in `whole`, extended to cover the whole hit. */
function sentenceAround(whole: string, from: number, to: number): string {
  // A '.', '!' or '?' ends a sentence only before whitespace or the end, so "~/.ssh" and "a.example.invalid" stay whole.
  const isEnd = (i: number): boolean => {
    const c = whole.charAt(i);
    if (c === '\n') return true;
    return (c === '.' || c === '!' || c === '?') && (i + 1 >= whole.length || /\s/.test(whole.charAt(i + 1)));
  };
  let start = Math.min(from, whole.length);
  const lo = Math.max(0, start - SENTENCE_WINDOW);
  while (start > lo && !isEnd(start - 1)) start--;
  let end = Math.max(Math.min(to, whole.length), start);
  const hi = Math.min(whole.length, end + SENTENCE_WINDOW);
  while (end < hi && !isEnd(end)) end++;
  return whole.slice(start, end);
}
/** True when the hint's own sentence conceals something, names a sensitive target, or sends something somewhere. */
function isSuspiciousSentence(sentence: string): boolean {
  if (CONCEALMENT.test(sentence) || SENSITIVE_TARGET.test(sentence)) return true;
  return SEND_VERB.test(sentence) && URL_OR_HOST.test(sentence);
}
/** True when `span` is only an ordering hint and the sentence it sits in has no sensitive signal. */
function isQuietHint(span: string, whole: string, at: number): boolean {
  return ORDER_HINT.test(span.trim()) && !isSuspiciousSentence(sentenceAround(whole, at, at + span.length));
}
/**
 * Run only EX-005 (tool description poisoning) on the description strings of a source file.
 * Each hit is mapped back to the line and column in the source file. The mapping is exact,
 * including for strings with escapes: every character of the resolved string remembers the
 * file offset it was read from (an escape maps to its backslash). The span is the matched text.
 * A hit that is only an ordering hint ("use X before calling this tool") is dropped unless the same
 * description also conceals something, names a sensitive target or tells the agent to read or send
 * something (requirement 4.4). The definition itself is unchanged, so JSON configs behave as before.
 * Returns [] when EX-005 is not among `defs` or the file is not TypeScript, JavaScript, Python or Go.
 */
export function scanSourceTools(file: RepoFile, text: string, defs: VirusDefinition[]): SignatureFinding[] {
  try {
    const def = defs.find((d) => d.id === 'EX-005');
    const lang = languageOf(file.rel);
    if (!def || lang === null || typeof text !== 'string') return [];
    const out: SignatureFinding[] = [];
    for (const s of extract(text, lang)) {
      for (const hit of scanText(s.text, 'mcp-config', [def], file.rel)) {
        const idx = Math.min(Math.max(indexOfLineCol(s.text, hit.line, hit.col), 0), s.text.length);
        if (isQuietHint(hit.span, s.text, idx)) continue;
        const at = s.map[idx] ?? s.offset;
        out.push({ ...hit, file: file.rel, ...positionOf(text, at) });
      }
    }
    return out;
  } catch {
    return [];
  }
}
