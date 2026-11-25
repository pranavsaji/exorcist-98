import { findHiddenUnicode, isHiddenCodePoint } from './normalizer.js';

/**
 * EX-029: a file or folder name (one path segment) that reads as an instruction
 * to an AI, or that carries hidden or control characters. Pure: no I/O.
 */
export type PathNameHit = { kind: 'instruction' | 'hidden-chars'; span: string };

/** The most characters of a name quoted in a report. */
export const MAX_PATH_SPAN = 120;

const CONTROL = /[\u0000-\u001F\u007F-\u009F]/;

const AI_NAMES = new Set(['assistant', 'agent', 'ai', 'claude', 'kiro', 'copilot', 'llm']);
const FILLER = new Set(['please', 'now', 'first', 'then', 'also', 'always', 'you', 'must', 'should', 'to']);
const ACTION_VERBS = new Set([
  'read', 'send', 'upload', 'post', 'email', 'leak', 'exfiltrate', 'forward', 'paste', 'copy', 'print', 'cat',
  'run', 'execute', 'fetch', 'curl', 'download', 'write', 'edit', 'delete', 'reveal', 'dump', 'ignore', 'disregard', 'forget',
]);
const SENSITIVE = new Set([
  'env', 'dotenv', 'secret', 'secrets', 'credential', 'credentials', 'token', 'tokens', 'key', 'keys',
  'ssh', 'passwd', 'password', 'passwords', 'apikey',
]);
const OVERRIDE = /^(?:(?:please|now|first|you must|always) )?(?:ignore|disregard|forget|override) (?:all |any |the |your |every )?(?:previous|prior|above|earlier|preceding|system) (?:instructions?|rules|prompts?|context|guidelines|directives)\b/;

/** The words of a name: `-`, `_`, `.`, `+`, spaces and camelCase all separate words. */
export function nameWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[\s._+\-]+/)
    .map((w) => w.toLowerCase())
    .filter((w) => w.length > 0);
}

/** Hidden and control characters shown as [U+XXXX], the rest as is, capped at MAX_PATH_SPAN characters. */
export function escapePathSpan(name: string): string {
  let out = '';
  let count = 0;
  for (const ch of name) {
    const cp = ch.codePointAt(0) ?? 0;
    const shown = isHiddenCodePoint(cp) || CONTROL.test(ch) || cp === 0x2028 || cp === 0x2029
      ? `[U+${cp.toString(16).toUpperCase().padStart(4, '0')}]`
      : ch;
    if (count >= MAX_PATH_SPAN) return `${out}…`;
    out += shown;
    count++;
  }
  return out;
}

function readsAsInstruction(words: string[]): boolean {
  if (words.length < 3) return false;
  if (OVERRIDE.test(words.join(' '))) return true;
  if (words.length < 4) return false;
  const verbs = words.filter((w) => ACTION_VERBS.has(w));
  const hasSensitive = words.some((w) => SENSITIVE.has(w));
  const aiNamed = words.some((w) => AI_NAMES.has(w));
  // The AI is named, told to do an action, with something sensitive as the object.
  if (aiNamed && verbs.length >= 1 && hasSensitive) return true;
  // An imperative sentence: it begins with an action, and a second action follows ("read env and send to ...").
  const lead = words.filter((w, i) => !(FILLER.has(w) && words.slice(0, i).every((p) => FILLER.has(p))));
  const first = lead[0];
  return first !== undefined && ACTION_VERBS.has(first) && verbs.length >= 2 && hasSensitive;
}

/** Null when the name is ordinary. Never throws. */
export function checkPathSegment(name: string): PathNameHit | null {
  if (name.length === 0) return null;
  if (CONTROL.test(name) || findHiddenUnicode(name).length > 0) {
    return { kind: 'hidden-chars', span: escapePathSpan(name) };
  }
  if (readsAsInstruction(nameWords(name))) return { kind: 'instruction', span: escapePathSpan(name) };
  return null;
}
