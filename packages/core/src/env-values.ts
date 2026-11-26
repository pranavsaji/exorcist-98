/**
 * env-values.ts
 *
 * Values assigned in the `.env*` files of a workspace root. The web-fetch guard
 * and the env-value write guard use them to spot a secret that was copied out
 * of a `.env` file. Values are secrets: this module never logs or prints them.
 *
 * `parseEnvValues` is pure. `loadEnvValues` reads the files and returns an empty
 * list on any problem; it never throws.
 */
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** Values shorter than this are ordinary configuration, not secrets. */
export const MIN_ENV_VALUE_LENGTH = 8;
/** A `.env*` file larger than this is skipped. */
const MAX_ENV_FILE_BYTES = 256 * 1024;

const COMMON_WORDS: ReadonlySet<string> = new Set([
  'true', 'false', 'null', 'undefined', 'none', 'yes', 'no', 'on', 'off',
  'localhost', '127.0.0.1', '0.0.0.0', 'development', 'production', 'staging', 'test', 'debug',
]);
const BARE_NUMBER = /^[+-]?\d+(\.\d+)?$/;
const LOCAL_URL = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\/?$/i;
const ASSIGNMENT = /^(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=\s*(.*)$/;

/** True when a value is too short or too ordinary to count as a secret. */
export function isIgnorableEnvValue(value: string): boolean {
  if (value.length < MIN_ENV_VALUE_LENGTH) return true;
  return COMMON_WORDS.has(value.toLowerCase()) || BARE_NUMBER.test(value) || LOCAL_URL.test(value);
}

/** The value part of an assignment's right-hand side: quotes removed, comments dropped. */
function valueOf(rest: string): string {
  const quote = rest[0];
  if (quote === '"' || quote === "'") {
    for (let i = 1; i < rest.length; i++) {
      if (quote === '"' && rest[i] === '\\') { i++; continue; }
      if (rest[i] === quote) return rest.slice(1, i);
    }
    return rest.slice(1); // unterminated quote: take the rest of the line
  }
  const hash = rest.search(/\s#/);
  return (hash === -1 ? rest : rest.slice(0, hash)).trim();
}

/** Values assigned in one `.env` file's text, without ordinary short or common ones, in order, unique. */
export function parseEnvValues(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const m = ASSIGNMENT.exec(line);
    if (!m) continue;
    const value = valueOf((m[1] ?? '').trim());
    if (isIgnorableEnvValue(value) || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

/** Values from every `.env*` file directly inside `cwd`. Empty when there is none or on any read error. */
export function loadEnvValues(cwd: string): string[] {
  let names: string[];
  try {
    names = readdirSync(cwd).filter((n) => n === '.env' || n.startsWith('.env.')).sort();
  } catch {
    return [];
  }
  const out: string[] = [];
  const seen = new Set<string>();
  for (const name of names) {
    try {
      const path = join(cwd, name);
      const st = lstatSync(path);
      if (!st.isFile() || st.size > MAX_ENV_FILE_BYTES) continue;
      for (const v of parseEnvValues(readFileSync(path, 'utf8'))) {
        if (!seen.has(v)) { seen.add(v); out.push(v); }
      }
    } catch {
      continue;
    }
  }
  return out;
}
