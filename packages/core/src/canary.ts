/**
 * canary.ts
 *
 * Canary traps: unique, harmless tokens planted where an attacker would want
 * an agent to read them. No honest workflow ever sends one anywhere, so a
 * canary token in a tool call, a scanned file or a staged commit is proof that
 * something talked the agent into leaking. The primitives here are shared by
 * the Shield (tool calls), the scanner (files) and the pre-commit hook.
 *
 * Library code only: no CLI, no network.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { z } from 'zod';

// ── tokens ──────────────────────────────────────────────────────────────────

export const CANARY_PREFIX = 'x98c_';
/** `x98c_` + 24 base32 characters: enough entropy to be unguessable and unique. */
export const CANARY_TOKEN_RE_SOURCE = 'x98c_[A-Z2-7]{24}';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** A fresh canary token: `x98c_` + 24 random base32 characters (120 bits). */
export function newToken(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(15));
  let out = '';
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return `${CANARY_PREFIX}${out}`;
}

// ── the records file ────────────────────────────────────────────────────────

export const CanaryRecordSchema = z.object({
  token:   z.string().regex(new RegExp(`^${CANARY_TOKEN_RE_SOURCE}$`), 'a canary token is x98c_ + 24 base32 characters'),
  /** The trap file the token lives in, relative to the project root. */
  file:    z.string().min(1),
  created: z.string().min(1),
});

export const CanariesFileSchema = z.object({
  version: z.literal(1),
  canaries: z.array(CanaryRecordSchema),
});

export type CanaryRecord = z.infer<typeof CanaryRecordSchema>;
export type CanariesFile = z.infer<typeof CanariesFileSchema>;

/** Where a project's canary records live: `<root>/.exorcist/canaries.json`. */
export function canariesPath(root: string): string {
  return join(root, '.exorcist', 'canaries.json');
}

export type CanariesResult = { ok: true; canaries: CanaryRecord[] } | { ok: false; error: string };

/** Read the records file. A missing file is an empty list, not an error. */
export function loadCanariesFile(path: string): CanariesResult {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    return { ok: true, canaries: [] };
  }
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return { ok: false, error: `The canary records file ${path} is not valid JSON.` };
  }
  const parsed = CanariesFileSchema.safeParse(json);
  if (!parsed.success) {
    return { ok: false, error: `The canary records file ${path} is invalid: ${parsed.error.issues[0]?.message ?? 'unknown problem'}` };
  }
  return { ok: true, canaries: parsed.data.canaries };
}

// ── detection ───────────────────────────────────────────────────────────────

/** Regex that matches the token with any amount of whitespace between its characters. */
function looseTokenRegex(token: string): RegExp {
  return new RegExp(token.split('').map((c) => (/[A-Z0-9_]/.test(c) ? c : `\\${c}`)).join('\\s*'));
}

/** Regex that matches the token with any character percent-encoded. */
function percentTokenRegex(token: string): RegExp {
  return new RegExp(token.split('').map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase()}|${c}`).join(''));
}

/** The base64 shapes of a token, one per alignment, so an encoded copy is found whole. */
export function base64Needles(token: string): string[] {
  const out: string[] = [];
  for (let shift = 0; shift < 3; shift++) {
    const len = 3 * Math.floor((token.length - shift) / 3);
    if (len < 21) continue;
    const enc = Buffer.from(`${'P'.repeat(shift)}${token.slice(shift, shift + len)}`, 'utf8').toString('base64');
    const needle = shift === 0 ? enc : enc.slice(4);
    out.push(needle, needle.replaceAll('+', '-').replaceAll('/', '_'));
  }
  return out;
}

export type CanaryHit = {
  record: CanaryRecord;
  /** Index in the searched text where the token (or its encoded shape) starts. */
  index: number;
  /** The shape it was found in. */
  shape: 'raw' | 'whitespace-split' | 'percent-encoded' | 'base64';
};

/** Runs of base64 (standard or URL-safe) long enough to hold a token. */
const B64_RUN = /[A-Za-z0-9+/_=-]{40,}/g;

function tryPctDecode(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

/**
 * Look for one record's token in a piece of text, raw or disguised: split by
 * whitespace, percent-encoded, or inside a base64 blob. Returns the first hit.
 */
export function findRecordIn(record: CanaryRecord, text: string): CanaryHit | null {
  // 1. The raw token.
  const raw = text.indexOf(record.token);
  if (raw >= 0) return { record, index: raw, shape: 'raw' };

  // 2. Whitespace between the token's characters.
  const m = looseTokenRegex(record.token).exec(text);
  if (m) return { record, index: m.index, shape: 'whitespace-split' };

  // 3. Each character optionally percent-encoded.
  const p = percentTokenRegex(record.token).exec(text);
  if (p) return { record, index: p.index, shape: 'percent-encoded' };

  // 4. The token base64-encoded (or percent-encoded then base64) in the text.
  const surfaces = [text];
  const pct = tryPctDecode(text);
  if (pct !== text) surfaces.push(pct);
  for (const s of surfaces) {
    for (const needle of base64Needles(record.token)) {
      const i = s.indexOf(needle);
      if (i >= 0) return { record, index: i, shape: 'base64' };
    }
    // 5. A base64 blob that decodes to the token.
    B64_RUN.lastIndex = 0;
    let run: RegExpExecArray | null;
    while ((run = B64_RUN.exec(s)) !== null) {
      const std = run[0].replaceAll('-', '+').replaceAll('_', '/');
      const decoded = Buffer.from(std, 'base64').toString('utf8');
      if (decoded.includes(record.token) || looseTokenRegex(record.token).test(decoded)) {
        return { record, index: run.index, shape: 'base64' };
      }
    }
  }
  return null;
}

/** Every record whose token appears in `text`, in text order. */
export function findCanaryInText(text: string, records: readonly CanaryRecord[]): CanaryHit[] {
  const hits = records.map((r) => ({ r, h: findRecordIn(r, text) })).filter((x) => x.h !== null);
  return hits.map((x) => x.h as CanaryHit).sort((a, b) => a.index - b.index);
}

/** 1-based line and column of an index in a text. */
export function lineColOf(text: string, index: number): { line: number; col: number } {
  let line = 1;
  let last = 0;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) {
      line++;
      last = i + 1;
    }
  }
  return { line, col: index - last + 1 };
}

// ── staged commits ──────────────────────────────────────────────────────────

export type StagedCanaryHit = { file: string; line: number; redacted: string };
export type StagedCanaryResult =
  | { ok: true; hits: StagedCanaryHit[] }
  | { ok: false; error: string };

const MAX_BYTES = 1_048_576;

/**
 * Canary tokens staged outside `.exorcist/` (the traps and the records file
 * themselves are allowed). A token that left its trap is on its way out of the
 * project, so the commit is refused.
 */
export function findStagedCanaries(cwd: string = process.cwd()): StagedCanaryResult {
  let root: string;
  let names: string[];
  try {
    root = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd, encoding: 'utf8' }).trim();
    const out = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'], { cwd: root, encoding: 'utf8' });
    names = out.split('\0').filter(Boolean);
  } catch (err) {
    return { ok: false, error: `Could not read the staged files: ${String(err).split('\n')[0]}` };
  }

  const records = loadCanariesFile(canariesPath(root));
  if (!records.ok) return { ok: false, error: records.error };
  if (records.canaries.length === 0) return { ok: true, hits: [] };

  const hits: StagedCanaryHit[] = [];
  for (const name of names) {
    if (name.replace(/\\/g, '/').startsWith('.exorcist/')) continue;
    const full = resolve(root, name);
    let text: string;
    try {
      if (statSync(full).size > MAX_BYTES) continue;
      const buf = readFileSync(full);
      if (buf.subarray(0, 512).includes(0)) continue; // binary
      text = buf.toString('utf8');
    } catch {
      continue; // deleted or unreadable between the two git calls
    }
    for (const h of findCanaryInText(text, records.canaries)) {
      const { line } = lineColOf(text, h.index);
      hits.push({ file: name, line, redacted: `${h.record.token.slice(0, 5)}${'*'.repeat(24)}` });
    }
  }
  return { ok: true, hits };
}
