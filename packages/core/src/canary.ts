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
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';

// ── tokens ──────────────────────────────────────────────────────────────────

export const CANARY_PREFIX = 'x98c_';
/** `x98c_` + 24 base32 characters: 120 random bits, unique per install. */
export const CANARY_TOKEN_RE_SOURCE = 'x98c_[A-Z2-7]{24}';
const TOKEN_RE = new RegExp(`^${CANARY_TOKEN_RE_SOURCE}$`);

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** A fresh canary token: `x98c_` + 24 random base32 characters (15 random bytes). */
export function newToken(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(15));
  let out = '';
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = ((value << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return `${CANARY_PREFIX}${out}`;
}

export function isCanaryToken(s: string): boolean {
  return TOKEN_RE.test(s);
}

// ── the records file ────────────────────────────────────────────────────────

/** Where trap files live, relative to the project root. */
export const CANARY_TRAP_DIR = '.exorcist/canary';
/** The records file, relative to the project root. */
export const CANARY_RECORDS_FILE = '.exorcist/canaries.json';

/**
 * A trap path must stay inside `.exorcist/canary/`: `--remove` deletes the
 * files named here, so a tampered records file must not be able to name
 * anything else.
 */
const TrapPathSchema = z
  .string()
  .min(1)
  .refine(
    (p) => p.startsWith(`${CANARY_TRAP_DIR}/`) && !p.split('/').some((seg) => seg === '..' || seg === '') && !p.includes('\\'),
    `a trap file must be a plain path inside ${CANARY_TRAP_DIR}/`,
  );

export const CanaryRecordSchema = z.object({
  token:   z.string().regex(TOKEN_RE, 'a canary token is x98c_ + 24 base32 characters'),
  /** The trap file the token lives in, relative to the project root. */
  file:    TrapPathSchema,
  created: z.string().min(1),
}).strict();

export const CanariesFileSchema = z.object({
  version:  z.literal(1),
  canaries: z.array(CanaryRecordSchema),
  /** Folders `plant` created, so `remove` takes away exactly those (when empty). */
  madeDirs: z.array(z.enum(['.exorcist', CANARY_TRAP_DIR])).optional(),
}).strict();

export type CanaryRecord = z.infer<typeof CanaryRecordSchema>;
export type CanariesFile = z.infer<typeof CanariesFileSchema>;
/** What detection needs from a record: the token and the trap it came from. */
export type Canary = { token: string; file: string };

/** Where a project's canary records live: `<root>/.exorcist/canaries.json`. */
export function canariesPath(root: string): string {
  return join(root, '.exorcist', 'canaries.json');
}

export type CanariesResult = { ok: true; canaries: CanaryRecord[]; madeDirs: string[] } | { ok: false; error: string };

/** Read a records file. A missing file is an empty list; an unreadable or invalid one is an error. */
export function loadCanariesFile(path: string): CanariesResult {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { ok: true, canaries: [], madeDirs: [] };
    return { ok: false, error: `Could not read the canary records file ${path}: ${String(err).split('\n')[0]}` };
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
  return { ok: true, canaries: parsed.data.canaries, madeDirs: parsed.data.madeDirs ?? [] };
}

// ── detection ───────────────────────────────────────────────────────────────

export type CanaryShape = 'raw' | 'whitespace-split' | 'percent-encoded' | 'base64';

export type CanaryHit<C extends Canary = Canary> = {
  canary: C;
  /** Where the token (or its disguised copy) starts in the searched text. */
  index: number;
  /** Where it ends (exclusive), so the exact quoted span is `text.slice(index, end)`. */
  end: number;
  shape: CanaryShape;
};

/**
 * A view of the text with whitespace removed and ASCII percent-escapes
 * decoded, with each character's position in the original. A token split by
 * spaces or line breaks, percent-encoded (whole or in part), or both, appears
 * whole in this view.
 */
type Surface = { s: string; start: number[]; end: number[] };

function hexVal(c: number): number {
  if (c >= 48 && c <= 57) return c - 48;
  if (c >= 65 && c <= 70) return c - 55;
  if (c >= 97 && c <= 102) return c - 87;
  return -1;
}

function surfaceOf(text: string): Surface {
  let s = '';
  const start: number[] = [];
  const end: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    if (/\s/.test(ch)) continue;
    if (ch === '%' && i + 2 < text.length) {
      const hi = hexVal(text.charCodeAt(i + 1));
      const lo = hexVal(text.charCodeAt(i + 2));
      if (hi >= 0 && lo >= 0 && hi < 8) {
        const decoded = String.fromCharCode(hi * 16 + lo);
        if (!/\s/.test(decoded)) {
          s += decoded;
          start.push(i);
          end.push(i + 3);
        }
        i += 2;
        continue;
      }
    }
    s += ch;
    start.push(i);
    end.push(i + 1);
  }
  return { s, start, end };
}

/**
 * The base64 shapes of a token, one per byte alignment, in standard and
 * URL-safe alphabets. Each holds only characters that depend on the token
 * alone, so it is found inside the base64 of any larger text that contains
 * the token, wherever the token sits. A needle covers all but one or two of
 * the token's characters; `verifyBase64` decodes around a hit to check the
 * rest.
 */
function needlesOf(token: string): Array<{ needle: string; shift: number }> {
  const out: Array<{ needle: string; shift: number }> = [];
  const tok = Buffer.from(token, 'utf8');
  for (let shift = 0; shift < 3; shift++) {
    const bytes = Buffer.concat([Buffer.alloc(shift, 0), tok]);
    const enc = bytes.toString('base64');
    const full = Math.floor(bytes.length / 3) * 4; // characters of complete groups only (no padding)
    const needle = enc.slice(shift === 0 ? 0 : 4, full);
    out.push({ needle, shift });
    const url = needle.replaceAll('+', '-').replaceAll('/', '_');
    if (url !== needle) out.push({ needle: url, shift });
  }
  return out;
}

export function base64Needles(token: string): string[] {
  return needlesOf(token).map((n) => n.needle);
}

const B64_CHAR = /[A-Za-z0-9+/_-]/;

/** Decode one group before and after a needle hit and check the whole token is there. */
function verifyBase64(s: string, at: number, needle: string, token: string): boolean {
  let pre = '';
  if (at >= 4) {
    const p = s.slice(at - 4, at);
    if ([...p].every((ch) => B64_CHAR.test(ch))) pre = p;
  }
  let post = '';
  for (const ch of s.slice(at + needle.length, at + needle.length + 4)) {
    if (!B64_CHAR.test(ch) && ch !== '=') break;
    post += ch;
  }
  const chunk = `${pre}${needle}${post}`.replaceAll('-', '+').replaceAll('_', '/');
  return Buffer.from(chunk, 'base64').toString('latin1').includes(token);
}

/** Runs of base64 (standard or URL-safe) long enough to hold a token. */
const B64_RUN = /[A-Za-z0-9+/_-]{36,}={0,2}/g;
const MAX_DEPTH = 2;

function decodeRuns(s: string): Array<{ at: number; to: number; text: string }> {
  const out: Array<{ at: number; to: number; text: string }> = [];
  B64_RUN.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = B64_RUN.exec(s)) !== null) {
    const std = m[0].replaceAll('-', '+').replaceAll('_', '/').replace(/=+$/, '');
    // The run may start mid-word (for example "key=" glued to the blob), so
    // every alignment is tried.
    for (let off = 0; off < 4 && std.length - off >= 36; off++) {
      out.push({ at: m.index, to: m.index + m[0].length, text: Buffer.from(std.slice(off), 'base64').toString('latin1') });
    }
  }
  return out;
}

type Found = { index: number; end: number; shape: CanaryShape };

function findIn<C extends Canary>(text: string, canaries: readonly C[], depth: number, found: Map<C, Found>): void {
  const pending = (): C[] => canaries.filter((c) => !found.has(c));
  // 1. The raw token.
  for (const c of pending()) {
    const i = text.indexOf(c.token);
    if (i >= 0) found.set(c, { index: i, end: i + c.token.length, shape: 'raw' });
  }
  if (pending().length === 0) return;

  // 2. Split by whitespace and/or percent-encoded.
  const surf = surfaceOf(text);
  for (const c of pending()) {
    const i = surf.s.indexOf(c.token);
    if (i < 0) continue;
    const index = surf.start[i] ?? 0;
    const end = surf.end[i + c.token.length - 1] ?? text.length;
    found.set(c, { index, end, shape: text.slice(index, end).includes('%') ? 'percent-encoded' : 'whitespace-split' });
  }
  if (pending().length === 0) return;

  // 3. Base64 of anything holding the token, at any alignment.
  for (const c of pending()) {
    search: for (const { needle } of needlesOf(c.token)) {
      for (let i = surf.s.indexOf(needle); i >= 0; i = surf.s.indexOf(needle, i + 1)) {
        if (!verifyBase64(surf.s, i, needle, c.token)) continue;
        found.set(c, { index: surf.start[i] ?? 0, end: surf.end[i + needle.length - 1] ?? text.length, shape: 'base64' });
        break search;
      }
    }
  }
  if (pending().length === 0 || depth >= MAX_DEPTH) return;

  // 4. Base64 of a disguised token (split or percent-encoded, then encoded).
  for (const run of decodeRuns(surf.s)) {
    const inner = new Map<C, Found>();
    findIn(run.text, pending(), depth + 1, inner);
    for (const c of inner.keys()) {
      found.set(c, { index: surf.start[run.at] ?? 0, end: surf.end[run.to - 1] ?? text.length, shape: 'base64' });
    }
    if (pending().length === 0) return;
  }
}

/**
 * Every canary whose token appears in `text`, raw or disguised: split by
 * whitespace, percent-encoded, base64 (standard or URL-safe, at any
 * alignment, also wrapped over lines), or those combined. In text order.
 */
export function findCanaryInText<C extends Canary>(text: string, canaries: readonly C[]): Array<CanaryHit<C>> {
  if (canaries.length === 0 || text.length === 0) return [];
  const found = new Map<C, Found>();
  findIn(text, canaries, 0, found);
  return [...found.entries()]
    .map(([canary, f]) => ({ canary, ...f }))
    .sort((a, b) => a.index - b.index);
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

/** The token with its random part hidden, for logs and terminal output. */
export function maskToken(token: string): string {
  return `${token.slice(0, CANARY_PREFIX.length + 2)}${'*'.repeat(Math.max(0, token.length - CANARY_PREFIX.length - 2))}`;
}

/** True for paths where canary tokens live on purpose: the trap folder and the records file. */
export function isCanaryHome(rel: string): boolean {
  const p = rel.replace(/\\/g, '/').replace(/^\.\//, '');
  return p === CANARY_RECORDS_FILE || p.startsWith(`${CANARY_TRAP_DIR}/`);
}

// ── staged commits ──────────────────────────────────────────────────────────

export type StagedCanaryHit = { file: string; line: number; trap: string; redacted: string };
export type StagedCanaryResult =
  | { ok: true; hits: StagedCanaryHit[] }
  | { ok: false; error: string };

const MAX_BYTES = 1_048_576;

/**
 * Canary tokens in the staged content of files outside the trap folder and
 * the records file. A token that left its trap is on its way out of the
 * project, so the commit is refused. The staged blob is read (not the working
 * copy), since that is what the commit would hold.
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
    if (isCanaryHome(name)) continue;
    let buf: Buffer;
    try {
      buf = execFileSync('git', ['cat-file', 'blob', `:${name}`], { cwd: root, maxBuffer: MAX_BYTES * 2 });
    } catch {
      continue; // too large or gone from the index between the two git calls
    }
    if (buf.length > MAX_BYTES || buf.subarray(0, 512).includes(0)) continue; // large or binary
    const text = buf.toString('utf8');
    for (const h of findCanaryInText(text, records.canaries)) {
      hits.push({ file: name, line: lineColOf(text, h.index).line, trap: h.canary.file, redacted: maskToken(h.canary.token) });
    }
  }
  return { ok: true, hits };
}
