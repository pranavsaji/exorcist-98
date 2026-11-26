/**
 * web-fetch-guard.ts (CT-13)
 *
 * Pure decision for the `web_fetch` PreToolUse hook: does the address the agent
 * wants to fetch carry a secret? The address is checked as written and in its
 * percent-decoded, base64-decoded and split (separators removed) forms against
 * the secret patterns of `redact-secrets`, the canary tokens (`findCanaryInText`)
 * and the values from the workspace's `.env*` files.
 *
 * The result names the kind of value and a shortened host. It never holds the
 * value or the full address, so nothing here can leak either into a message.
 */
import { z } from 'zod';
import { findCanaryInText } from './canary.js';
import type { Canary } from './canary.js';
import { containsSecret } from './redact-secrets.js';

export type WebFetchKind = 'secret' | 'canary' | 'env-value' | 'oversized' | 'too-many-encodings';
export type WebFetchDecision = { block: false } | { block: true; kind: WebFetchKind; host: string };
export type WebFetchContext = { envValues: readonly string[]; canaries: readonly Canary[] };

const EventSchema = z.object({
  tool_name: z.string().optional(),
  tool_input: z.record(z.unknown()),
});

const URL_KEYS = new Set(['url', 'uri', 'href', 'link', 'urls']);
const MAX_URL_CHARS = 16_384;
const MAX_FORMS = 512;
const MAX_DECODED_BYTES = 65_536;

/** The address strings a web_fetch event asks for. Empty for anything else or anything unparsable. */
export function extractFetchUrls(event: unknown): string[] {
  const parsed = EventSchema.safeParse(event);
  if (!parsed.success) return [];
  const { tool_name: tool, tool_input: input } = parsed.data;
  if (tool !== undefined && !/fetch/i.test(tool)) return [];
  const out: string[] = [];
  for (const [key, value] of Object.entries(input)) {
    if (!URL_KEYS.has(key.toLowerCase())) continue;
    if (typeof value === 'string') out.push(value);
    else if (Array.isArray(value)) for (const v of value) if (typeof v === 'string') out.push(v);
  }
  return out;
}

function percentDecode(s: string): string {
  try { return decodeURIComponent(s); } catch { /* a stray % */ }
  return s.replace(/%([0-9a-fA-F]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
}

const SEPARATORS = /[\s/?&=#.+]/g;
const B64_RUN = /[A-Za-z0-9+/_-]{12,}={0,2}/g;

/**
 * Work done so far on one address: forms already yielded, the shallowest depth at which each form was
 * expanded, and decoded bytes spent. `exhausted` once a cap stopped the search.
 */
type FormState = { seen: Set<string>; expandedAt: Map<string, number>; bytes: number; exhausted: boolean };
const newState = (): FormState => ({ seen: new Set(), expandedAt: new Map(), bytes: 0, exhausted: false });
/** True when the form is new (not yielded before) and within the form cap; sets `exhausted` when the cap stops it. */
function admit(f: string, st: FormState): boolean {
  if (f === '' || st.seen.has(f)) return false;
  if (st.seen.size >= MAX_FORMS) { st.exhausted = true; return false; }
  st.seen.add(f);
  return true;
}
/** Decodings of every base64-looking run, at each of the four alignments, one at a time. Stops when the byte budget is spent. */
function* base64Forms(s: string, st: FormState): Generator<string> {
  for (const m of s.matchAll(B64_RUN)) {
    const std = m[0].replaceAll('-', '+').replaceAll('_', '/').replace(/=+$/, '');
    for (let off = 0; off < 4 && std.length - off >= 12; off++) {
      st.bytes += Math.floor(((std.length - off) * 3) / 4);
      if (st.bytes > MAX_DECODED_BYTES) { st.exhausted = true; return; }
      yield Buffer.from(std.slice(off), 'base64').toString('utf8');
    }
  }
}
/**
 * Each form as soon as it is produced, so the caller can stop at the first match. A form is yielded once,
 * but expanded again when it is reached at a shallower depth than before, since it may then decode further.
 * Depth only ever decreases between expansions of one form and is at least 0, so this terminates.
 */
function* formsOf(s: string, depth: number, st: FormState): Generator<string> {
  const decoded = percentDecode(s);
  for (const f of [s, decoded, decoded.replace(SEPARATORS, '')]) if (admit(f, st)) yield f;
  if (depth >= 2) return;
  const prior = st.expandedAt.get(s);
  if (prior !== undefined && prior <= depth) return;
  st.expandedAt.set(s, depth);
  // Base64 may sit in a path segment or a query value, so look at the pieces and at the whole.
  for (const piece of [decoded, ...decoded.split(/[/?&=#]/)]) {
    for (const b of base64Forms(piece, st)) {
      if (b !== '') yield* formsOf(b, depth + 1, st);
      if (st.exhausted) return;
    }
    if (st.exhausted) return;
  }
}
/** The text and its disguises: percent-decoded, base64-decoded (two levels), and with separators removed. Capped. */
export function urlForms(url: string): string[] {
  return [...formsOf(url, 0, newState())];
}
const alnum = (s: string): string => s.replace(/[^A-Za-z0-9]/g, '');

/** A host that cannot carry a secret in its first labels: `*.example.invalid`. */
export function shortHost(url: string): string {
  let host: string;
  try { host = new URL(url).hostname; } catch { return 'an unreadable address'; }
  if (host === '') return 'an unreadable address';
  if (host.includes(':') || /^\d+(\.\d+){3}$/.test(host)) return 'an IP address';
  const labels = host.split('.');
  return labels.length > 2 ? `*.${labels.slice(-2).join('.')}` : host;
}

/** The kind of secret one form carries, or null. */
function formKind(f: string, ctx: WebFetchContext): WebFetchKind | null {
  if (ctx.canaries.length > 0 && findCanaryInText(f, ctx.canaries).length > 0) return 'canary';
  if (containsSecret(f)) return 'secret';
  const flat = alnum(f);
  for (const value of ctx.envValues) {
    if (value === '') continue;
    if (f.includes(value)) return 'env-value';
    const needle = alnum(value);
    if (needle.length >= 8 && flat.includes(needle)) return 'env-value';
  }
  return null;
}
/** The first kind of secret one address carries, or null. Fails closed: too long or too many encodings is a kind of its own. */
function kindOf(url: string, ctx: WebFetchContext): WebFetchKind | null {
  if (url.length > MAX_URL_CHARS) return 'oversized';
  const st = newState();
  for (const f of formsOf(url, 0, st)) {
    const kind = formKind(f, ctx);
    if (kind !== null) return kind;
  }
  return st.exhausted ? 'too-many-encodings' : null;
}
/** Decide one `web_fetch` event (already JSON-parsed). Anything not recognisable is allowed. */
export function decideWebFetch(event: unknown, ctx: WebFetchContext): WebFetchDecision {
  for (const url of extractFetchUrls(event)) {
    const kind = kindOf(url, ctx);
    if (kind !== null) return { block: true, kind, host: shortHost(url) };
  }
  return { block: false };
}

const KIND_TEXT: Record<WebFetchKind, string> = {
  'secret': 'holds a secret (a key or token)',
  'canary': 'holds a canary token, a trap value that must never leave the project',
  'env-value': 'holds a value copied from a .env file',
  'oversized': 'is too long to check',
  'too-many-encodings': 'has too many encoded pieces to check',
};

/** One plain line for stderr. Names the kind and the shortened host; never the value or the address. */
export function webFetchBlockMessage(d: { kind: WebFetchKind; host: string }): string {
  return `Exorcist 98 blocked the web fetch to ${d.host}: the address ${KIND_TEXT[d.kind]}. A fetch can send data out through its address. If you want this fetch, make it yourself.`;
}
