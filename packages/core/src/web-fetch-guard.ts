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

export type WebFetchKind = 'secret' | 'canary' | 'env-value';
export type WebFetchDecision = { block: false } | { block: true; kind: WebFetchKind; host: string };
export type WebFetchContext = { envValues: readonly string[]; canaries: readonly Canary[] };

const EventSchema = z.object({
  tool_name: z.string().optional(),
  tool_input: z.record(z.unknown()),
});

const URL_KEYS = new Set(['url', 'uri', 'href', 'link', 'urls']);
const MAX_URL_CHARS = 16_384;
const MAX_FORMS = 64;

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
  return out.map((u) => u.slice(0, MAX_URL_CHARS));
}

function percentDecode(s: string): string {
  try { return decodeURIComponent(s); } catch { /* a stray % */ }
  return s.replace(/%([0-9a-fA-F]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
}

const SEPARATORS = /[\s/?&=#.+]/g;
const B64_RUN = /[A-Za-z0-9+/_-]{12,}={0,2}/g;

/** Decodings of every base64-looking run, at each of the four alignments. */
function base64Forms(s: string): string[] {
  const out: string[] = [];
  for (const m of s.matchAll(B64_RUN)) {
    const std = m[0].replaceAll('-', '+').replaceAll('_', '/').replace(/=+$/, '');
    for (let off = 0; off < 4 && std.length - off >= 12; off++) {
      out.push(Buffer.from(std.slice(off), 'base64').toString('utf8'));
    }
  }
  return out;
}

/** The text and its disguises: percent-decoded, base64-decoded (two levels), and with separators removed. */
export function urlForms(url: string): string[] {
  const forms = new Set<string>();
  const add = (s: string): void => { if (s !== '' && forms.size < MAX_FORMS) forms.add(s); };
  const level = (s: string, depth: number): void => {
    const decoded = percentDecode(s);
    for (const f of [s, decoded, decoded.replace(SEPARATORS, '')]) add(f);
    if (depth >= 2) return;
    // Base64 may sit in a path segment or a query value, so look at the pieces and at the whole.
    const pieces = [decoded, ...decoded.split(/[/?&=#]/)];
    for (const piece of pieces) for (const b of base64Forms(piece)) { add(b); level(b, depth + 1); }
  };
  level(url, 0);
  return [...forms];
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

/** The first kind of secret one address carries, or null. */
function kindOf(url: string, ctx: WebFetchContext): WebFetchKind | null {
  const forms = urlForms(url);
  if (ctx.canaries.length > 0 && forms.some((f) => findCanaryInText(f, ctx.canaries).length > 0)) return 'canary';
  if (forms.some((f) => containsSecret(f))) return 'secret';
  const flat = forms.map(alnum);
  for (const value of ctx.envValues) {
    const needle = alnum(value);
    if (value === '') continue;
    if (forms.some((f) => f.includes(value))) return 'env-value';
    if (needle.length >= 8 && flat.some((f) => f.includes(needle))) return 'env-value';
  }
  return null;
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
  'secret': 'a secret (a key or token)',
  'canary': 'a canary token, a trap value that must never leave the project',
  'env-value': 'a value copied from a .env file',
};

/** One plain line for stderr. Names the kind and the shortened host; never the value or the address. */
export function webFetchBlockMessage(d: { kind: WebFetchKind; host: string }): string {
  return `Exorcist 98 blocked the web fetch to ${d.host}: the address holds ${KIND_TEXT[d.kind]}. A fetch can send data out through its address. If you want this fetch, make it yourself.`;
}
