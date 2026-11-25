import type { Finding } from './types.js';

/**
 * Redaction of secret material in anything the scanner prints, writes or sends
 * (m7-precision, requirement 1). Browser-safe: no Node imports, because the
 * SARIF reporter also runs in the web page.
 *
 * A redacted secret keeps its type and length and, when it is long enough that
 * four characters give nothing away, its first four characters:
 * `[redacted github-token: ghp_…, 40 chars]`.
 *
 * The patterns mirror EX-011 (definitions/EX-011-secrets-in-agent-reach.yaml).
 * This is the only list of secret patterns used for output.
 */

/** Show leading characters only for a secret at least this long. */
export const MIN_LENGTH_FOR_PREFIX = 16;
const PREFIX_CHARS = 4;

type Kind = { type: string; re: RegExp };

// Bare tokens recognisable by their own format.
const TOKEN_KINDS: readonly Kind[] = [
  { type: 'github-token',    re: /^(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})$/ },
  { type: 'anthropic-key',   re: /^sk-ant-api\d\d-[A-Za-z0-9_-]{40,}$/ },
  { type: 'openai-key',      re: /^sk-(?:proj-)?[A-Za-z0-9_-]{40,}$/ },
  { type: 'aws-access-key',  re: /^AKIA[0-9A-Z]{16}$/ },
  { type: 'slack-token',     re: /^xox[baprs]-[0-9A-Za-z-]{20,}$/ },
  { type: 'google-api-key',  re: /^AIza[0-9A-Za-z_-]{35}$/ },
  { type: 'stripe-key',      re: /^sk_live_[0-9A-Za-z]{24,}$/ },
  { type: 'npm-token',       re: /^npm_[A-Za-z0-9]{36}$/ },
];

const BARE_TOKEN =
  /\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}|sk-(?:proj-|ant-api\d\d-)?[A-Za-z0-9_-]{40,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{20,}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]{24,}|npm_[A-Za-z0-9]{36})\b/g;

// The marker is assembled so that this file does not itself hold the PEM header
// (a repository check fails on any file that does).
const PEM = ['PRIVATE', 'KEY'].join(' ');
const PRIVATE_KEY = new RegExp(
  `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?${PEM}(?: BLOCK)?-----(?:[\\s\\S]*?-----END [A-Z ]*${PEM}(?: BLOCK)?-----|[\\s\\S]*$)`,
  'g',
);

const DATABASE_URL = /\b(DATABASE_URL=)([a-z+]+:\/\/[^\s:@/]+:[^\s@/]+@[^\s]+)/g;

const SECRET_VARIABLE =
  /\b((?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|SLACK_BOT_TOKEN|STRIPE_SECRET_KEY|GOOGLE_API_KEY|NPM_TOKEN)=)(?!EXAMPLE_|\[redacted )([^\s]+)/g;

// Values that are plainly not secrets, so a variable name next to a placeholder stays readable.
const PLACEHOLDER_VALUE = /^["']?(?:\[?redacted\]?|x{3,}|\*{3,}|<|\$\{?[A-Za-z_]+\}?|your[_-]|changeme|placeholder|dummy|fake)/i;

function typeOfToken(value: string): string {
  return TOKEN_KINDS.find((k) => k.re.test(value))?.type ?? 'secret-variable';
}

/** The marker that replaces `secret`: type, at most four leading characters, length. */
export function redactionMarker(type: string, secret: string): string {
  const head = secret.length >= MIN_LENGTH_FOR_PREFIX ? `${secret.slice(0, PREFIX_CHARS)}…, ` : '';
  return `[redacted ${type}: ${head}${secret.length} chars]`;
}

/** Replace every secret in `text` with a marker. Text without secrets is returned unchanged. */
export function redactSecretText(text: string): string {
  if (text.length === 0) return text;
  let out = text.replace(PRIVATE_KEY, (m) => `[redacted private-key: ${m.length} chars]`);
  out = out.replace(DATABASE_URL, (_m, name: string, value: string) => `${name}${redactionMarker('database-url', value)}`);
  out = out.replace(SECRET_VARIABLE, (m, name: string, value: string) =>
    PLACEHOLDER_VALUE.test(value) ? m : `${name}${redactionMarker(typeOfToken(value.replace(/^["']|["',;]+$/g, '')), value)}`);
  out = out.replace(BARE_TOKEN, (m) => redactionMarker(typeOfToken(m), m));
  return out;
}

/** 1-based numbers of the lines that belong to a private-key block (its BEGIN and END lines and everything between). */
export function privateKeyLines(text: string): Set<number> {
  const out = new Set<number>();
  const re = new RegExp(PRIVATE_KEY.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    let line = 1;
    for (let i = text.indexOf('\n'); i !== -1 && i < m.index; i = text.indexOf('\n', i + 1)) line++;
    const last = line + (m[0].match(/\n/g)?.length ?? 0);
    for (let n = line; n <= last; n++) out.add(n);
  }
  return out;
}
/** The marker for one line of a private-key block. */
export const PRIVATE_KEY_LINE_MARKER = '[redacted private-key line]';
/**
 * `redactSecretText` for text shown line by line (a diff, a snippet): the line
 * count is kept, every line inside a private-key block is replaced by a marker
 * (with `diff`, after its one-character diff prefix), and each other line is
 * redacted on its own. Redacting line by line alone leaves the body of a key
 * block in the clear, because only its BEGIN and END lines carry the marker.
 */
export function redactSecretLines(text: string, opts: { diff?: boolean } = {}): string {
  const key = privateKeyLines(text);
  return text.split('\n').map((line, i) => {
    if (!key.has(i + 1)) return redactSecretText(line);
    const prefix = opts.diff && /^[-+ ]/.test(line) ? line.slice(0, 1) : '';
    return `${prefix}${PRIVATE_KEY_LINE_MARKER}`;
  }).join('\n');
}
/** True when `text` holds a secret that `redactSecretText` would replace. */
export function containsSecret(text: string): boolean {
  return redactSecretText(text) !== text;
}

/**
 * The finding with secret material removed from every field that quotes file
 * text (`span`, `rationale`, `decoded`). Rule, severity, file, line and column
 * are untouched. An EX-011 span that no pattern recognised is replaced whole,
 * so a secret in an unknown format cannot leak.
 */
export function redactFinding<T extends Finding>(f: T): T {
  let span = redactSecretText(f.span);
  if (f.ruleId === 'EX-011' && span === f.span && f.span.length > 0 && !f.span.includes('[redacted ')) {
    span = `[redacted secret: ${f.span.length} chars]`;
  }
  const out: T = { ...f, span };
  if (out.source === 'heuristic') (out as { rationale: string }).rationale = redactSecretText(out.rationale);
  if (out.source === 'signature' && out.decoded !== undefined) (out as { decoded?: string }).decoded = redactSecretText(out.decoded);
  return out;
}

/** `redactFinding` for a list. */
export function redactFindings<T extends Finding>(findings: readonly T[]): T[] {
  return findings.map(redactFinding);
}
