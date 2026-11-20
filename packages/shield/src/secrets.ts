import { findSecrets, redact } from '@exorcist-98/core';

/**
 * Credential shapes the Shield blocks in tool-call arguments (S-008), on top of
 * core's `findSecrets` (AWS access key, GitHub token, OpenAI-style key).
 * Each pattern is anchored on a prefix the issuer documents, so ordinary text
 * does not match. Placeholders (`EXAMPLE_*_DO_NOT_USE`) are never reported.
 */
export type SecretHit = { kind: string; match: string };

type Pattern = { kind: string; re: RegExp };

const PATTERNS: Pattern[] = [
  { kind: 'private key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g },
  { kind: 'Anthropic API key', re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}/g },
  { kind: 'Slack token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { kind: 'Slack webhook', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/g },
  { kind: 'Stripe secret key', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g },
  { kind: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { kind: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,}/g },
  { kind: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { kind: 'PyPI token', re: /\bpypi-[A-Za-z0-9_-]{50,}/g },
  { kind: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{30,}\b/g },
  { kind: 'SendGrid key', re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g },
  { kind: 'Twilio key', re: /\bSK[0-9a-f]{32}\b/g },
  { kind: 'Discord bot token', re: /\b[MN][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/g },
  { kind: 'JSON web token', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}/g },
  { kind: 'database URL with password', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:/@]+:[^\s@/]{6,}@/g },
];

/** `secret = value` style assignments whose value looks random (not a word or a placeholder). */
const ASSIGNMENT = /\b(?:[a-z0-9_]*?(?:secret|token|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth))["']?\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.]{20,})/gi;

const PLACEHOLDER = /EXAMPLE_[A-Z0-9_]*DO_NOT_USE|\b(?:x{6,}|\*{6,}|your[_-]|changeme|placeholder|redacted|<[^>]+>)/i;

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const MAX_HITS = 20;

export function findCredentials(text: string): SecretHit[] {
  const hits: SecretHit[] = [];
  const add = (kind: string, match: string): void => {
    if (hits.length >= MAX_HITS || PLACEHOLDER.test(match)) return;
    if (hits.some((h) => h.match === match)) return;
    hits.push({ kind, match });
  };
  for (const h of findSecrets(text)) add(h.pattern, h.match);
  for (const { kind, re } of PATTERNS) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) add(kind, m[0]);
  }
  ASSIGNMENT.lastIndex = 0;
  for (const m of text.matchAll(ASSIGNMENT)) {
    const value = m[1] ?? '';
    // Random-looking: mixed character classes and high entropy. Rules out
    // words, paths and repeated characters.
    const classes = [/[a-z]/, /[A-Z]/, /\d/].filter((r) => r.test(value)).length;
    if (classes >= 2 && entropy(value) >= 3.5) add('secret assignment', value);
  }
  return hits;
}

export const describeCredential = (h: SecretHit): string => `${h.kind}, ${redact(h.match)}`;
