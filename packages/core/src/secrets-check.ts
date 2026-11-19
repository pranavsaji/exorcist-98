/**
 * secrets-check.ts
 *
 * Finds real-looking secrets in text and in staged git files. Placeholder
 * values (EXAMPLE_*_DO_NOT_USE) are never flagged, but a real key written next
 * to a placeholder still is.
 *
 * Library code only. The command-line entry point is secrets-check-cli.ts;
 * keeping it separate means bundling this module can never run a CLI.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';

export type SecretPattern = 'aws-access-key' | 'github-token' | 'openai-key';

export interface SecretHit {
  pattern: SecretPattern;
  offset: number;
  match: string;
}

const PATTERNS: Array<{ id: SecretPattern; re: RegExp }> = [
  { id: 'aws-access-key', re: /AKIA[0-9A-Z]{16}/g },
  { id: 'github-token',   re: /gh[ps]_[A-Za-z0-9]{36}/g },
  { id: 'openai-key',     re: /sk-[A-Za-z0-9]{48}/g },
];

const PLACEHOLDER_RE = /EXAMPLE_[A-Z0-9_]*_DO_NOT_USE/g;

function placeholderRanges(text: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  PLACEHOLDER_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = PLACEHOLDER_RE.exec(text)) !== null) {
    ranges.push([m.index, m.index + m[0].length]);
  }
  return ranges;
}

/**
 * Pure function: all secret-shaped matches in `text`, except those that sit
 * inside a EXAMPLE_*_DO_NOT_USE placeholder token.
 */
export function findSecrets(text: string): SecretHit[] {
  const ranges = placeholderRanges(text);
  const hits: SecretHit[] = [];

  for (const { id, re } of PATTERNS) {
    re.lastIndex = 0; // the regexes are shared, module-level objects
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const start = m.index;
      const end = start + m[0].length;
      const inPlaceholder = ranges.some(([a, b]) => start >= a && end <= b);
      if (!inPlaceholder) hits.push({ pattern: id, offset: start, match: m[0] });
    }
  }
  return hits.sort((a, b) => a.offset - b.offset);
}

/** First four characters then asterisks, so logs never contain a full secret. */
export function redact(secret: string): string {
  return `${secret.slice(0, 4)}${'*'.repeat(Math.max(4, secret.length - 4))}`;
}

export function lineOf(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

export type StagedHit = { file: string; line: number; pattern: SecretPattern; redacted: string };
export type StagedResult =
  | { ok: true; hits: StagedHit[]; filesChecked: number }
  | { ok: false; error: string };

const MAX_BYTES = 1_048_576;

/**
 * Scan the files staged in the git repository that contains `cwd`. Paths from
 * git are relative to the repository root, so they are resolved against the
 * root (not against `cwd`).
 */
export function findStagedSecrets(cwd: string = process.cwd()): StagedResult {
  let root: string;
  let names: string[];
  try {
    root = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd, encoding: 'utf8' }).trim();
    const out = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'], {
      cwd: root,
      encoding: 'utf8',
    });
    names = out.split('\0').filter(Boolean);
  } catch (err) {
    return { ok: false, error: `Could not read the staged files: ${String(err).split('\n')[0]}` };
  }

  const hits: StagedHit[] = [];
  let filesChecked = 0;
  for (const name of names) {
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
    filesChecked++;
    for (const h of findSecrets(text)) {
      hits.push({ file: name, line: lineOf(text, h.offset), pattern: h.pattern, redacted: redact(h.match) });
    }
  }
  return { ok: true, hits, filesChecked };
}
