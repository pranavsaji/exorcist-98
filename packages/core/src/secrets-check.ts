#!/usr/bin/env node
/**
 * secrets-check.ts
 *
 * Scans text (or staged files when --staged is passed) for real secret patterns.
 * Placeholder values matching EXAMPLE_*_DO_NOT_USE are always excluded.
 *
 * Exit 0 — no secrets found.
 * Exit 1 — one or more secrets found (file:line printed per hit).
 */

import { readFileSync, existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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

const PLACEHOLDER_RE = /EXAMPLE_[A-Z0-9_]*_DO_NOT_USE/;

/**
 * Pure function — scan `text` and return all secret hits that are not part of
 * a placeholder value.
 */
export function findSecrets(text: string): SecretHit[] {
  const hits: SecretHit[] = [];

  for (const { id, re } of PATTERNS) {
    // Reset lastIndex because the regex objects are module-level (shared)
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const offset = m.index;
      const matched = m[0];
      // Allow if the surrounding 40 chars contain a placeholder
      const surrounding = text.slice(
        Math.max(0, offset - 30),
        offset + matched.length + 30,
      );
      if (!PLACEHOLDER_RE.test(surrounding)) {
        hits.push({ pattern: id, offset, match: matched });
      }
    }
  }

  return hits;
}

// ── CLI entry point ───────────────────────────────────────────────────────────
// Only runs when this file is executed directly (not imported by tests).

import { resolve } from 'node:path';

const isMain =
  typeof process !== 'undefined' &&
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

function offsetToLineNumber(text: string, offset: number): number {
  return text.slice(0, offset).split('\n').length;
}

function scanFile(filePath: string): boolean {
  if (!existsSync(filePath)) return false;
  const text = readFileSync(filePath, 'utf8');
  const hits = findSecrets(text);
  for (const hit of hits) {
    const line = offsetToLineNumber(text, hit.offset);
    process.stdout.write(`${filePath}:${line} [${hit.pattern}] ${hit.match}\n`);
  }
  return hits.length > 0;
}

if (isMain) {
  const args = process.argv.slice(2);
  const stagedMode = args.includes('--staged');
  const explicitFiles = args.filter((a) => a !== '--staged');

  let filesToScan: string[] = explicitFiles;

  if (stagedMode) {
    try {
      const output = execSync('git diff --name-only --cached', { encoding: 'utf8' });
      const staged = output
        .split('\n')
        .map((f) => f.trim())
        .filter(Boolean);
      filesToScan = [...filesToScan, ...staged];
    } catch {
      // Not in a git repo or git not available — skip staged check silently
    }
  }

  let anyFound = false;
  for (const f of filesToScan) {
    if (scanFile(f)) anyFound = true;
  }

  process.exit(anyFound ? 1 : 0);
}
