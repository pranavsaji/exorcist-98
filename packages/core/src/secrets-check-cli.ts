#!/usr/bin/env node
/**
 * Command line for the secrets check.
 *
 *   tsx packages/core/src/secrets-check-cli.ts --staged
 *   tsx packages/core/src/secrets-check-cli.ts <file>...
 *
 * Exit 0: nothing found. 1: something found (file:line, redacted).
 * 2: the staged files could not be read (treated as a failure, not a pass).
 */
import { readFileSync } from 'node:fs';
import { findSecrets, findStagedSecrets, lineOf, redact } from './secrets-check.js';

const args = process.argv.slice(2);
const files = args.filter((a) => a !== '--staged');
let found = false;

if (args.includes('--staged')) {
  const r = findStagedSecrets();
  if (!r.ok) {
    process.stderr.write(`${r.error}\n`);
    process.exit(2);
  }
  for (const h of r.hits) {
    process.stdout.write(`${h.file}:${h.line} [${h.pattern}] ${h.redacted}\n`);
    found = true;
  }
}
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  for (const h of findSecrets(text)) {
    process.stdout.write(`${f}:${lineOf(text, h.offset)} [${h.pattern}] ${redact(h.match)}\n`);
    found = true;
  }
}
process.exit(found ? 1 : 0);
