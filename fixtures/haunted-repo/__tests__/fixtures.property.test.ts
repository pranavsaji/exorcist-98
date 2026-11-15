import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(__dirname, '..');

// Collect every EX-NNN-* file (excluding README, vitest config, and this test)
const fixtureFiles = readdirSync(fixtureDir)
  .filter(f => /^EX-\d{3}-/.test(f))
  .map(f => join(fixtureDir, f));

// All 20 expected IDs
const EXPECTED_IDS = [
  'EX-001', 'EX-002', 'EX-003', 'EX-004', 'EX-005',
  'EX-006', 'EX-007', 'EX-008', 'EX-009', 'EX-010',
  'EX-011', 'EX-012', 'EX-013', 'EX-014', 'EX-015',
  'EX-016', 'EX-017', 'EX-018', 'EX-019', 'EX-020',
];

// A URL starting with http(s):// whose host is NOT one of the allowed safe values.
// Allowed: example.invalid (any subdomain), localhost, 127.0.0.1, 0.0.0.0
const LIVE_DOMAIN_RE =
  /https?:\/\/(?!(?:[\w-]+\.)*example\.invalid|localhost|127\.0\.0\.1|0\.0\.0\.0)[\w.-]+/i;

// Real secret patterns (not wrapped in EXAMPLE_.*_DO_NOT_USE)
const AWS_KEY_RE = /AKIA[0-9A-Z]{16}/;
const GITHUB_TOKEN_RE = /gh[ps]_[A-Za-z0-9]{36}/;
const OPENAI_KEY_RE = /sk-[A-Za-z0-9]{48}/;
const PLACEHOLDER_RE = /EXAMPLE_[A-Z0-9_]*_DO_NOT_USE/;

function containsUnwrappedSecret(text: string): boolean {
  for (const re of [AWS_KEY_RE, GITHUB_TOKEN_RE, OPENAI_KEY_RE]) {
    const match = text.match(re);
    if (match) {
      // Allow if the matching region is part of a placeholder
      const start = text.indexOf(match[0]);
      const surrounding = text.slice(Math.max(0, start - 30), start + match[0].length + 30);
      if (!PLACEHOLDER_RE.test(surrounding)) {
        return true;
      }
    }
  }
  return false;
}

describe('Haunted Repo fixture safety (property-based)', () => {
  // PBT-FIX-01: no fixture contains a live domain
  it('PBT-FIX-01: no fixture file contains a reachable domain', () => {
    fc.assert(
      fc.property(fc.constantFrom(...fixtureFiles), (file) => {
        const text = readFileSync(file, 'utf8');
        const match = text.match(LIVE_DOMAIN_RE);
        if (match) {
          throw new Error(`${file} contains a live domain: ${match[0]}`);
        }
        return true;
      }),
      { numRuns: fixtureFiles.length },
    );
  });

  // PBT-FIX-02: no fixture contains an unwrapped real secret pattern
  it('PBT-FIX-02: no fixture contains a real secret pattern outside EXAMPLE_*_DO_NOT_USE', () => {
    fc.assert(
      fc.property(fc.constantFrom(...fixtureFiles), (file) => {
        const text = readFileSync(file, 'utf8');
        if (containsUnwrappedSecret(text)) {
          throw new Error(`${file} contains an unwrapped secret pattern`);
        }
        return true;
      }),
      { numRuns: fixtureFiles.length },
    );
  });

  // PBT-FIX-03: every fixture contains the literal string DEFANGED
  it('PBT-FIX-03: every fixture file contains the string DEFANGED', () => {
    fc.assert(
      fc.property(fc.constantFrom(...fixtureFiles), (file) => {
        const text = readFileSync(file, 'utf8');
        if (!text.includes('DEFANGED')) {
          throw new Error(`${file} is missing the DEFANGED marker`);
        }
        return true;
      }),
      { numRuns: fixtureFiles.length },
    );
  });

  // PBT-FIX-04: a file for each expected EX-NNN ID exists on disk
  it('PBT-FIX-04: every EX-NNN threat ID has a fixture file on disk', () => {
    fc.assert(
      fc.property(fc.constantFrom(...EXPECTED_IDS), (id) => {
        const exists = fixtureFiles.some(f => f.includes(`/${id}-`));
        if (!exists) {
          throw new Error(`No fixture file found for ${id}`);
        }
        return true;
      }),
      { numRuns: EXPECTED_IDS.length },
    );
  });
});
