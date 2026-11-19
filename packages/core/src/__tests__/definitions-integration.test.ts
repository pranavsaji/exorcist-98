import { describe, it, expect } from 'vitest';
import { resolve, dirname, join } from 'node:path';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadDefinitions } from '../definitions/loader.js';
import { runSignatures } from '../scanner/signature-engine.js';
import { normalize } from '../normalizer.js';
import type { RepoFile } from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFINITIONS_DIR = resolve(__dirname, '../../../../definitions');
const FIXTURE_DIR     = resolve(__dirname, '../../../../fixtures/haunted-repo');

// role map for each fixture by threat type
const ROLE_MAP: Record<string, RepoFile['role']> = {
  'EX-001': 'docs',
  'EX-002': 'docs',
  'EX-003': 'docs',
  'EX-004': 'docs',
  'EX-005': 'config',
  'EX-006': 'config',
  'EX-007': 'config',
  'EX-008': 'hook',
  'EX-009': 'manifest',
  'EX-010': 'config',
  'EX-011': 'unknown',
  'EX-012': 'docs',
  'EX-015': 'tool-result',
};

describe('INT-DEF: each definition fires on its haunted-repo fixture', () => {
  const fixtureEntries = readdirSync(FIXTURE_DIR)
    .filter(f => /^EX-\d{3}-/.test(f))
    .map(f => ({ name: f, id: f.slice(0, 6), path: join(FIXTURE_DIR, f) }));

  for (const { name, id, path } of fixtureEntries) {
    // Only test EX-001 through EX-012 (definitions built in M1)
    const num = parseInt(id.replace('EX-', ''), 10);
    if (!(num >= 1 && num <= 12) && num !== 15) continue;

    it(`${id} fires on ${name}`, async () => {
      const defs = await loadDefinitions(DEFINITIONS_DIR);
      const def  = defs.find(d => d.id === id);
      expect(def, `No definition found for ${id}`).toBeDefined();
      if (!def) return;

      const text = readFileSync(path, 'utf8');
      const role = ROLE_MAP[id] ?? 'docs';
      const file: RepoFile = { path, rel: name, role, sizeBytes: text.length };
      const norm = normalize(text, role);

      const findings = runSignatures(file, norm, [def]);
      expect(
        findings.length,
        `Expected at least one finding for ${id} on ${name}, got 0.\nFile content (first 300 chars):\n${text.slice(0,300)}`
      ).toBeGreaterThan(0);
      expect(findings[0]?.ruleId).toBe(id);
    });
  }
});
