import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classifyFile, walkRepo } from '../walker.js';
import type { FileRole } from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = resolve(__dirname, '../../../../fixtures/haunted-repo');

const ALL_ROLES: FileRole[] = [
  'instruction','mcp-config','hook','manifest','definition',
  'memory','power','docs','code','config','unknown',
];

// Collect all yielded files from haunted-repo once (shared across PBTs)
async function collectFixtureFiles() {
  const files = [];
  for await (const f of walkRepo(FIXTURE_DIR)) files.push(f);
  return files;
}

describe('Walker property-based tests', () => {
  // PBT-WLK-01: every yielded file has sizeBytes <= 1 MB
  it('PBT-WLK-01: every file yielded from haunted-repo is <= 1 MB', async () => {
    const files = await collectFixtureFiles();
    fc.assert(
      fc.property(fc.constantFrom(...files), (f) => {
        expect(f.sizeBytes).toBeLessThanOrEqual(1_048_576);
        return true;
      }),
      { numRuns: files.length },
    );
  });

  // PBT-WLK-02: no yielded path contains node_modules or .git
  it('PBT-WLK-02: no yielded path contains node_modules or .git', async () => {
    const files = await collectFixtureFiles();
    fc.assert(
      fc.property(fc.constantFrom(...files), (f) => {
        expect(f.rel).not.toMatch(/node_modules/);
        expect(f.rel).not.toMatch(/\.git/);
        return true;
      }),
      { numRuns: files.length },
    );
  });

  // PBT-WLK-03: classifyFile is pure — same input always returns same role
  it('PBT-WLK-03: classifyFile is pure (same input → same output)', () => {
    const samplePaths = [
      'README.md', '.kiro/settings/mcp.json', 'package.json',
      '.kiro/hooks/x.yaml', 'definitions/EX-001.yaml', 'power/x.yaml',
      'docs/guide.md', 'src/index.ts', 'config.json', 'binary.bin',
    ];
    fc.assert(
      fc.property(fc.constantFrom(...samplePaths), (path) => {
        expect(classifyFile(path)).toBe(classifyFile(path));
        return true;
      }),
      { numRuns: samplePaths.length },
    );
  });

  // PBT-WLK-04: every FileRole value is a non-empty string
  it('PBT-WLK-04: every FileRole value is a non-empty string', () => {
    fc.assert(
      fc.property(fc.constantFrom(...ALL_ROLES), (role) => {
        expect(typeof role).toBe('string');
        expect(role.length).toBeGreaterThan(0);
        return true;
      }),
      { numRuns: ALL_ROLES.length },
    );
  });
});
