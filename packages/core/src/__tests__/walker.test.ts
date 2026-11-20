import { describe, it, expect } from 'vitest';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classifyFile, walkRepo } from '../walker.js';
import { fromRoot } from './repo-root.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = fromRoot('fixtures/haunted-repo');

describe('classifyFile', () => {
  it('README.md → instruction', () => expect(classifyFile('README.md')).toBe('instruction'));
  it('README.txt → instruction', () => expect(classifyFile('README.txt')).toBe('instruction'));
  it('.kiro/steering/product.md → instruction', () => expect(classifyFile('.kiro/steering/product.md')).toBe('instruction'));
  it('AGENTS.md → instruction', () => expect(classifyFile('AGENTS.md')).toBe('instruction'));
  it('.cursorrules → instruction', () => expect(classifyFile('.cursorrules')).toBe('instruction'));
  it('.kiro/settings/mcp.json → mcp-config', () => expect(classifyFile('.kiro/settings/mcp.json')).toBe('mcp-config'));
  it('.cursor/mcp.json → mcp-config', () => expect(classifyFile('.cursor/mcp.json')).toBe('mcp-config'));
  it('claude_desktop_config.json → mcp-config', () => expect(classifyFile('claude_desktop_config.json')).toBe('mcp-config'));
  it('.kiro/hooks/definition-save.yaml → hook', () => expect(classifyFile('.kiro/hooks/definition-save.yaml')).toBe('hook'));
  it('packages/core/package.json → manifest', () => expect(classifyFile('packages/core/package.json')).toBe('manifest'));
  it('definitions/EX-001.yaml → definition', () => expect(classifyFile('definitions/EX-001.yaml')).toBe('definition'));
  it('power/manifest.yaml → power', () => expect(classifyFile('power/manifest.yaml')).toBe('power'));
  it('docs/guide.md → docs', () => expect(classifyFile('docs/guide.md')).toBe('docs'));
  it('src/index.ts → code', () => expect(classifyFile('src/index.ts')).toBe('code'));
  it('src/app.py → code', () => expect(classifyFile('src/app.py')).toBe('code'));
  it('some.config.yaml → config', () => expect(classifyFile('some.config.yaml')).toBe('config'));
  it('random.bin → unknown', () => expect(classifyFile('random.bin')).toBe('unknown'));
});

describe('walkRepo', () => {
  it('yields at least 20 files from haunted-repo', async () => {
    const files = [];
    for await (const f of walkRepo(FIXTURE_DIR)) files.push(f);
    expect(files.length).toBeGreaterThanOrEqual(20);
  });

  it('no yielded file has a node_modules or .git segment', async () => {
    for await (const f of walkRepo(FIXTURE_DIR)) {
      expect(f.rel).not.toMatch(/node_modules/);
      expect(f.rel).not.toMatch(/\.git/);
    }
  });

  it('every yielded file has sizeBytes <= 1_048_576', async () => {
    for await (const f of walkRepo(FIXTURE_DIR)) {
      expect(f.sizeBytes).toBeLessThanOrEqual(1_048_576);
    }
  });

  it('every yielded file has a non-empty role', async () => {
    for await (const f of walkRepo(FIXTURE_DIR)) {
      expect(typeof f.role).toBe('string');
      expect(f.role.length).toBeGreaterThan(0);
    }
  });
});
