import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join, resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { loadDefinitions } from '../loader.js';
import { DefinitionLoadError } from '../schema.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// Navigate from packages/core/src/definitions/__tests__ → repo root → definitions/
const DEFINITIONS_DIR = resolve(__dirname, '../../../../../definitions');

const VALID_YAML = `
id: EX-001
title: Hidden Unicode instructions
severity: critical
applies_to:
  - instruction
match:
  regex: "\\\\u200B"
owasp:
  - "LLM01:2025 Prompt Injection"
fix: Remove hidden characters.
`.trim();

const MISSING_ID_YAML = `
title: No id here
severity: high
applies_to:
  - docs
match:
  regex: foo
owasp:
  - "LLM01"
fix: Fix it.
`.trim();

const INVALID_SEVERITY_YAML = `
id: EX-002
title: Bad severity
severity: extreme
applies_to:
  - docs
match:
  regex: foo
owasp:
  - "LLM01"
fix: Fix it.
`.trim();

let tmpDir: string | null = null;

afterEach(async () => {
  if (tmpDir) {
    await rm(tmpDir, { recursive: true, force: true });
    tmpDir = null;
  }
});

async function makeTmpDir(files: Record<string, string>): Promise<string> {
  tmpDir = await mkdtemp(join(tmpdir(), 'exorcist-test-'));
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(tmpDir, name), content, 'utf8');
  }
  return tmpDir;
}

describe('loadDefinitions', () => {
  it('loading a valid YAML file returns the correct typed object', async () => {
    const dir = await makeTmpDir({ 'EX-001.yaml': VALID_YAML });
    const defs = await loadDefinitions(dir);
    expect(defs).toHaveLength(1);
    const def = defs[0];
    expect(def).toBeDefined();
    if (!def) throw new Error('no def');
    expect(def.id).toBe('EX-001');
    expect(def.title).toBe('Hidden Unicode instructions');
    expect(def.severity).toBe('critical');
    expect(def.enabled).toBe(true); // default applied
  });

  it('a YAML file missing id throws DefinitionLoadError', async () => {
    const dir = await makeTmpDir({ 'bad.yaml': MISSING_ID_YAML });
    await expect(loadDefinitions(dir)).rejects.toBeInstanceOf(DefinitionLoadError);
  });

  it('a YAML file with an invalid severity value throws DefinitionLoadError', async () => {
    const dir = await makeTmpDir({ 'bad.yaml': INVALID_SEVERITY_YAML });
    const err = await loadDefinitions(dir).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DefinitionLoadError);
    if (err instanceof DefinitionLoadError) {
      expect(err.issues.length).toBeGreaterThan(0);
    }
  });

  it('loading the real definitions/ directory succeeds and includes EX-001', async () => {
    const defs = await loadDefinitions(DEFINITIONS_DIR);
    expect(defs.length).toBeGreaterThanOrEqual(1);
    const ex001 = defs.find((d) => d.id === 'EX-001');
    expect(ex001).toBeDefined();
    expect(ex001?.severity).toBe('critical');
  });
});
