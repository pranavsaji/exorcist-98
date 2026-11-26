/**
 * m13-kiro-evidence: the two Kiro skills and the red-team agent's skill resources
 * (format: kiro.dev/docs/skills and custom-agents/configuration-reference).
 */
import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const SKILLS = ['add-virus-definition', 'triage-finding'] as const;

function skill(name: string): { fm: Record<string, string>; body: string } {
  const text = readFileSync(join(ROOT, '.kiro/skills', name, 'SKILL.md'), 'utf8');
  const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text);
  if (m === null) throw new Error(`${name}: no front matter`);
  const fm: Record<string, string> = {};
  for (const line of (m[1] ?? '').split('\n')) {
    const kv = /^([a-z]+):\s*(.*)$/.exec(line);
    if (kv !== null) fm[kv[1] ?? ''] = kv[2] ?? '';
  }
  return { fm, body: m[2] ?? '' };
}

describe('.kiro/skills', () => {
  it.each(SKILLS)('KE-31 KE-32: %s has valid front matter (name equals folder, description within 1024 chars)', (name) => {
    const { fm } = skill(name);
    expect(fm['name']).toBe(name);
    expect(fm['name']).toMatch(/^[a-z0-9-]{1,64}$/);
    expect((fm['description'] ?? '').length).toBeGreaterThan(20);
    expect((fm['description'] ?? '').length).toBeLessThanOrEqual(1024);
    expect(fm['description']).toMatch(/Use when/);
  });

  it('KE-31: add-virus-definition has the rule, test, benchmark, docs and facts steps with the real paths', () => {
    const { body } = skill('add-virus-definition');
    for (const h of ['## Step 1. Write the rule YAML', '## Step 2. Add a unit test', '## Step 3. Add a benchmark attack and a benign look-alike', '## Step 4. Update the docs', '## Step 5. Refresh the facts']) {
      expect(body).toContain(h);
    }
    for (const p of ['definitions/', 'fixtures/benchmark/labels.json', 'docs/THREATS.md', 'scripts/facts.mjs', '.invalid', 'EXAMPLE_TOKEN_DO_NOT_USE']) expect(body).toContain(p);
    for (const p of ['fixtures/benchmark/labels.json', 'docs/THREATS.md', 'scripts/facts.mjs', 'packages/core/src/__tests__/definitions-accuracy.test.ts', 'packages/core/src/__tests__/benchmark.test.ts']) {
      expect(existsSync(join(ROOT, p)), p).toBe(true);
    }
  });

  it('KE-32: triage-finding has the verdict and suppression steps covering inline, ignore file and baseline', () => {
    const { body } = skill('triage-finding');
    for (const h of ['## Step 2. Decide true or false positive', '## Step 3. Suppress with a reason', '## Step 4. Verify']) expect(body).toContain(h);
    for (const s of ['exorcist-ignore EX-NNN: reason', '.exorcistignore', 'exorcist baseline', '--baseline .exorcist-baseline.json', 'EX-001', 'EX-011']) expect(body).toContain(s);
  });

  it('KE-31 KE-32: no real secret shapes or PEM headers in the skills', () => {
    for (const name of SKILLS) {
      const text = readFileSync(join(ROOT, '.kiro/skills', name, 'SKILL.md'), 'utf8');
      // The PEM marker is assembled at run time so this file does not contain it (no-private-keys.test.ts).
      expect(text).not.toMatch(new RegExp(`-----BEGIN [A-Z ]*${['PRIVATE', 'KEY'].join(' ')}-----`));
      expect(text).not.toMatch(/\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,})\b/);
    }
  });
});

describe('exorcist-red-team resources', () => {
  it('KE-33: lists a skill:// URI for each skill, and each URI resolves to an existing SKILL.md', () => {
    const a = JSON.parse(readFileSync(join(ROOT, '.kiro/agents/exorcist-red-team.json'), 'utf8')) as { resources?: string[] };
    expect(a.resources).toBeDefined();
    for (const name of SKILLS) {
      const uri = `skill://.kiro/skills/${name}/SKILL.md`;
      expect(a.resources).toContain(uri);
      expect(existsSync(join(ROOT, uri.slice('skill://'.length)))).toBe(true);
    }
    for (const r of a.resources ?? []) expect(r.startsWith('skill://') || r.startsWith('file://')).toBe(true);
  });
});
