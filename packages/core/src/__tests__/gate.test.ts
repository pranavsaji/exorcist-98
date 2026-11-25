/** m10-kiro-gate requirements 1.2 to 1.5, 1.8 and 1.9: which findings a change adds. */
import { describe, it, expect, beforeAll } from 'vitest';
import { loadDefinitions } from '../definitions/loader.js';
import { gateFindings, gateRole, isBlocking, isGateFile, renderGate, tooLargeFinding } from '../gate.js';
import type { VirusDefinition } from '../definitions/schema.js';
import { fromRoot } from './repo-root.js';

let defs: VirusDefinition[] = [];
beforeAll(async () => { defs = await loadDefinitions(fromRoot('definitions')); });

/** Invisible Unicode tag characters spelling "NPQ": EX-001, critical. */
const HIDDEN = String.fromCodePoint(0xe0049, 0xe004e, 0xe0050);
const CLEAN = '# Steering\n\nUse tabs.\nRun the tests before you commit.\n';

describe('isGateFile (1.2)', () => {
  it.each([
    '.kiro/steering/product.md', '.kiro/specs/m1/design.md', '.kiro/hooks/a.json', '.kiro/agents/a.json',
    '.kiro/settings/mcp.json', '.cursor/mcp.json', 'AGENTS.md', 'CLAUDE.md', 'README.md', 'docs/README.md', 'power/skills/x/SKILL.md', '.cursor/rules/a.mdc',
  ])('%s is an agent-facing file', (rel) => { expect(isGateFile(rel)).toBe(true); });
  it.each(['src/index.ts', 'package-lock.json', 'docs/notes.md', 'image.png'])('%s is not', (rel) => { expect(isGateFile(rel)).toBe(false); });
  it('scans specs and agent definitions as instructions', () => {
    expect(gateRole('.kiro/specs/a/tasks.md')).toBe('instruction');
    expect(gateRole('.kiro/agents/a.json')).toBe('instruction');
  });
});

describe('gateFindings (1.3 to 1.5)', () => {
  it('passes a clean change', () => {
    expect(gateFindings('.kiro/steering/a.md', CLEAN, `${CLEAN}Prefer small functions.\n`, defs)).toEqual([]);
  });
  it('fails a change that adds hidden characters to a steering file', () => {
    const added = gateFindings('.kiro/steering/a.md', CLEAN, `${CLEAN}Be kind.${HIDDEN}\n`, defs);
    expect(added.some((f) => f.ruleId === 'EX-001' && isBlocking(f))).toBe(true);
    expect(added.find((f) => f.ruleId === 'EX-001')?.file).toBe('.kiro/steering/a.md');
  });
  it('ignores a finding the committed version already had, even when its line moves', () => {
    const old = `${CLEAN}Be kind.${HIDDEN}\n`;
    expect(gateFindings('.kiro/steering/a.md', old, `New first line.\n${old}Another line.\n`, defs)).toEqual([]);
  });
  it('counts a second copy of an old finding as added', () => {
    const old = `${CLEAN}Be kind.${HIDDEN}\n`;
    const added = gateFindings('.kiro/steering/a.md', old, `${old}Be kind.${HIDDEN}\n`, defs);
    expect(added.filter((f) => f.ruleId === 'EX-001')).toHaveLength(1);
  });
  it('treats every finding in a new file as added', () => {
    const added = gateFindings('AGENTS.md', null, `Hello.${HIDDEN}\n`, defs);
    expect(added.some((f) => f.ruleId === 'EX-001')).toBe(true);
  });
});

describe('isBlocking', () => {
  it('blocks high and critical by default, and follows the threshold', () => {
    expect(isBlocking({ severity: 'critical' })).toBe(true);
    expect(isBlocking({ severity: 'high' })).toBe(true);
    expect(isBlocking({ severity: 'medium' })).toBe(false);
    expect(isBlocking({ severity: 'medium' }, 'medium')).toBe(true);
    expect(isBlocking({ severity: 'high' }, 'critical')).toBe(false);
  });
});

describe('renderGate (1.3, 1.8)', () => {
  it('lists file, line, headline, rule id and fix, and shows hidden characters as markers', () => {
    const added = gateFindings('.kiro/steering/a.md', CLEAN, `${CLEAN}Be kind.${HIDDEN}\n`, defs);
    const text = renderGate(added);
    expect(text).toContain('.kiro/steering/a.md:');
    expect(text).toContain('EX-001');
    expect(text).toContain('This file hides instructions for your AI');
    expect(text).toContain('fix:');
    expect(text).not.toContain(HIDDEN);
    expect(text).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e]/);
  });
  it('never prints a secret in full', () => {
    const key = ['ghp', 'a7Xk2Q9rT4mZ8vB1nC6dF3hJ5LsW0pYe2Gu1'].join('_');
    const added = gateFindings('AGENTS.md', null, `GITHUB_TOKEN=${key}\n`, defs);
    expect(added.some((f) => f.ruleId === 'EX-011')).toBe(true);
    expect(renderGate(added)).not.toContain(key);
  });
});

describe('tooLargeFinding (1.9)', () => {
  it('reports an oversized agent file as EX-026 instead of treating it as clean', () => {
    const f = tooLargeFinding('AGENTS.md', 12 * 1_048_576, defs);
    expect(f?.ruleId).toBe('EX-026');
    expect(f?.span).toContain('12 MB');
  });
});
