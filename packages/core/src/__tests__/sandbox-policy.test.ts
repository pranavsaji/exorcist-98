import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sandboxFindings } from '../sandbox-policy.js';
import { scanRepo } from '../scanner/orchestrator.js';
import { hasPlainEntry } from '../plain.js';
import { fromRoot } from './repo-root.js';

const REL = '.kiro/settings/sandbox.json';

describe('CT-18: sandboxFindings', () => {
  it('CT-18: MCP sandboxing off fires, naming file, line and quoted span', () => {
    const text = '{\n  "enabled": true,\n  "mcpSandboxing": false\n}\n';
    const [f, ...rest] = sandboxFindings(text, REL);
    expect(rest).toHaveLength(0);
    expect(f).toMatchObject({ ruleId: 'EX-035', file: REL, line: 3, span: '"mcpSandboxing": false' });
    expect(text.includes(f!.span)).toBe(true);
    expect(f!.fix).toMatch(/can only tighten the global sandbox policy/);
  });
  it('CT-18: the whole sandbox off fires', () => {
    const [f] = sandboxFindings('{ "enabled": false }', REL);
    expect(f).toMatchObject({ ruleId: 'EX-035', line: 1, span: '"enabled": false' });
  });
  it('CT-18: sandboxing on, or the field absent, gives no finding', () => {
    expect(sandboxFindings('{"enabled":true,"mcpSandboxing":true}', REL)).toEqual([]);
    expect(sandboxFindings('{"enabled":true}', REL)).toEqual([]);
  });
  it('CT-18: severity is the lowest level and below the default gate threshold', () => {
    const [f] = sandboxFindings('{"enabled":true,"mcpSandboxing":false}', REL);
    expect(f!.severity).toBe('low');
  });
  it('CT-18: comments are allowed and a commented-out line does not count', () => {
    const text = '{\n  // "mcpSandboxing": false\n  "enabled": true, /* x */\n  "mcpSandboxing": true,\n}';
    expect(sandboxFindings(text, REL)).toEqual([]);
  });
  it('CT-18: bad JSON and other files give no finding', () => {
    expect(sandboxFindings('{"mcpSandboxing": false', REL)).toEqual([]);
    expect(sandboxFindings('{"mcpSandboxing": false}', '.kiro/settings/mcp.json')).toEqual([]);
  });
  it('CT-18: the rule has a plain-language entry', () => {
    expect(hasPlainEntry('EX-035')).toBe(true);
  });
  it('CT-18: a scan reports it for a committed sandbox file', async () => {
    const d = mkdtempSync(join(tmpdir(), 'exorcist-sandbox-'));
    try {
      mkdirSync(join(d, '.kiro/settings'), { recursive: true });
      writeFileSync(join(d, REL), '{\n  "enabled": true,\n  "mcpSandboxing": false\n}\n');
      const found: string[] = [];
      for await (const ev of scanRepo(d, { definitionsDir: fromRoot('definitions') })) if (ev.type === 'finding') found.push(`${ev.finding.ruleId}:${ev.finding.line}`);
      expect(found).toContain('EX-035:3');
    } finally { rmSync(d, { recursive: true, force: true }); }
  });
});

describe('CT-18: Property 8', () => {
  const field = fc.option(fc.boolean(), { nil: undefined });
  it('CT-18: Property 8: the sandbox info finding tracks exactly the MCP-sandboxing-off field', () => {
    // Validates: Requirements CT-18
    fc.assert(fc.property(field, field, fc.boolean(), (enabled, mcp, comments) => {
      const obj: Record<string, unknown> = { networkAccess: 'DEFAULT_BLOCKED' };
      if (enabled !== undefined) obj['enabled'] = enabled;
      if (mcp !== undefined) obj['mcpSandboxing'] = mcp;
      const json = JSON.stringify(obj, null, 2);
      const text = comments ? `// committed\n${json.replace(/\n}$/, ',\n}')}` : json;
      const out = sandboxFindings(text, REL);
      const off = mcp === false || enabled === false;
      expect(out.length).toBe(off ? 1 : 0);
      for (const f of out) {
        expect(f.severity).toBe('low');
        expect(text.split('\n')[f.line - 1]!.includes(f.span)).toBe(true);
      }
    }), { numRuns: 200 });
  });
});
