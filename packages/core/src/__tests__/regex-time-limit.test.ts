import { describe, expect, it } from 'vitest';
import { runSignatures } from '../scanner/signature-engine.js';
import { normalize } from '../normalizer.js';
import { VirusDefinitionSchema } from '../definitions/schema.js';
import type { RepoFile } from '../types.js';

const def = (id: string, regex: string) => VirusDefinitionSchema.parse({
  id, title: id, severity: 'high', applies_to: ['docs'], match: { regex }, owasp: ['x'], fix: 'Fix it.',
});
const file: RepoFile = { path: '/x/a.md', rel: 'a.md', role: 'docs', sizeBytes: 0 };

describe('L-004: rule regexes have a time limit', () => {
  it('stops a catastrophic regex, reports it, and keeps the other rules', () => {
    const text = `${'a'.repeat(40)}! and ignore this`;
    const t0 = Date.now();
    const out = runSignatures(file, normalize(text, 'docs'), [def('EX-901', '(a+)+$'), def('EX-902', 'ignore')], 300);
    expect(Date.now() - t0).toBeLessThan(3000);
    expect(out).toContainEqual(expect.objectContaining({ ruleId: 'EX-901', severity: 'medium', span: 'EX-901 ran out of time on this file' }));
    expect(out).toContainEqual(expect.objectContaining({ ruleId: 'EX-902', span: 'ignore' }));
  });
  it('gives the same results as before on ordinary text', () => {
    const out = runSignatures(file, normalize('one ignore two ignore', 'docs'), [def('EX-902', 'ignore')]);
    expect(out.map((f) => f.col)).toEqual([5, 16]);
  });
});

describe('L-010: positions are right after HTML entities', () => {
  it('reports the column in the original file, not in the decoded text', () => {
    const text = 'a &amp; b &lt;tag&gt; then ignore this';
    const [f] = runSignatures(file, normalize(text, 'docs'), [def('EX-902', 'ignore')]);
    expect(f?.col).toBe(text.indexOf('ignore') + 1);
  });
  it('still matches text that only exists after decoding', () => {
    const [f] = runSignatures(file, normalize('x\n&#105;gnore', 'docs'), [def('EX-902', 'ignore')]);
    expect(f).toMatchObject({ line: 2, col: 1 });
  });
});


import { packageArg } from '../scanner/signature-engine.js';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDefinitions } from '../definitions/loader.js';

const DEFS = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../definitions');

describe('L-012: the package a runner runs', () => {
  it('skips flags and reads --package, -p and --from', () => {
    expect(packageArg(['-y', '@scope/pkg@1.0.0', '/path'])).toBe('@scope/pkg@1.0.0');
    expect(packageArg(['--yes', '--quiet', 'pkg'])).toBe('pkg');
    expect(packageArg(['--package', '@a/b', 'cmd'])).toBe('@a/b');
    expect(packageArg(['-p', 'x'])).toBe('x');
    expect(packageArg(['--from=mcp-server-git', 'mcp-server-git'])).toBe('mcp-server-git');
    expect(packageArg(['-y'])).toBeNull();
  });
  it('EX-010 finds an unpinned package after flags, and ignores a later bare word', async () => {
    const defs = (await loadDefinitions(DEFS)).filter((d) => d.id === 'EX-010');
    const cfg = (args: string[]) => JSON.stringify({ mcpServers: { s: { command: 'npx', args } } }, null, 2);
    const mcp: RepoFile = { path: '/x/.vscode/mcp.json', rel: '.vscode/mcp.json', role: 'mcp-config', sizeBytes: 0 };
    const run = (args: string[]) => runSignatures(mcp, normalize(cfg(args), 'mcp-config'), defs);
    expect(run(['--yes', '--quiet', '@scope/server'])).toHaveLength(1);
    expect(run(['-y', '@scope/server@1.2.3', 'stdio'])).toHaveLength(0);
  });
});

describe('L-011: a repeated JSON value points at each of its places', () => {
  it('reports the second occurrence on its own line', async () => {
    const defs = (await loadDefinitions(DEFS)).filter((d) => d.id === 'EX-010');
    const text = JSON.stringify({ mcpServers: { a: { command: 'npx', args: ['-y', 'same-server'] }, b: { command: 'npx', args: ['-y', 'same-server'] } } }, null, 2);
    const mcp: RepoFile = { path: '/x/mcp.json', rel: 'mcp.json', role: 'mcp-config', sizeBytes: 0 };
    const lines = runSignatures(mcp, normalize(text, 'mcp-config'), defs).map((f) => f.line);
    const expected = text.split('\n').map((l, i) => (l.includes('"same-server"') ? i + 1 : 0)).filter(Boolean);
    expect(lines).toEqual(expected);
  });
});
