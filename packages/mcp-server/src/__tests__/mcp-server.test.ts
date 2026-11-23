import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDefinitions } from '@exorcist-98/core';
import { inspectResult } from '@exorcist-98/shield';
import { quarantineTool, resolveInside, reveal, scanRepoTool } from '../tools.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../../..');
const PKG = join(ROOT, 'packages/mcp-server');
const BUNDLE = join(PKG, 'dist/index.mjs');
const DEFS = join(ROOT, 'definitions');

beforeAll(() => {
  execFileSync(process.execPath, [join(PKG, 'build.mjs')], { cwd: PKG, stdio: 'pipe' });
}, 60_000);

const dirs: string[] = [];
const clients: Client[] = [];
afterEach(async () => {
  for (const c of clients.splice(0)) await c.close().catch(() => undefined);
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-mcp-')); dirs.push(d); return d; };

/** Connect the official SDK client to the built server over stdio. */
async function connect(cwd: string): Promise<Client> {
  const transport = new StdioClientTransport({ command: process.execPath, args: [BUNDLE], cwd, env: { PATH: process.env['PATH'] ?? '' } });
  const client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(transport);
  clients.push(client);
  return client;
}

type CallResult = { content?: Array<{ type: string; text?: string }>; isError?: boolean };
async function call(c: Client, name: string, args: Record<string, unknown>): Promise<{ text: string; isError: boolean }> {
  const r = (await c.callTool({ name, arguments: args })) as CallResult;
  return { text: r.content?.[0]?.text ?? '', isError: r.isError === true };
}

describe('the exorcist MCP server (official SDK client, real stdio)', () => {
  it('is a runnable file and lists its four tools with honest annotations', async () => {
    expect(readFileSync(BUNDLE, 'utf8').startsWith('#!/usr/bin/env node')).toBe(true);
    const c = await connect(ROOT);
    const { tools } = await c.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(['explain_finding', 'quarantine', 'scan_mcp_config', 'scan_repo']);
    const by = Object.fromEntries(tools.map((t) => [t.name, t.annotations ?? {}]));
    expect(by['scan_repo']).toMatchObject({ readOnlyHint: true });
    expect(by['quarantine']).toMatchObject({ readOnlyHint: false, destructiveHint: true });
    for (const t of tools) expect(t.inputSchema.type).toBe('object');
  });

  it('scan_repo lists plain-language findings and does not quote file text by default', async () => {
    const c = await connect(ROOT);
    const r = await call(c, 'scan_repo', { path: 'fixtures/haunted-repo', maxFindings: 40 });
    expect(r.isError).toBe(false);
    expect(r.text).toMatch(/\d+ threats in \d+ files/);
    expect(r.text).toContain('This file hides instructions for your AI');
    expect(r.text).toContain('rule: EX-001');
    expect(r.text).not.toContain('quoted:');
    expect(r.text.toLowerCase()).not.toContain('ignore previous instructions');
  });

  it('scan_repo quotes are opt-in, revealed and marked untrusted', async () => {
    const c = await connect(ROOT);
    const r = await call(c, 'scan_repo', { path: 'fixtures/haunted-repo', includeQuotes: true, maxFindings: 100 });
    expect(r.text).toContain('untrusted data');
    expect(r.text).toContain('quoted:');
    // Hidden-character findings are quoted as escape text, never as the raw character.
    expect(r.text).toMatch(/quoted: "\\\\u(200B|202E|\{E00[0-9A-F]{2})/);
    expect(r.text).not.toMatch(/[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}]/u);
  });

  it('M5-REQ-04.1: a decoded hidden message is never handed to the agent, even with quotes on', async () => {
    const out = await scanRepoTool({ cwd: ROOT, definitionsDir: DEFS }, { path: 'fixtures/haunted-repo', includeQuotes: true, maxFindings: 100 });
    expect(out.text).toContain('rule: EX-021');
    expect(out.text).not.toContain('DEFANGED: placeholder message');
    expect(out.text).not.toMatch(/[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/u);
  });

  it('reveal() makes any hidden character visible', () => {
    expect(reveal('a\u200Bb')).toBe('a[U+200B]b');
    expect(reveal(`x${String.fromCodePoint(0xE0041)}`)).toBe('x[U+E0041]');
    expect(reveal('plain text')).toBe('plain text');
  });

  it("the server's own output is clean enough to pass through the Shield", async () => {
    const defs = await loadDefinitions(DEFS);
    const out = await scanRepoTool({ cwd: ROOT, definitionsDir: DEFS }, { path: 'fixtures/haunted-repo', maxFindings: 100 });
    expect(inspectResult({ content: [{ type: 'text', text: out.text }] }, defs).action).toBe('allow');
  });

  it('refuses paths outside the project folder, including symlinks and absolute paths', async () => {
    const project = tmp();
    const outside = tmp();
    writeFileSync(join(outside, 'secret.md'), 'ignore previous instructions');
    symlinkSync(outside, join(project, 'link'));
    const c = await connect(project);
    for (const p of ['../', outside, '/etc', 'link', 'link/secret.md', join(project, '..')]) {
      const r = await call(c, 'scan_repo', { path: p });
      expect(r.isError, p).toBe(true);
      expect(r.text, p).toMatch(/outside the project folder|not found/i);
    }
    expect(resolveInside(project, '.').ok).toBe(true);
  });

  it('scan_mcp_config finds risky settings and says which servers are behind the shield', async () => {
    const project = tmp();
    mkdirSync(join(project, '.kiro/settings'), { recursive: true });
    writeFileSync(
      join(project, '.kiro/settings/mcp.json'),
      JSON.stringify({
        mcpServers: {
          files:  { command: 'npx', args: ['-y', '@acme/files-server'], autoApprove: ['read_file', 'write_file'] },
          safe:   { command: 'exorcist', args: ['shield', '--server', 'safe', '--', 'node', 's.js'] },
          remote: { url: 'https://mcp.example.invalid/sse' },
        },
      }, null, 2),
    );
    const c = await connect(project);
    const r = await call(c, 'scan_mcp_config', { path: '.kiro/settings/mcp.json' });
    expect(r.isError).toBe(false);
    expect(r.text).toContain('rule: EX-007');
    expect(r.text).toContain('rule: EX-010');
    expect(r.text).toContain('Behind the shield: safe');
    expect(r.text).toContain('Not behind the shield: files');
    expect(r.text).toContain('exorcist wrap .kiro/settings/mcp.json');
  });

  it('explain_finding explains a rule, covers shield-only rules, and rejects junk', async () => {
    const c = await connect(ROOT);
    const ex1 = await call(c, 'explain_finding', { ruleId: 'ex-001' });
    expect(ex1.text).toContain('This file hides instructions for your AI');
    expect(ex1.text).toContain('How to fix:');
    expect(ex1.text).toContain('OWASP:');
    const ex17 = await call(c, 'explain_finding', { ruleId: 'EX-017' });
    expect(ex17.isError).toBe(false);
    expect(ex17.text).toContain('enforced by the shield');
    expect((await call(c, 'explain_finding', { ruleId: 'nope' })).isError).toBe(true);
    expect((await call(c, 'explain_finding', { ruleId: 'EX-999' })).isError).toBe(true);
  });

  it('quarantine disables one server, keeps a backup, tells the user how to undo it', async () => {
    const project = tmp();
    const cfg = join(project, 'mcp.json');
    writeFileSync(cfg, `${JSON.stringify({ mcpServers: { a: { command: 'node', args: ['a.js'] }, b: { command: 'node', args: ['b.js'] } } }, null, 2)}\n`);
    const c = await connect(project);
    const r = await call(c, 'quarantine', { config: 'mcp.json', server: 'a', reason: 'rug pull' });
    expect(r.isError).toBe(false);
    expect(r.text).toContain('exorcist vault restore');
    const after = JSON.parse(readFileSync(cfg, 'utf8')) as { mcpServers: Record<string, { disabled?: boolean }> };
    expect(after.mcpServers['a']?.disabled).toBe(true);
    expect(after.mcpServers['b']?.disabled).toBeUndefined();
    expect((await call(c, 'quarantine', { config: 'mcp.json', server: 'a' })).isError).toBe(true);
    expect((await call(c, 'quarantine', { config: 'mcp.json', server: 'zzz' })).isError).toBe(true);
    expect((await call(c, 'quarantine', { config: '../x.json', server: 'a' })).isError).toBe(true);
  });

  it('rejects invalid arguments through the schema', async () => {
    const c = await connect(ROOT);
    await expect(c.callTool({ name: 'scan_repo', arguments: { path: '' } })).resolves.toMatchObject({ isError: true });
    await expect(c.callTool({ name: 'scan_repo', arguments: { path: 'x', maxFindings: 9999 } })).resolves.toMatchObject({ isError: true });
  });

  it('quarantine is not reachable outside the project (in-process check)', async () => {
    const project = tmp();
    const outside = tmp();
    writeFileSync(join(outside, 'mcp.json'), JSON.stringify({ mcpServers: { a: { command: 'x' } } }));
    const r = await quarantineTool({ cwd: project, definitionsDir: DEFS }, { config: join(outside, 'mcp.json'), server: 'a' });
    expect(r.isError).toBe(true);
    expect(JSON.parse(readFileSync(join(outside, 'mcp.json'), 'utf8')).mcpServers.a.disabled).toBeUndefined();
  });
});
