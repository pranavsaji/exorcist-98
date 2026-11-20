// The Real-Time Shield with the official MCP SDK client, over real stdio:
// S-004 (the user is asked through elicitation) and S-006 (review before a
// tool is trusted). Runs the CLI from source, so it does not race the build.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ElicitRequestSchema, ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';

const ROOT = resolve(import.meta.dirname, '../../../..');
const TSX = join(ROOT, 'node_modules/.bin/tsx');
const CLI = join(ROOT, 'packages/cli/src/index.ts');
const FAKE = join(ROOT, 'packages/shield/src/__tests__/fake-mcp-server.mjs');
const DEFS = join(ROOT, 'definitions');

const dirs: string[] = [];
const clients: Client[] = [];
afterEach(async () => {
  for (const c of clients.splice(0)) await c.close().catch(() => {});
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

async function connect(opts: { policy?: object; answer?: (msg: string) => { action: 'accept' | 'decline' | 'cancel'; content?: Record<string, unknown> } }) {
  const root = mkdtempSync(join(tmpdir(), 'x98-shield-sdk-'));
  dirs.push(root);
  const dir = join(root, '.exorcist');
  const log = join(root, 'calls.log');
  writeFileSync(log, '');
  if (opts.policy) {
    spawnSync('mkdir', ['-p', dir]);
    writeFileSync(join(dir, 'policy.json'), JSON.stringify(opts.policy));
  }
  const transport = new StdioClientTransport({
    command: TSX,
    args: [CLI, 'shield', '--server', 'notes', '--dir', dir, '--definitions', DEFS, '--', process.execPath, FAKE],
    env: { PATH: process.env['PATH'] ?? '', HOME: root, EXORCIST_NOTIFY: '0', FAKE_MCP_LOG: log, FAKE_MCP_CONTROL: join(root, 'control.json') },
    stderr: 'pipe',
  });
  const prompts: string[] = [];
  const client = new Client({ name: 'sdk-test', version: '1.0.0' }, { capabilities: opts.answer ? { elicitation: {} } : {} });
  if (opts.answer) {
    const answer = opts.answer;
    client.setRequestHandler(ElicitRequestSchema, async (req) => {
      prompts.push(req.params.message);
      return answer(req.params.message);
    });
  }
  let listChanged = 0;
  client.setNotificationHandler(ToolListChangedNotificationSchema, async () => { listChanged++; });
  await client.connect(transport);
  clients.push(client);
  const calls = () => readFileSync(log, 'utf8').split('\n').filter(Boolean).length;
  return { client, dir, prompts, calls, listChanged: () => listChanged };
}

const text = (r: unknown) => JSON.stringify(r);

describe('Shield + official MCP SDK client over stdio', () => {
  it('S-004: the user is asked; accept with remember sends the call and allows the host', async () => {
    const s = await connect({ answer: () => ({ action: 'accept', content: { remember: true } }) });
    expect((await s.client.listTools()).tools.map((t) => t.name).sort()).toEqual(['read_note', 'send_report']);
    const r = await s.client.callTool({ name: 'send_report', arguments: { url: 'https://collect.example.invalid/in', body: 'hello' } });
    expect(s.prompts).toHaveLength(1);
    expect(s.prompts[0]).toContain('collect.example.invalid');
    expect(r.isError).not.toBe(true);
    expect(s.calls()).toBe(1);
    const pins = JSON.parse(readFileSync(join(s.dir, 'pins.json'), 'utf8')) as { servers: { notes: { approvedHosts: string[] } } };
    expect(pins.servers.notes.approvedHosts).toEqual(['collect.example.invalid']);
    // Remembered: no second prompt.
    await s.client.callTool({ name: 'send_report', arguments: { url: 'https://collect.example.invalid/again', body: 'x' } });
    expect(s.prompts).toHaveLength(1);
    expect(s.calls()).toBe(2);
  }, 60_000);

  it('S-004: declining refuses the call and the server never hears about it', async () => {
    const s = await connect({ answer: () => ({ action: 'decline' }) });
    await s.client.listTools();
    const r = await s.client.callTool({ name: 'send_report', arguments: { url: 'https://collect.example.invalid/in', body: 'hello' } });
    expect(r.isError).toBe(true);
    expect(text(r)).toContain('declined');
    expect(s.calls()).toBe(0);
  }, 60_000);

  it('S-006: review mode hides new tools until exorcist approve tool, then tells the client to re-list', async () => {
    const s = await connect({ policy: { firstUse: 'review' } });
    expect((await s.client.listTools()).tools).toEqual([]);
    const refused = await s.client.callTool({ name: 'read_note', arguments: { name: 'todo' } });
    expect(refused.isError).toBe(true);
    expect(s.calls()).toBe(0);
    const ok = spawnSync(TSX, [CLI, 'approve', 'tool', 'notes', 'read_note', '--dir', s.dir], { encoding: 'utf8' });
    expect(ok.status, ok.stderr).toBe(0);
    for (let i = 0; i < 40 && s.listChanged() === 0; i++) await new Promise((r) => setTimeout(r, 100));
    expect(s.listChanged()).toBeGreaterThan(0);
    expect((await s.client.listTools()).tools.map((t) => t.name)).toEqual(['read_note']);
    const r = await s.client.callTool({ name: 'read_note', arguments: { name: 'todo' } });
    expect(r.isError).not.toBe(true);
    expect(s.calls()).toBe(1);
  }, 60_000);
});
