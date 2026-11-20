import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PassThrough } from 'node:stream';
import { runRemoteProxy } from '../remote.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

const sse = (...events: object[]) =>
  new Response(new ReadableStream({ start(c) { for (const e of events) c.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(e)}\n\n`)); c.close(); } }), { headers: { 'content-type': 'text/event-stream' } });

describe('a dropped remote stream is reopened', () => {
  it('server notifications keep arriving after the first stream ends', async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'x98-reconnect-')));
    dirs.push(root);
    let gets = 0;
    const fakeFetch = (async (_url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        const m = JSON.parse(String(init.body)) as { method?: string; id?: number };
        if (m.method === 'initialize') {
          return new Response(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'r', version: '1' } } }), { headers: { 'content-type': 'application/json', 'mcp-session-id': 'abc123' } });
        }
        return new Response(null, { status: 202 });
      }
      if (init?.method === 'GET') {
        gets++;
        // First stream: ends at once with nothing. Second: one notification.
        if (gets === 1) return sse();
        if (gets === 2) return sse({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'back again' } });
        return new Promise<Response>(() => undefined); // later streams stay open
      }
      return new Response(null, { status: 200 });
    }) as typeof fetch;

    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    let out = '';
    stdout.on('data', (c: Buffer) => { out += c.toString(); });
    const done = runRemoteProxy({
      server: 'remote', url: 'https://mcp.example.invalid/mcp', dir: join(root, '.exorcist'),
      definitionsDir: resolve(import.meta.dirname, '../../../../definitions'),
      stdin, stdout, stderr, fetchFn: fakeFetch, reconnectBaseMs: 10, pollMs: 60_000,
    });
    stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'a', version: '1' } } })}\n`);
    await new Promise((r) => setTimeout(r, 100));
    stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
    for (let i = 0; i < 50 && !out.includes('back again'); i++) await new Promise((r) => setTimeout(r, 50));
    expect(out).toContain('back again');
    expect(gets).toBeGreaterThanOrEqual(2);
    stdin.end();
    await done;
  }, 30_000);
});
