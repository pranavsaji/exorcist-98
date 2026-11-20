import { describe, expect, it } from 'vitest';
import { join } from 'node:path';
import { loadDefinitions } from '@exorcist-98/core';
import { ShieldEngine } from '../engine.js';
import type { Action } from '../engine.js';
import { DEFAULT_POLICY } from '../policy.js';
import { emptyState } from '../state.js';
import type { State } from '../state.js';

const defs = await loadDefinitions(join(import.meta.dirname, '../../../../definitions'));

function make() {
  let state: State = emptyState();
  const engine = new ShieldEngine({
    server: 'notes', defs, policy: { ...DEFAULT_POLICY },
    io: { load: () => structuredClone(state), save: (s) => { state = structuredClone(s); } },
  });
  engine.onClient({ jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: { elicitation: {} }, clientInfo: { name: 't', version: '1' } } });
  return { engine, get state() { return state; } };
}

const fwd = (as: Action[], to: 'client' | 'server') =>
  as.filter((a) => a.type === 'forward' && a.to === to).map((a) => (a as { message: Record<string, any> }).message);

const sendTool = (name: string) => ({ name, description: 'Send a short report.', inputSchema: { type: 'object', properties: { url: { type: 'string' } } } });
function list(engine: ShieldEngine, tools: object[], id: number) {
  engine.onClient({ jsonrpc: '2.0', id, method: 'tools/list' });
  engine.onServer({ jsonrpc: '2.0', id, result: { tools } });
}
const call = (id: number, name: string, url = 'https://collect.example.invalid/x') => ({ jsonrpc: '2.0' as const, id, method: 'tools/call', params: { name, arguments: { url } } });

describe('approval prompts cannot pile up or mislead', () => {
  it('stops prompting after too many unanswered prompts, and refuses further calls instead', () => {
    const t = make();
    list(t.engine, [sendTool('send_report')], 1);
    let prompts = 0;
    let lastRefused = false;
    for (let i = 0; i < 200; i++) {
      const acts = t.engine.onClient(call(100 + i, 'send_report', `https://h${i}.example.invalid/x`));
      const out = fwd(acts, 'client');
      if (out.some((m) => m['method'] === 'elicitation/create')) prompts++;
      lastRefused = out.some((m) => m['id'] === 100 + i && m['result']?.isError === true);
    }
    expect(prompts).toBeLessThanOrEqual(32);
    expect(lastRefused).toBe(true);
  });

  it('after an old prompt is answered there is room for a new one', () => {
    const t = make();
    list(t.engine, [sendTool('send_report')], 1);
    const first = fwd(t.engine.onClient(call(100, 'send_report')), 'client')[0];
    for (let i = 1; i < 40; i++) t.engine.onClient(call(100 + i, 'send_report', `https://h${i}.example.invalid/x`));
    t.engine.onClient({ jsonrpc: '2.0', id: first?.['id'], result: { action: 'decline' } });
    const again = fwd(t.engine.onClient(call(500, 'send_report', 'https://later.example.invalid/x')), 'client');
    expect(again.some((m) => m['method'] === 'elicitation/create')).toBe(true);
  });

  it('a tool whose name hides characters is withheld before any prompt can exist', () => {
    const t = make();
    const evil = 'send\u202e_report\u200b';
    list(t.engine, [sendTool(evil)], 1);
    const out = fwd(t.engine.onClient(call(5, evil)), 'client');
    expect(out.some((m) => m['method'] === 'elicitation/create')).toBe(false);
    expect(out[0]).toMatchObject({ id: 5, result: { isError: true } });
  });

  it('the prompt shows hosts and long names with hidden characters removed and shortened', () => {
    const t = make();
    const longName = 'send_' + 'x'.repeat(300);
    list(t.engine, [sendTool(longName)], 1);
    const prompt = fwd(t.engine.onClient(call(5, longName, 'https://col\u200blect.example.invalid/x')), 'client')[0];
    const message = String(prompt?.['params']?.message ?? '');
    expect(message).toContain('wants to send data');
    expect(message).not.toMatch(/[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/);
    expect(message.length).toBeLessThan(400);
  });

  it('"always allow" that cannot be saved is reported, not silently ignored', () => {
    const t = make();
    list(t.engine, [sendTool('send_report')], 1);
    const prompt = fwd(t.engine.onClient(call(5, 'send_report', 'http://[2001:db8::1]/x')), 'client')[0];
    const acts = t.engine.onClient({ jsonrpc: '2.0', id: prompt?.['id'], result: { action: 'accept', content: { remember: true } } });
    expect(fwd(acts, 'server')).toHaveLength(1); // it still runs once
    const alert = acts.find((a) => a.type === 'alert') as { alert: { message: string } } | undefined;
    expect(alert?.alert.message).toMatch(/could not be saved|only this once/i);
  });
});

describe('bookkeeping stays bounded', () => {
  it('requests the server never answers do not grow without limit', () => {
    const t = make();
    for (let i = 0; i < 5000; i++) t.engine.onServer({ jsonrpc: '2.0', id: `r${i}`, method: 'sampling/createMessage', params: { messages: [{ role: 'user', content: { type: 'text', text: 'hi' } }], maxTokens: 5 } });
    expect(t.engine.openCounts().serverRequests).toBeLessThanOrEqual(1000);
  });

  it('calls the server never answers do not grow without limit', () => {
    const t = make();
    list(t.engine, [{ name: 'read_note', description: 'Read.', inputSchema: { type: 'object' } }], 1);
    for (let i = 0; i < 5000; i++) t.engine.onClient({ jsonrpc: '2.0', id: 1000 + i, method: 'tools/call', params: { name: 'read_note', arguments: { name: 'x' } } });
    expect(t.engine.openCounts().pending).toBeLessThanOrEqual(1000);
  });
});
