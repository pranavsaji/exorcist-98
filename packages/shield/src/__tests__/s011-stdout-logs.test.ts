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
  return new ShieldEngine({ server: 'noisy', defs, policy: { ...DEFAULT_POLICY }, io: { load: () => structuredClone(state), save: (s) => { state = structuredClone(s); } } });
}

describe('S-011 a server that prints logs to stdout', () => {
  it('its log lines go to stderr, never to the agent, with one alert per session', () => {
    const e = make();
    const all: Action[] = [];
    for (let i = 0; i < 50; i++) all.push(...e.onServerLine(`[INFO] starting worker ${i}`));
    const alerts = all.filter((a) => a.type === 'alert');
    const logs = all.filter((a) => a.type === 'log') as Array<{ type: 'log'; text: string }>;
    const toClient = all.filter((a) => a.type === 'forward');
    expect(alerts).toHaveLength(1);
    expect(logs).toHaveLength(50);
    expect(logs[0]?.text).toContain('starting worker 0');
    expect(toClient).toEqual([]);
  });

  it('log text is cleaned and shortened before it is shown', () => {
    const e = make();
    const out = e.onServerLine(`evil\u202e text \u001b[31m${'x'.repeat(5000)}`).filter((a) => a.type === 'log') as Array<{ text: string }>;
    expect(out[0]?.text).not.toMatch(/[\u001b\u202e]/);
    expect(out[0]?.text.length).toBeLessThanOrEqual(600);
  });

  it('protocol messages after the noise still work', () => {
    const e = make();
    e.onServerLine('booting...');
    const ok = e.onServerLine(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 1, progress: 1 } }));
    expect(ok.some((a) => a.type === 'forward' && a.to === 'client')).toBe(true);
  });
});
