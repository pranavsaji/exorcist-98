import { describe, it, expect, beforeAll } from 'vitest';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDefinitions } from '@exorcist-98/core';
import type { VirusDefinition } from '@exorcist-98/core';
import { SCENARIO_IDS, listScenarios, runScenario } from '../simulator.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
let defs: VirusDefinition[] = [];
beforeAll(async () => { defs = await loadDefinitions(resolve(__dirname, '../../../../definitions')); });

describe('Possession Lab simulator (real ShieldEngine)', () => {
  it('lists every scenario', () => {
    expect(listScenarios().map((s) => s.id)).toEqual([...SCENARIO_IDS]);
  });

  for (const id of SCENARIO_IDS) {
    it(`${id}: the unprotected run is harmed and the shielded run is not`, () => {
      const r = runScenario(id, defs);
      // Without the Shield, the attack works.
      expect(r.unshielded.leakedSecrets > 0 || r.unshielded.poisonReachedAgent || r.unshielded.verdict.includes('nobody approved')).toBe(true);
      // With the Shield, nothing leaks, no poison reaches the agent, and it says so.
      expect(r.shielded.leakedSecrets).toBe(0);
      expect(r.shielded.poisonReachedAgent).toBe(false);
      expect(r.shielded.alerts).toBeGreaterThan(0);
      expect(r.shielded.verdict).toMatch(/^Nothing leaked/);
      // Every step has events in both worlds.
      for (const s of r.steps) {
        expect(s.shielded.length).toBeGreaterThan(0);
        expect(s.unshielded.length).toBeGreaterThan(0);
      }
    });
  }

  it('rug pull: the cached-list call is caught by the pre-call check, with a diff', () => {
    const r = runScenario('rug-pull', defs);
    const step = r.steps[3]!;
    expect(step.shielded.some((e) => e.text.includes('re-reads the tool list'))).toBe(true);
    const diff = step.shielded.find((e) => e.ruleId === 'EX-006')?.diff ?? '';
    expect(diff).toContain('-Get the weather forecast for a city.');
    expect(diff).toContain('~/.aws/credentials');
    // Without the Shield the changed tool was called and then fed the credentials.
    expect(r.unshielded.serverReceived.length).toBe(3);
    expect(r.unshielded.leakedSecrets).toBeGreaterThan(0);
    // With it, only Monday's honest call reached the server.
    expect(r.shielded.serverReceived).toEqual([{ tool: 'get_forecast', args: { city: 'Paris' } }]);
  });

  it('benign calls still work through the Shield', () => {
    const notes = runScenario('poisoned-tool', defs);
    expect(notes.shielded.serverReceived.map((c) => c.tool)).toEqual(['read_note']);
    const chat = runScenario('secret-leak', defs);
    expect(chat.shielded.serverReceived.map((c) => (c.args as { text: string }).text)).toEqual(['Build is green, deploying at 3pm.']);
    const fetch = runScenario('unknown-host', defs);
    expect(fetch.shielded.serverReceived.map((c) => (c.args as { url: string }).url)).toEqual(['https://docs.example.com/getting-started']);
  });

  it('the canary: the trap token leaves without the Shield, and EX-022 stops both copies with it', () => {
    expect(SCENARIO_IDS).toHaveLength(6);
    expect(listScenarios().find((s) => s.id === 'canary')?.title).toBe('The Canary');
    const r = runScenario('canary', defs);
    // Unprotected: the paste server got the .env.canary contents, plain and base64.
    expect(r.unshielded.serverReceived.map((c) => (c.args as { title: string }).title)).toEqual(['deploy debug', 'deploy debug (encoded)', 'todo']);
    expect(r.unshielded.leakedSecrets).toBe(2);
    expect(r.steps[1]!.unshielded.some((e) => e.text.includes('trap token from .exorcist/canary/.env.canary'))).toBe(true);
    // Shielded: both leaking calls blocked by a critical EX-022 naming the trap file; the honest paste goes through.
    expect(r.shielded.serverReceived.map((c) => (c.args as { title: string }).title)).toEqual(['todo']);
    for (const i of [1, 2]) {
      const alert = r.steps[i]!.shielded.find((e) => e.ruleId === 'EX-022');
      expect(alert?.severity).toBe('critical');
      expect(alert?.text).toContain('EX-022 Canary token in a tool call');
      expect(alert?.text).toContain('.exorcist/canary/.env.canary');
    }
    expect(r.steps[2]!.shielded.find((e) => e.ruleId === 'EX-022')?.text).toContain('base64');
  });

  it('is deterministic', () => {
    for (const id of SCENARIO_IDS) expect(JSON.stringify(runScenario(id, defs))).toBe(JSON.stringify(runScenario(id, defs)));
  });
});
