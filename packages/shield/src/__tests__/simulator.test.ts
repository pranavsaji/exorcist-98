import { describe, it, expect, beforeAll } from 'vitest';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCapabilityRules, loadDefinitions } from '@exorcist-98/core';
import type { CapabilityRule, VirusDefinition } from '@exorcist-98/core';
import { SCENARIO_IDS, listScenarios, runScenario } from '../simulator.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFS = resolve(__dirname, '../../../../definitions');
let defs: VirusDefinition[] = [];
let rules: CapabilityRule[] = [];
beforeAll(async () => {
  defs = await loadDefinitions(DEFS);
  const r = await loadCapabilityRules(DEFS);
  if (!r.ok) throw new Error(r.error);
  rules = r.rules;
});

describe('Possession Lab simulator (real ShieldEngine)', () => {
  it('lists every scenario', () => {
    expect(listScenarios().map((s) => s.id)).toEqual([...SCENARIO_IDS]);
  });

  for (const id of SCENARIO_IDS) {
    it(`${id}: the unprotected run is harmed and the shielded run is not`, () => {
      const r = runScenario(id, defs, rules);
      // Without the Shield, the attack works.
      expect(r.unshielded.leakedSecrets > 0 || r.unshielded.poisonReachedAgent || r.unshielded.verdict.includes('nobody approved')).toBe(true);
      // With the Shield, nothing leaks, no poison reaches the agent (except in
      // the trifecta, where the poison is meant to look harmless and pass),
      // and it says so.
      expect(r.shielded.leakedSecrets).toBe(0);
      expect(r.shielded.poisonReachedAgent).toBe(id === 'trifecta');
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
    const r = runScenario('rug-pull', defs, rules);
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
    const notes = runScenario('poisoned-tool', defs, rules);
    expect(notes.shielded.serverReceived.map((c) => c.tool)).toEqual(['read_note']);
    const chat = runScenario('secret-leak', defs, rules);
    expect(chat.shielded.serverReceived.map((c) => (c.args as { text: string }).text)).toEqual(['Build is green, deploying at 3pm.']);
    const fetch = runScenario('unknown-host', defs, rules);
    expect(fetch.shielded.serverReceived.map((c) => (c.args as { url: string }).url)).toEqual(['https://docs.example.com/getting-started']);
  });

  it('the canary: the trap token leaves without the Shield, and EX-022 stops both copies with it', () => {
    expect(listScenarios().find((s) => s.id === 'canary')?.title).toBe('The Canary');
    const r = runScenario('canary', defs, rules);
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

  it('the lethal trifecta: each step alone passes, and EX-027 holds the call that closes the loop', () => {
    expect(SCENARIO_IDS).toHaveLength(7);
    expect(listScenarios().find((s) => s.id === 'trifecta')?.title).toBe('The Lethal Trifecta');
    const r = runScenario('trifecta', defs, rules);
    // Unprotected: three servers, and the base64 .env (two fake keys) reached team chat.
    expect(r.unshielded.serverReceived.map((c) => `${c.server}/${c.tool}`)).toEqual(['issues/get_issue', 'files/read_file', 'team-chat/send_message', 'team-chat/send_message']);
    expect(r.unshielded.leakedSecrets).toBe(2);
    expect(r.unshielded.verdict).toBe('2 secrets reached the team-chat server.');
    // Shielded: the issue and the .env read pass, with no alert, because each looks harmless alone.
    const [, issue, read, post, update] = r.steps;
    for (const s of [issue!, read!]) {
      expect(s.shielded.some((e) => e.actor === 'shield' && e.tone === 'block')).toBe(false);
      expect(s.shielded.some((e) => e.text === 'Received the call.')).toBe(true);
    }
    expect(issue!.shielded.find((e) => e.text.startsWith('Session Guard notes'))?.text).toContain('"get_issue" on "issues" reads issues and pull requests written by anyone (CAP-012)');
    expect(read!.shielded.find((e) => e.text.startsWith('Session Guard notes'))?.text).toMatch(/"read_file" on "files" .*EX-017.*next call that could send data out will be held/);
    // The post is held by EX-027, the user declines, the chat server never hears of it.
    const held = post!.shielded.find((e) => e.ruleId === 'EX-027' && e.severity === 'critical');
    expect(held?.text).toContain('"get_issue" on "issues"');
    expect(held?.text).toContain('"read_file" on "files"');
    expect(held?.text).toContain('Now "send_message" on "team-chat" would send data out: it sends email or messages (CAP-021)');
    expect(held?.text).toContain('held until you answer the approval prompt');
    expect(post!.shielded.some((e) => e.actor === 'shield' && e.text.startsWith('Asks you') && (e.quote ?? '').includes('Allow this call?'))).toBe(true);
    expect(post!.shielded.some((e) => e.actor === 'user')).toBe(true);
    expect(post!.shielded.some((e) => e.text.startsWith('Never received the call'))).toBe(true);
    // The honest update is held too, you allow it once, and it goes through.
    expect(update!.shielded.some((e) => e.ruleId === 'EX-027' && e.text.includes('only this once'))).toBe(true);
    expect(r.shielded.serverReceived.map((c) => `${c.server}/${c.tool}`)).toEqual(['issues/get_issue', 'files/read_file', 'team-chat/send_message']);
    expect((r.shielded.serverReceived[2]!.args as { channel: string }).channel).toBe('#dev');
    expect(r.shielded.verdict).toMatch(/^Nothing leaked\. The issue's request reached your AI/);
    // No secret text in anything the Shield said.
    expect(JSON.stringify(r.steps.map((s) => s.shielded.filter((e) => e.actor === 'shield')))).not.toMatch(/AKIA|wJalr/);
  });

  it('without the capability rules a chat tool is not known to send data out, and the Lab says the Shield missed it', () => {
    // The web route always passes the rules; this documents why they matter
    // (and that the Lab's verdict is honest when something gets through).
    const r = runScenario('trifecta', defs);
    expect(r.shielded.leakedSecrets).toBe(2);
    expect(r.shielded.verdict).toMatch(/^The Shield missed something/);
  });

  it('is deterministic', () => {
    for (const id of SCENARIO_IDS) expect(JSON.stringify(runScenario(id, defs, rules))).toBe(JSON.stringify(runScenario(id, defs, rules)));
  });
});
