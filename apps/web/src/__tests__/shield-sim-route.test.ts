import { describe, it, expect } from 'vitest';
import { GET } from '@/app/api/shield-sim/route';
import type { SimResult } from '@exorcist-98/shield/simulator';
import { parseDeepLink } from '@/lib/deeplink';

const get = (q: string) => GET(new Request(`http://localhost/api/shield-sim${q}`));

describe('GET /api/shield-sim', () => {
  it('lists The Lethal Trifecta with the other attacks', async () => {
    const r = (await (await get('')).json()) as { scenarios: Array<{ id: string; title: string }> };
    expect(r.scenarios.map((s) => s.id)).toContain('trifecta');
    expect(r.scenarios.find((s) => s.id === 'trifecta')?.title).toBe('The Lethal Trifecta');
  });

  it('replays the trifecta with the capability rules, so the Session Guard (EX-027) holds the leak', async () => {
    const res = await get('?scenario=trifecta');
    expect(res.status).toBe(200);
    const r = (await res.json()) as SimResult;
    expect(r.shielded.leakedSecrets).toBe(0);
    expect(r.shielded.verdict).toMatch(/^Nothing leaked/);
    expect(r.unshielded.leakedSecrets).toBe(2);
    expect(r.steps.some((s) => s.shielded.some((e) => e.ruleId === 'EX-027' && e.severity === 'critical'))).toBe(true);
    expect(r.steps.some((s) => s.shielded.some((e) => e.actor === 'user'))).toBe(true);
  });

  it('?demo=trifecta opens it', () => {
    expect(parseDeepLink('?demo=trifecta')).toEqual({ kind: 'lab', scenario: 'trifecta' });
  });
});
describe('GET /api/shield-sim, The Hidden Page (m8-incidents, requirement 6)', () => {
  it('is listed among the attacks', async () => {
    const r = (await (await get('')).json()) as { scenarios: Array<{ id: string; title: string }> };
    expect(r.scenarios).toHaveLength(9);
    expect(r.scenarios.find((s) => s.id === 'hidden-web-text')?.title).toBe('The Hidden Page');
  });
  it('replays it: the config is written without the Shield, and EX-028 withholds the page with it', async () => {
    const r = (await (await get('?scenario=hidden-web-text')).json()) as SimResult;
    expect(r.unshielded.poisonReachedAgent).toBe(true);
    expect(r.shielded.poisonReachedAgent).toBe(false);
    expect(r.shielded.alerts).toBeGreaterThan(0);
    expect(r.summary).toContain('Shield layer');
    expect(r.realWorld).toContain('0.11.130');
  });
});


describe('GET /api/shield-sim, The Settings Tamper (m11-config-tamper)', () => {
  it('CT-19: is listed as attack 9 and replays blocked, with EX-030 as the stopping rule', async () => {
    const list = (await (await get('')).json()) as { scenarios: Array<{ id: string; title: string }> };
    expect(list.scenarios).toHaveLength(9);
    expect(list.scenarios[8]).toMatchObject({ id: 'settings-tamper', title: 'The Settings Tamper' });
    const r = (await (await get('?scenario=settings-tamper')).json()) as SimResult;
    expect(r.unshielded.verdict).toMatch(/every command trusted/);
    expect(r.shielded.poisonReachedAgent).toBe(false);
    expect(r.shielded.serverReceived.map((c) => c.tool)).toEqual(['read_file']);
    expect(r.steps.some((s) => s.shielded.some((e) => e.ruleId === 'EX-030' && e.severity === 'high'))).toBe(true);
  });
});
