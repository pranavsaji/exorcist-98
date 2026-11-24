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
