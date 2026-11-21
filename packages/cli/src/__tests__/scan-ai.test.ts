import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { DEFAULT_AI_CALLS, makeAiClient } from '../commands/scan.js';
import type { Io } from '../util.js';

const io = (): Io & { errs: string[] } => {
  const errs: string[] = [];
  return { errs, out: () => undefined, err: (s) => { errs.push(s); } };
};

function fake(result: { ok: true; raw: string } | { ok: false; error: string } = { ok: true, raw: '{}' }) {
  const counts = { haiku: 0, sonnet: 0, failed: 0 };
  let calls = 0;
  return {
    counts,
    get calls() { return calls; },
    async call(p: { model: 'haiku' | 'sonnet' }) {
      calls++;
      if (result.ok) counts[p.model]++; else counts.failed++;
      return result;
    },
  };
}

describe('S-020 exorcist scan --ai', () => {
  it('never makes more model calls than the budget, whatever the scan asks for', async () => {
    await fc.assert(fc.asyncProperty(fc.integer({ min: 1, max: 40 }), fc.integer({ min: 0, max: 120 }), async (max, asked) => {
      const real = fake();
      const ai = await makeAiClient(String(max), io(), real);
      if (ai === false) throw new Error('should start');
      for (let i = 0; i < asked; i++) await ai.client.call({ model: i % 2 ? 'sonnet' : 'haiku', prompt: 'p', maxTokens: 10 });
      expect(real.calls).toBe(Math.min(max, asked));
    }), { numRuns: 30 });
  });

  it('the summary says how many calls were made, how many were skipped, and the first error', async () => {
    const real = fake({ ok: false, error: 'ThrottlingException: Too many tokens per day\nstack...' });
    const ai = await makeAiClient('2', io(), real);
    if (ai === false) throw new Error('should start');
    for (let i = 0; i < 5; i++) await ai.client.call({ model: 'haiku', prompt: 'p', maxTokens: 10 });
    expect(ai.summary()).toBe('AI judge: 2 model calls (0 triage, 0 judge, 2 failed); 3 more skipped by --ai-max-calls 2; first error: ThrottlingException: Too many tokens per day.');
  });

  it('defaults to a budget and rejects bad budgets', async () => {
    expect(DEFAULT_AI_CALLS).toBe(100);
    for (const bad of ['0', '-3', '1.5', 'many', '20000']) {
      const o = io();
      expect(await makeAiClient(bad, o, fake())).toBe(false);
      expect(o.errs[0]).toMatch(/--ai-max-calls/);
    }
  });
});
