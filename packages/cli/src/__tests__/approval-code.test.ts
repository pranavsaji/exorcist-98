import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { CODE_TTL_MS, checkCode, personConfirms } from '../commands/on-access.js';
import type { Terminal } from '../commands/on-access.js';

const codeArb = fc.stringMatching(/^[0-9a-f]{6,12}$/);
const NO_OS = { available: async () => false, verify: async () => 'error' as const };

function run(clock: { t: number }, issueAt: number, answerAt: number, typed?: string) {
  const out: string[] = [];
  const err: string[] = [];
  let step = 0;
  const term: Terminal = {
    interactive: true,
    ask: async () => { clock.t = answerAt; return typed ?? 'abcdef'; },
    nonce: () => 'abcdef',
    now: () => new Date(step++ === 0 ? issueAt : clock.t),
    osAuth: NO_OS,
  };
  return personConfirms(term, { out: (s) => out.push(s), err: (s) => err.push(s) }, 'm', 'r').then((ok) => ({ ok, err }));
}

describe('approval code expiry and single use', () => {
  it('AC-25: Property 7: a correct code is rejected once the TTL has passed', () => {
    fc.assert(fc.property(codeArb, fc.integer({ min: 0, max: 2 ** 40 }), fc.integer({ min: -10 * CODE_TTL_MS, max: 10 * CODE_TTL_MS }), (code, t0, dt) => {
      const v = checkCode(code, { code, issuedAt: t0 }, t0 + dt, false);
      expect(v).toBe(dt <= CODE_TTL_MS ? 'ok' : 'expired');
    }));
  });

  it('AC-26: Property 8: a code accepted once is refused the second time', () => {
    fc.assert(fc.property(codeArb, fc.integer({ min: 0, max: 2 ** 40 }), fc.integer({ min: 0, max: CODE_TTL_MS }), fc.integer({ min: 0, max: CODE_TTL_MS }), (code, t0, d1, d2) => {
      const ticket = { code, issuedAt: t0 };
      expect(checkCode(code, ticket, t0 + d1, false)).toBe('ok');
      expect(checkCode(code, ticket, t0 + d2, true)).toBe('used');
    }));
  });

  it('AC-25: a wrong answer is a mismatch, and a short code is never accepted', () => {
    expect(checkCode('zzzzzz', { code: 'abcdef', issuedAt: 0 }, 0, false)).toBe('mismatch');
    expect(checkCode('abc', { code: 'abc', issuedAt: 0 }, 0, false)).toBe('mismatch');
    expect(checkCode(' ABCDEF ', { code: 'abcdef', issuedAt: 0 }, 0, false)).toBe('ok');
  });

  it('AC-25: personConfirms refuses a code typed after 15 minutes and says so', async () => {
    const r = await run({ t: 0 }, 1_000, 1_000 + CODE_TTL_MS + 1);
    expect(r.ok).toBe(false);
    expect(r.err.join('\n')).toMatch(/expired/);
  });

  it('AC-25: personConfirms accepts a code typed exactly at the limit', async () => {
    expect((await run({ t: 0 }, 1_000, 1_000 + CODE_TTL_MS)).ok).toBe(true);
  });

  it('AC-25: personConfirms keeps the plain mismatch message for a wrong code', async () => {
    const r = await run({ t: 0 }, 0, 10, 'nope00');
    expect(r.ok).toBe(false);
    expect(r.err.join('\n')).toMatch(/does not match/);
  });
});
