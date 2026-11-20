import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { clientKey, createLimiter } from '@/lib/limits';

describe('W-003 scan limits', () => {
  const policies = { github: { capacity: 2, refillPerMs: 1 / 60_000 }, 'haunted-repo': { capacity: 3, refillPerMs: 1 / 1000 } };
  it('allows a burst per visitor, then answers 429 with a wait, then refills', () => {
    let t = 0;
    const l = createLimiter({ policies, maxConcurrent: { github: 10, 'haunted-repo': 10 }, now: () => t });
    const a = l.acquire('github', '1.2.3.4');
    const b = l.acquire('github', '1.2.3.4');
    expect(a.ok && b.ok).toBe(true);
    const c = l.acquire('github', '1.2.3.4');
    expect(c).toMatchObject({ ok: false, status: 429, retryAfterSeconds: 60 });
    expect(l.acquire('github', '5.6.7.8').ok).toBe(true);
    t += 60_000;
    expect(l.acquire('github', '1.2.3.4').ok).toBe(true);
  });
  it('caps scans running at once and frees the slot exactly once', () => {
    const l = createLimiter({ policies: { github: { capacity: 100, refillPerMs: 1 }, 'haunted-repo': { capacity: 100, refillPerMs: 1 } }, maxConcurrent: { github: 2, 'haunted-repo': 1 } });
    const a = l.acquire('github', 'x');
    const b = l.acquire('github', 'y');
    expect(l.acquire('github', 'z')).toMatchObject({ ok: false, status: 503 });
    expect(l.acquire('haunted-repo', 'z').ok).toBe(true);
    if (a.ok) { a.release(); a.release(); }
    expect(l.running().github).toBe(1);
    expect(l.acquire('github', 'z').ok).toBe(true);
    if (b.ok) b.release();
  });
  it('PBT-WEB-10: with no time passing, a visitor never gets more than the bucket size', () => {
    fc.assert(fc.property(fc.array(fc.constantFrom('a', 'b', 'c'), { maxLength: 60 }), (clients) => {
      const l = createLimiter({ policies, maxConcurrent: { github: 1000, 'haunted-repo': 1000 }, now: () => 0 });
      const granted = new Map<string, number>();
      for (const c of clients) if (l.acquire('github', c).ok) granted.set(c, (granted.get(c) ?? 0) + 1);
      for (const n of granted.values()) expect(n).toBeLessThanOrEqual(2);
    }));
  });
  it('reads the client address only from the proxy header, and shares one bucket without it', () => {
    expect(clientKey(new Headers({ 'fly-client-ip': '203.0.113.7' }), {})).toBe('203.0.113.7');
    expect(clientKey(new Headers({ 'x-forwarded-for': '203.0.113.7' }), {})).toBe('shared');
    expect(clientKey(new Headers({ 'fly-client-ip': '<script>' }), {})).toBe('shared');
    expect(clientKey(new Headers({ 'x-real-ip': '2001:db8::1' }), { EXORCIST_CLIENT_IP_HEADER: 'X-Real-IP' })).toBe('2001:db8::1');
  });
});
