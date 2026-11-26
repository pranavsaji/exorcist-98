/**
 * Pure helpers for the demo chain controls. They call the same `eventHash` and
 * `verifyChain` the CLI uses (packages/shield/src/chain-core.ts); nothing here
 * hashes or verifies on its own.
 */
import { eventHash, verifyChain } from '@exorcist-98/shield/chain-core';
import type { ChainStatus, ChainedShieldEvent, HeadRecord } from '@exorcist-98/shield/chain-core';
import type { DemoBody } from './chain-demo-bodies';

/** Chain `bodies` from `genesis`, exactly as the Shield's writer does it. Used by the generator script and its test. */
export function buildChain(bodies: readonly DemoBody[], genesis: string): { events: ChainedShieldEvent[]; head: HeadRecord } {
  const events: ChainedShieldEvent[] = [];
  let prev = genesis;
  bodies.forEach((body, i) => {
    const seq = i + 1;
    const hash = eventHash({ ...body, seq, prev } as Parameters<typeof eventHash>[0]);
    events.push({ ...body, seq, prev, hash } as ChainedShieldEvent);
    prev = hash;
  });
  const last = events[events.length - 1] as ChainedShieldEvent;
  return { events, head: { v: 1, genesis, seq: last.seq, hash: last.hash } };
}

export type Rewrite = { events: ChainedShieldEvent[]; index: number; field: 'decision'; from: string; to: string };

/**
 * Change one field of one event and leave its seq, prev and hash alone. The
 * first blocked or held call is rewritten to "allowed": the lie someone would
 * tell to hide that the Shield stopped something. Returns null if there is
 * nothing to rewrite.
 */
export function rewriteOneEvent(events: readonly ChainedShieldEvent[]): Rewrite | null {
  const index = events.findIndex((e) => e.kind === 'call' && e.decision !== 'allowed');
  const target = events[index];
  if (target === undefined || target.kind !== 'call') return null;
  const copy = events.map((e) => ({ ...e })) as ChainedShieldEvent[];
  copy[index] = { ...target, decision: 'allowed' } as ChainedShieldEvent;
  return { events: copy, index, field: 'decision', from: target.decision, to: 'allowed' };
}

export const verifyDemo = (events: readonly ChainedShieldEvent[], head: HeadRecord): ChainStatus => verifyChain(events, head, head.genesis);

/** The three console labels: "intact", "broken at event N", "not chained". */
export function statusLabel(s: ChainStatus): string {
  if (s.status === 'intact') return 'intact';
  if (s.status === 'not-chained') return 'not chained';
  return `broken at event ${s.atSeq}`;
}

/** What a screen reader hears: label first, then the reason, in plain words. */
export function statusAnnouncement(s: ChainStatus): string {
  if (s.status === 'intact') return `Log ${statusLabel(s)}: all ${s.head.seq} events match their hashes.`;
  if (s.status === 'not-chained') return `Log ${statusLabel(s)}: it has no hashes to check.`;
  return `Log ${statusLabel(s)}: ${s.reason}. ${s.detail}.`;
}
