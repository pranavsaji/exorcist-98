/** m13-kiro-evidence: properties of hook counting and totals aggregation (tasks 3.2, 3.3). */
import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';
import { aggregateTotals, extractSessionRecord, type KiroEvent, type SessionRecord } from '../kiro-evidence.js';

const alnum = 'abcdefghijklmnopqrstuvwxyz0123456789-'.split('');
const nameArb = fc.array(fc.constantFrom(...alnum), { minLength: 1, maxLength: 8 }).map((a) => a.join(''));
const hookNames = ['guard-a', 'guard-b', 'guard-c'];

let seq = 0;
function ev(payload: Record<string, unknown>): KiroEvent {
  seq += 1;
  return { id: `e${seq}`, timestamp: `2026-01-01T00:00:00.${String(seq % 1000).padStart(3, '0')}Z`, payload: payload as KiroEvent['payload'] };
}
const hookLine = (name: string): KiroEvent => ev({ type: 'ContextualHookInvoked', name, hookActionType: 'runCommand', status: 'completed' });
const deniedByHook = (tool: string): KiroEvent =>
  ev({
    type: 'tool_result',
    status: 'denied',
    success: false,
    content: `Tool "${tool}" was intercepted by PreToolUse hooks before execution.\n<HOOK_INSTRUCTION>stop</HOOK_INSTRUCTION>`,
  });
const okResult = (): KiroEvent => ev({ type: 'tool_result', status: 'completed', success: true, content: 'ok' });
const policyDenied = (): KiroEvent =>
  ev({ type: 'tool_result', status: 'denied', success: false, content: 'Kiro blocked this action: policy' });

/** A step is a hook line followed directly by either a hook-blocked result or a normal / policy-denied one. */
type Step = { hook: string; outcome: 'block' | 'ok' | 'policy' | 'none'; extraRuns: number };
const stepArb: fc.Arbitrary<Step> = fc.record({
  hook: fc.constantFrom(...hookNames),
  outcome: fc.constantFrom('block', 'ok', 'policy', 'none'),
  extraRuns: fc.integer({ min: 0, max: 2 }),
});

describe('Property 7: hook run and hook block counting matches construction', () => {
  it('KE-12 KE-13 counts every hook line as a run and only hook-intercepted denials as blocks, by hook name', () => {
    fc.assert(
      fc.property(fc.array(stepArb, { maxLength: 25 }), (steps) => {
        const events: KiroEvent[] = [];
        const runs: Record<string, number> = {};
        const blocks: Record<string, number> = {};
        for (const s of steps) {
          // Earlier hook lines in a group run but cannot be blamed; the last one directly before the result is.
          for (let i = 0; i < s.extraRuns; i++) {
            events.push(hookLine('guard-extra'));
            runs['guard-extra'] = (runs['guard-extra'] ?? 0) + 1;
          }
          events.push(hookLine(s.hook));
          runs[s.hook] = (runs[s.hook] ?? 0) + 1;
          if (s.outcome === 'block') {
            events.push(deniedByHook('read_file'));
            blocks[s.hook] = (blocks[s.hook] ?? 0) + 1;
          } else if (s.outcome === 'ok') events.push(okResult());
          else if (s.outcome === 'policy') events.push(policyDenied());
          // Separate groups so one step's hook line never directly precedes the next step's result.
          events.push(ev({ type: 'assistant', content: 'x' }));
        }
        const rec = extractSessionRecord({ id: 's' }, events);
        expect(rec.hookRuns).toEqual(runs);
        expect(rec.hookBlocks).toEqual(blocks);
        const blockTotal = Object.values(blocks).reduce((a, b) => a + b, 0);
        expect(rec.hookBlockEvents).toHaveLength(blockTotal);
      }),
    );
  });

  it('KE-13 a hook-intercepted denial with no hook line directly before it is attributed to "unknown"', () => {
    fc.assert(
      fc.property(nameArb, fc.integer({ min: 1, max: 5 }), (tool, n) => {
        const events: KiroEvent[] = [];
        for (let i = 0; i < n; i++) events.push(ev({ type: 'assistant', content: 'x' }), deniedByHook(tool));
        const rec = extractSessionRecord({ id: 's' }, events);
        expect(rec.hookBlocks).toEqual({ unknown: n });
        expect(rec.hookRuns).toEqual({});
      }),
    );
  });
});

const countMap = fc.dictionary(nameArb, fc.integer({ min: 0, max: 1000 }), { maxKeys: 5 });
const recordArb: fc.Arbitrary<SessionRecord> = fc
  .record({
    id: nameArb,
    credits: fc.integer({ min: 0, max: 100000 }).map((n) => n / 100),
    toolCalls: countMap,
    hookRuns: countMap,
    hookBlocks: countMap,
  })
  .map((r) => ({
    ...r,
    title: null,
    agentMode: null,
    startTime: null,
    endTime: null,
    model: null,
    autopilot: null,
    approveForMe: null,
    hookBlockEvents: [],
    commits: [],
    eventsDroppedUnparseable: 0,
  }));

function sumMaps(maps: Record<string, number>[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const m of maps) for (const [k, v] of Object.entries(m)) out[k] = (out[k] ?? 0) + v;
  return out;
}

describe('Property 3: totals equal the sum of kept sessions', () => {
  it('KE-5 KE-14 sums credits and per-key tool calls, hook runs and hook blocks across records', () => {
    fc.assert(
      fc.property(fc.array(recordArb, { maxLength: 12 }), fc.nat(50), (records, skipped) => {
        const t = aggregateTotals(records, skipped);
        expect(t.sessionsKept).toBe(records.length);
        expect(t.sessionsSkipped).toBe(skipped);
        expect(t.credits).toBeCloseTo(records.reduce((a, r) => a + r.credits, 0), 6);
        expect(t.toolCalls).toEqual(sumMaps(records.map((r) => r.toolCalls)));
        expect(t.hookRuns).toEqual(sumMaps(records.map((r) => r.hookRuns)));
        expect(t.hookBlocks).toEqual(sumMaps(records.map((r) => r.hookBlocks)));
      }),
    );
  });

  it('KE-5 totals of no sessions are all zero and empty', () => {
    expect(aggregateTotals([], 3)).toEqual({
      sessionsKept: 0,
      sessionsSkipped: 3,
      credits: 0,
      toolCalls: {},
      hookRuns: {},
      hookBlocks: {},
      eventsDroppedUnparseable: 0,
    });
  });
});
