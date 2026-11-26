'use client';
import { useState } from 'react';
import type { ChainStatus, ChainedShieldEvent, HeadRecord } from '@exorcist-98/shield/chain-core';
import { CHAIN_DEMO } from '@/lib/chain-demo-data';
import type { DemoScenario } from '@/lib/chain-demo-bodies';
import { rewriteOneEvent, statusAnnouncement, statusLabel, verifyDemo } from '@/lib/chain-demo-core';

export type ChainDemoState = {
  events: ChainedShieldEvent[];
  /** Index of the event that was rewritten, or null. */
  rewritten: number | null;
  /** The last Verify result; null until Verify is pressed. */
  result: ChainStatus | null;
};

export const initialChainState = (scenario: DemoScenario): ChainDemoState => ({ events: CHAIN_DEMO[scenario].events, rewritten: null, result: null });

export function rewriteAction(s: ChainDemoState): ChainDemoState {
  if (s.rewritten !== null) return s;
  const r = rewriteOneEvent(s.events);
  return r === null ? s : { events: r.events, rewritten: r.index, result: null };
}

export function verifyAction(s: ChainDemoState, head: HeadRecord): ChainDemoState {
  return { ...s, result: verifyDemo(s.events, head) };
}

const TAG: Record<ChainStatus['status'], string> = { intact: 'lab-tag-ok', broken: 'lab-tag-block', 'not-chained': 'lab-tag-info' };

function describeEvent(e: ChainedShieldEvent): string {
  if (e.kind === 'start') return `Shield started (${e.mode})`;
  if (e.kind === 'alert') return `alert ${e.ruleId}`;
  return `${e.tool}: ${e.decision}`;
}

type ViewProps = {
  state: ChainDemoState;
  onRewrite: () => void;
  onVerify: () => void;
  onReset: () => void;
};

/** The stateless view: every control is a native button (Tab to reach, Enter or Space to press). */
export function ChainControlsView({ state, onRewrite, onVerify, onReset }: ViewProps) {
  const { events, rewritten, result } = state;
  return (
    <div className="bevel-in p-2" data-testid="chain-controls" role="group" aria-label="Tamper test for the Shield log">
      <p className="m-0 font-semibold">Can anyone quietly change the Shield&apos;s log?</p>
      <p className="m-0 mt-1 text-[0.82rem]">
        Every log entry carries a fingerprint (hash) of itself and of the entry before it. Rewrite one entry, then check the log:
        the check names the first entry that no longer matches. It is the same check as <code>exorcist verify-log</code>.
      </p>
      <ol className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0 text-[0.82rem]" aria-label="Log entries">
        {events.map((e, i) => (
          <li key={e.seq} data-rewritten={rewritten === i ? 'true' : undefined}>
            <span className="font-bold">Event {e.seq}:</span> {describeEvent(e)} <code>#{e.hash.slice(0, 8)}</code>
            {rewritten === i && <span className="lab-tag lab-tag-warn ml-1">REWRITTEN</span>}
          </li>
        ))}
      </ol>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button type="button" className="btn" onClick={onRewrite} disabled={rewritten !== null} aria-label="Rewrite an event: change one log entry to simulate tampering">
          Rewrite an event
        </button>
        <button type="button" className="btn" onClick={onVerify} aria-label="Verify the log: check whether the log is still intact">
          Verify the log
        </button>
        <button type="button" className="btn" onClick={onReset} aria-label="Start over: restore the original log">
          Start over
        </button>
      </div>
      <p className="m-0 mt-1 font-semibold" data-testid="chain-status" aria-live="polite" role="status">
        {result !== null && (
          <>
            <span className={`lab-tag ${TAG[result.status]}`}>{statusLabel(result).toUpperCase()}</span>{' '}
            <span className="sr-only">{statusAnnouncement(result)}</span>
            <span aria-hidden="true">
              {result.status === 'broken' ? `${result.reason}: ${result.detail}` : result.status === 'intact' ? `all ${result.head.seq} events match.` : 'no hashes to check.'}
            </span>
          </>
        )}
      </p>
    </div>
  );
}

/** The tamper test shown in the Rug Pull and Trifecta demos (AC-19 to AC-22). */
export function ChainControls({ scenario }: { scenario: DemoScenario }) {
  const [state, setState] = useState<ChainDemoState>(() => initialChainState(scenario));
  const head = CHAIN_DEMO[scenario].head;
  return (
    <ChainControlsView
      state={state}
      onRewrite={() => setState(rewriteAction)}
      onVerify={() => setState((s) => verifyAction(s, head))}
      onReset={() => setState(initialChainState(scenario))}
    />
  );
}
