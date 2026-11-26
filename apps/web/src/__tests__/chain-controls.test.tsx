import { describe, expect, it } from 'vitest';
import { isValidElement } from 'react';
import type { ReactElement, ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { verifyChain } from '@exorcist-98/shield/chain-core';
import {
  ChainControlsView, initialChainState, rewriteAction, verifyAction,
} from '@/components/ChainControls';
import type { ChainDemoState } from '@/components/ChainControls';
import { CHAIN_DEMO } from '@/lib/chain-demo-data';
import { chainDemoSource } from '@/lib/chain-demo-gen';
import { statusAnnouncement } from '@/lib/chain-demo-core';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SCENARIOS = ['rug-pull', 'trifecta'] as const;

/** Find every element of `type` in a React element tree (the view has no hooks, so it can be called directly). */
function find(node: ReactNode, type: string, out: ReactElement<Record<string, unknown>>[] = []): ReactElement<Record<string, unknown>>[] {
  if (Array.isArray(node)) node.forEach((n) => find(n, type, out));
  else if (isValidElement(node)) {
    const el = node as ReactElement<Record<string, unknown>>;
    if (el.type === type) out.push(el);
    find(el.props['children'] as ReactNode, type, out);
  }
  return out;
}

/** A tiny harness: the view is stateless, so keep the state here and "press" a button by its label. */
function harness(scenario: (typeof SCENARIOS)[number]) {
  let state: ChainDemoState = initialChainState(scenario);
  const head = CHAIN_DEMO[scenario].head;
  const view = () => ChainControlsView({
    state,
    onRewrite: () => { state = rewriteAction(state); },
    onVerify: () => { state = verifyAction(state, head); },
    onReset: () => { state = initialChainState(scenario); },
  });
  const button = (label: string) => {
    const b = find(view(), 'button').find((x) => String(x.props['aria-label']).startsWith(label));
    if (!b) throw new Error(`no button ${label}`);
    return b;
  };
  /** Keyboard: Tab reaches a native button and Enter/Space fire its click handler; no pointer event is involved. */
  const press = (label: string) => { (button(label).props['onClick'] as () => void)(); };
  const text = () => renderToStaticMarkup(view());
  return { press, button, text, get state() { return state; }, head };
}

const changedFields = (a: object, b: object): string[] => {
  const x = a as Record<string, unknown>;
  const y = b as Record<string, unknown>;
  return [...new Set([...Object.keys(x), ...Object.keys(y)])].filter((k) => x[k] !== y[k]);
};

describe('demo chain data', () => {
  it.each(SCENARIOS)('AC-21: the committed %s log is exactly what the generator produces, and verifies intact with the shared verifyChain', (id) => {
    const file = fileURLToPath(new URL('../lib/chain-demo-data.ts', import.meta.url));
    expect(readFileSync(file, 'utf8')).toBe(chainDemoSource());
    const { events, head } = CHAIN_DEMO[id];
    expect(verifyChain(events, head, head.genesis)).toEqual({ status: 'intact', head });
  });
});

describe('ChainControls', () => {
  it.each(SCENARIOS)('AC-19: "Rewrite an event" changes exactly one field of exactly one event (%s)', (id) => {
    const h = harness(id);
    const before = h.state.events;
    h.press('Rewrite an event');
    const after = h.state.events;
    const diffs = after.flatMap((e, i) => changedFields(before[i] as object, e).map((f) => `${i}:${f}`));
    expect(diffs).toHaveLength(1);
    expect(diffs[0]).toMatch(/:decision$/);
    const i = h.state.rewritten as number;
    for (const k of ['seq', 'prev', 'hash'] as const) expect(after[i]?.[k]).toBe(before[i]?.[k]);
    expect(h.text()).toContain('REWRITTEN');
  });

  it.each(SCENARIOS)('AC-20: "Verify the log" after a rewrite names the event number and the reason (%s)', (id) => {
    const h = harness(id);
    h.press('Rewrite an event');
    h.press('Verify the log');
    const n = (h.state.rewritten as number) + 1;
    expect(h.state.result).toMatchObject({ status: 'broken', atSeq: n, reason: 'changed' });
    const html = h.text();
    expect(html).toContain(`BROKEN AT EVENT ${n}`);
    expect(html).toContain('changed');
  });

  it.each(SCENARIOS)('AC-21: "Verify the log" with no rewrite shows intact (%s)', (id) => {
    const h = harness(id);
    h.press('Verify the log');
    expect(h.state.result?.status).toBe('intact');
    expect(h.text()).toContain('INTACT');
  });

  it.each(SCENARIOS)('AC-22: both controls are native buttons with plain-language aria-labels, operable without a pointer, and the live region updates (%s)', (id) => {
    const h = harness(id);
    for (const label of ['Rewrite an event', 'Verify the log']) {
      const b = h.button(label);
      expect(b.type).toBe('button'); // native: Tab focuses it, Enter and Space activate it
      expect(String(b.props['aria-label'])).toMatch(/simulate tampering|still intact/);
      expect(b.props['tabIndex']).toBeUndefined(); // in the natural tab order
    }
    const live = (html: string) => /<p[^>]*aria-live="polite"[^>]*>([\s\S]*?)<\/p>/.exec(html)?.[1] ?? '';
    expect(live(h.text())).toBe('');
    h.press('Verify the log');
    const intact = live(h.text());
    expect(intact).toContain('Log intact');
    h.press('Rewrite an event');
    h.press('Verify the log');
    const broken = live(h.text());
    expect(broken).not.toBe(intact);
    expect(broken).toMatch(/Log broken at event \d+: changed\./);
  });

  it('AC-22: the announcement uses the same three labels as the console badge', () => {
    const { head } = CHAIN_DEMO['rug-pull'];
    expect(statusAnnouncement({ status: 'intact', head })).toContain('intact');
    expect(statusAnnouncement({ status: 'not-chained' })).toContain('not chained');
    expect(statusAnnouncement({ status: 'broken', atSeq: 3, reason: 'changed', detail: 'x' })).toContain('broken at event 3');
  });
});
