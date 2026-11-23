'use client';

import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { BYOA_MAX_CHARS, BYOA_PLACEMENTS, PLACEMENT_LABELS, byoaSamples } from '@exorcist-98/shield/byoa-samples';
import type { ByoaPlacement, ByoaSample } from '@exorcist-98/shield/byoa-samples';
import type { ByoaResult, ShieldAction } from '@exorcist-98/shield/byoa';
import { SeverityBadge } from './SeverityBadge';
import { revealHidden } from '@/lib/snippet';
import { play } from '@/lib/sound';

// Built once in the browser: the hidden-Unicode sample is assembled from code points at run time.
const SAMPLES: ByoaSample[] = byoaSamples();

const WHERE: Record<ByoaPlacement, string> = {
  'rules-file': 'in a README',
  'tool-description': 'as a tool description',
  'tool-result': 'as a tool result',
  'call-arguments': 'as call arguments',
};

const ACTION_TAG: Record<ShieldAction, { label: string; tone: 'ok' | 'info' | 'warn' }> = {
  withheld: { label: 'WITHHELD', tone: 'ok' },
  blocked: { label: 'BLOCKED', tone: 'ok' },
  pinned: { label: 'PINNED', tone: 'info' },
  passed: { label: 'PASSED', tone: 'info' },
  unavailable: { label: 'NOT RUN', tone: 'warn' },
};

const HIDDEN_CHARS = /[​-‍﻿⁠-⁤᠎‪-‮⁦-⁩\u{E0000}-\u{E007F}]/gu;
const fmt = (n: number) => n.toLocaleString('en-US');

/** "EXORCISED: the Shield would stop this." -> "The Shield would stop this." */
const afterStamp = (headline: string) => headline.replace(/^[A-Z]+:\s*/, '').replace(/^./, (c) => c.toUpperCase());

export function ByoaLab() {
  const [placement, setPlacement] = useState<ByoaPlacement>('rules-file');
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ByoaResult | null>(null);
  const [announce, setAnnounce] = useState('');
  const abort = useRef<AbortController | null>(null);

  useEffect(() => () => abort.current?.abort(), []);

  const hiddenCount = (text.match(HIDDEN_CHARS) ?? []).length;

  async function check(p: ByoaPlacement, t: string) {
    if (t.length === 0) {
      setError('Paste some text to check first, or pick a sample.');
      return;
    }
    abort.current?.abort();
    const ctl = new AbortController();
    abort.current = ctl;
    setBusy(true);
    setError(null);
    setResult(null);
    setAnnounce('Checking the text…');
    try {
      const res = await fetch('/api/byoa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ placement: p, text: t }),
        signal: ctl.signal,
      });
      const body = (await res.json().catch(() => ({}))) as Partial<ByoaResult> & { error?: string };
      if (!res.ok || !body.verdict) throw new Error(body.error ?? 'The attack could not be checked. Try again.');
      const r = body as ByoaResult;
      setResult(r);
      setAnnounce(`Verdict: ${r.headline}`);
      play(r.verdict === 'clean' ? 'done-clean' : 'threat');
    } catch (e) {
      if (ctl.signal.aborted) return;
      const msg = e instanceof Error && e.message ? e.message : 'The attack could not be checked. Try again.';
      setError(msg);
      setAnnounce('');
    } finally {
      if (abort.current === ctl) setBusy(false);
    }
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    void check(placement, text);
  }

  function runSample(s: ByoaSample) {
    setPlacement(s.placement);
    setText(s.text);
    void check(s.placement, s.text);
  }

  return (
    <div className="flex flex-col gap-2 text-sm">
      <p className="m-0">
        <strong>Bring your own attack.</strong> Old antivirus came with a harmless test file so you could watch it
        work. Here, paste any text you are worried about, say where your AI agent would meet it, and the{' '}
        <em>real</em> scanner and the <em>real</em> Shield engine decide. Your text is checked in memory and thrown
        away: it is not stored or logged.
      </p>

      <div role="group" aria-labelledby="byoa-samples-label" className="flex flex-col gap-1">
        <p id="byoa-samples-label" className="m-0 font-semibold">Or try a sample (all defanged):</p>
        <div className="flex flex-wrap gap-1.5">
          {SAMPLES.map((s) => (
            <button key={s.id} type="button" className="btn byoa-sample" onClick={() => runSample(s)} disabled={busy}>
              <span className="font-bold">{s.label}</span>
              <span className="byoa-sample-where">{WHERE[s.placement]}</span>
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={onSubmit} className="flex flex-col gap-2" aria-label="Check your own attack">
        <fieldset className="byoa-fieldset">
          <legend className="font-semibold">Where would your agent meet this text?</legend>
          <div className="byoa-radios">
            {BYOA_PLACEMENTS.map((p) => (
              <label key={p} className="byoa-radio">
                <input type="radio" name="byoa-placement" value={p} checked={placement === p} onChange={() => setPlacement(p)} />
                {PLACEMENT_LABELS[p]}
              </label>
            ))}
          </div>
        </fieldset>

        <label htmlFor="byoa-text" className="font-semibold">
          Text to check (up to {fmt(BYOA_MAX_CHARS)} characters)
        </label>
        <textarea
          id="byoa-text"
          className="field byoa-text"
          rows={7}
          maxLength={BYOA_MAX_CHARS}
          spellCheck={false}
          value={text}
          aria-describedby="byoa-count"
          placeholder={placement === 'call-arguments' ? '{ "channel": "#general", "text": "..." }' : 'Paste a README, a tool description, a web page...'}
          onChange={(e) => { setText(e.target.value); if (error) setError(null); }}
        />
        <p id="byoa-count" className="m-0 text-[0.8rem]">
          {fmt(text.length)} of {fmt(BYOA_MAX_CHARS)} characters.
          {hiddenCount > 0 && (
            <strong className="byoa-invisible">
              {' '}This text holds {fmt(hiddenCount)} invisible character{hiddenCount === 1 ? '' : 's'}: you cannot see
              {hiddenCount === 1 ? ' it' : ' them'} here, but an AI reads {hiddenCount === 1 ? 'it' : 'them'}.
            </strong>
          )}
        </p>
        <div className="flex flex-wrap gap-1.5">
          <button type="submit" className="btn" disabled={busy}>
            {busy ? 'Checking…' : 'Scan this text'}
          </button>
          <button type="button" className="btn" disabled={busy} onClick={() => { setText(''); setResult(null); setError(null); setAnnounce(''); }}>
            Clear
          </button>
        </div>
      </form>

      <p className="sr-only" aria-live="polite">{announce}</p>
      {error && <p role="alert" className="m-0 font-semibold">{error}</p>}
      {result && <Verdict r={result} />}
    </div>
  );
}

function Verdict({ r }: { r: ByoaResult }) {
  const tag = r.shield.applies ? ACTION_TAG[r.shield.action] : null;
  return (
    <div className="flex flex-col gap-2" data-testid="byoa-result">
      <section className={`lab-verdict byoa-verdict byoa-verdict-${r.verdict}`} aria-labelledby="byoa-verdict-title">
        <h3 id="byoa-verdict-title" className="byoa-verdict-title">
          <span className="lab-stamp byoa-stamp">{r.stamp}</span>
          <span className="byoa-verdict-line">{afterStamp(r.headline)}</span>
        </h3>
        <p className="m-0">{r.explanation}</p>
        <p className="m-0 mt-1 byoa-caveat"><strong>Not a guarantee:</strong> {r.caveat}</p>
      </section>

      {r.hidden && (
        <section className="bevel-in byoa-panel" aria-labelledby="byoa-ouija-title">
          <h4 id="byoa-ouija-title" className="byoa-h">Ouija board: the invisible text</h4>
          <p className="m-0">Found {r.hidden.kinds.join(', ')}.</p>
          {r.hidden.decoded ? (
            <>
              <p className="m-0 mt-1 font-semibold">The invisible text says:</p>
              <pre className="lab-quote byoa-ouija">{r.hidden.decoded}</pre>
              <p className="m-0 mt-1 text-[0.8rem]">This is attacker text. It is only shown here, never followed.</p>
            </>
          ) : (
            <p className="m-0 mt-1 text-[0.8rem]">They do not spell out a message, but they can still split words so filters miss them.</p>
          )}
        </section>
      )}

      <div className="lab-grid">
        <section className="lab-col byoa-col" aria-labelledby="byoa-scanner-title">
          <h4 id="byoa-scanner-title" className="lab-col-title">What the scanner found</h4>
          {r.findings.length === 0 ? (
            <p className="m-0">No findings.</p>
          ) : (
            <ul className="m-0 flex list-none flex-col gap-1 p-0" aria-label="Scanner findings, worst first">
              {r.findings.map((f, i) => (
                <li key={i} className="lab-event" data-tone={f.severity === 'critical' || f.severity === 'high' ? 'block' : 'warn'}>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <SeverityBadge severity={f.severity} />
                    <a className="lab-rule byoa-rule-link" href={`/encyclopedia/${f.ruleId}`}>{f.ruleId}</a>
                    <span className="font-bold">{f.title}</span>
                    <span className="text-[0.78rem]">line {f.line}, column {f.col}</span>
                  </div>
                  <p className="m-0 mt-1 text-[0.78rem] font-semibold">Quoted text:</p>
                  <pre className="lab-quote">{revealHidden(f.span)}</pre>
                  <p className="m-0 mt-1 text-[0.82rem]"><strong>How to fix it:</strong> {f.fix.trim()}</p>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="lab-col byoa-col" data-side="shielded" aria-labelledby="byoa-shield-title">
          <h4 id="byoa-shield-title" className="lab-col-title">What the real Shield did</h4>
          {!r.shield.applies ? (
            <p className="m-0">{r.shield.note}</p>
          ) : (
            <>
              <p className="m-0">
                {tag && <span className={`lab-tag lab-tag-${tag.tone}`}>{tag.label}</span>} {r.shield.summary}
              </p>
              {r.shield.alerts.length > 0 && (
                <ul className="m-0 mt-1 flex list-none flex-col gap-1 p-0" aria-label="Shield alerts">
                  {r.shield.alerts.map((a, i) => (
                    <li key={i} className="lab-event" data-tone="block">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="lab-actor">Exorcist Shield</span>
                        <SeverityBadge severity={a.severity} />
                        {a.ruleId !== 'SHIELD' && <span className="lab-rule">{a.ruleId}</span>}
                      </div>
                      <p className="m-0 mt-0.5 text-[0.85rem] leading-snug">{a.message}</p>
                    </li>
                  ))}
                </ul>
              )}
              {r.shield.agentReceived && (
                <>
                  <p className="m-0 mt-1 text-[0.78rem] font-semibold">What your AI got instead:</p>
                  <pre className="lab-quote">{r.shield.agentReceived}</pre>
                </>
              )}
            </>
          )}
        </section>
      </div>

      <ul className="m-0 list-disc pl-5 text-[0.8rem]">
        {r.notes.map((n, i) => <li key={i}>{n}</li>)}
        <li>Checked {fmt(r.checkedChars)} characters in memory. Nothing you pasted was stored or logged.</li>
      </ul>
    </div>
  );
}
