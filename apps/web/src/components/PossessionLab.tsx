'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ScenarioId, SimEvent, SimResult } from '@exorcist-98/shield/simulator';
import { play } from '@/lib/sound';

type ScenarioCard = { id: ScenarioId; title: string; summary: string };

const ACTOR: Record<SimEvent['actor'], string> = { agent: 'Your AI agent', server: 'MCP server', shield: 'Exorcist Shield' };
const TONE_LABEL: Record<SimEvent['tone'], string> = { info: '', ok: 'SAFE', warn: 'WARNING', block: 'DANGER' };

function DiffView({ diff }: { diff: string }) {
  const lines = diff.split('\n').filter((l) => !l.startsWith('===') && !l.startsWith('Index'));
  return (
    <pre className="lab-diff" aria-label="What changed in the tool">
      {lines.map((l, i) => {
        const kind = l.startsWith('+') && !l.startsWith('+++') ? 'add' : l.startsWith('-') && !l.startsWith('---') ? 'del' : 'ctx';
        return (
          <span key={i} className={`lab-diff-${kind}`}>
            {kind === 'add' ? 'ADDED   ' : kind === 'del' ? 'REMOVED ' : '        '}
            {l}
            {'\n'}
          </span>
        );
      })}
    </pre>
  );
}

function EventRow({ e, shielded }: { e: SimEvent; shielded: boolean }) {
  // On the shielded side a "block" is the Shield doing its job; on the other side it is the harm.
  const label = e.tone === 'block' && shielded && e.actor === 'shield' ? 'STOPPED' : TONE_LABEL[e.tone];
  return (
    <li className="lab-event" data-actor={e.actor} data-tone={e.tone}>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="lab-actor">{ACTOR[e.actor]}</span>
        {label && <span className={`lab-tag lab-tag-${e.tone}`}>{label}</span>}
        {e.ruleId && e.ruleId !== 'SHIELD' && <span className="lab-rule">{e.ruleId}</span>}
      </div>
      <p className="m-0 mt-0.5 text-[0.85rem] leading-snug">{e.text}</p>
      {e.quote !== undefined && e.quote !== '' && <pre className="lab-quote">{e.quote}</pre>}
      {e.diff && <DiffView diff={e.diff} />}
    </li>
  );
}

/** The one-word outcome of a step, for the collapsed view. */
function keyMoment(events: SimEvent[]): { tone: SimEvent['tone']; label: string } | null {
  if (events.some((e) => e.actor === 'shield' && e.tone === 'block')) return { tone: 'ok', label: 'STOPPED' };
  if (events.some((e) => e.tone === 'block')) return { tone: 'block', label: 'HARMED' };
  if (events.some((e) => e.tone === 'warn')) return { tone: 'warn', label: 'WARNING' };
  return null;
}

export function PossessionLab({ initial = 'rug-pull' }: { initial?: ScenarioId }) {
  const [scenarios, setScenarios] = useState<ScenarioCard[]>([]);
  const [id, setId] = useState<ScenarioId>(initial);
  const [result, setResult] = useState<SimResult | null>(null);
  const [step, setStep] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [playing, setPlaying] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    fetch('/api/shield-sim')
      .then((r) => r.json())
      .then((d: { scenarios?: ScenarioCard[] }) => setScenarios(d.scenarios ?? []))
      .catch(() => setError('Could not load the scenarios.'));
  }, []);

  useEffect(() => {
    let live = true;
    setResult(null);
    setStep(0);
    setPlaying(false);
    setError(null);
    fetch(`/api/shield-sim?scenario=${encodeURIComponent(id)}`)
      .then(async (r) => {
        if (!r.ok) throw new Error();
        return (await r.json()) as SimResult;
      })
      .then((d) => { if (live) setResult(d); })
      .catch(() => { if (live) setError('The simulation could not be loaded. Try again.'); });
    return () => { live = false; };
  }, [id]);

  const total = result?.steps.length ?? 0;
  const finished = result !== null && step >= total - 1;

  const next = useCallback(() => setStep((s) => Math.min(s + 1, Math.max(0, total - 1))), [total]);

  useEffect(() => {
    if (!playing) return;
    if (finished) { setPlaying(false); return; }
    timer.current = setTimeout(next, 1600);
    return () => { if (timer.current) clearTimeout(timer.current); };
  }, [playing, step, finished, next]);

  useEffect(() => {
    if (!result) return;
    const s = result.steps[step];
    if (s?.shielded.some((e) => e.actor === 'shield' && e.tone === 'block')) play('threat');
    if (finished) play('done-clean');
  }, [result, step, finished]);

  return (
    <div className="flex flex-col gap-2 text-sm">
      <p className="m-0">
        <strong>Watch the Real-Time Shield stop an attack.</strong> Each run replays the same agent and MCP server
        twice: once through the <em>real</em> Exorcist 98 Shield engine (the same code that runs on your machine),
        once with nothing in between. The server and every secret are fake.
      </p>

      <div role="group" aria-label="Choose an attack" className="flex flex-wrap gap-1.5">
        {(scenarios.length ? scenarios : [{ id, title: 'The Rug Pull', summary: '' }]).map((s) => (
          <button key={s.id} type="button" className="btn" aria-pressed={s.id === id} onClick={() => { if (s.id === id) { setStep(0); setPlaying(false); } else setId(s.id); }}>
            {s.title}
          </button>
        ))}
      </div>

      {error && <p role="alert" className="m-0 font-semibold">{error}</p>}
      {!result && !error && <p className="m-0" aria-live="polite">Summoning the attack…</p>}

      {result && (
        <>
          <div className="bevel-in p-2">
            <p className="m-0 font-semibold">{result.summary}</p>
            <p className="m-0 mt-1 text-[0.82rem]"><strong>Why it matters:</strong> {result.realWorld}</p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button type="button" className="btn" onClick={() => setStep((s) => Math.max(0, s - 1))} disabled={step === 0}>
              ◀ Back
            </button>
            <button type="button" className="btn" onClick={next} disabled={finished}>
              Next step ▶
            </button>
            <button type="button" className="btn" aria-pressed={playing} onClick={() => setPlaying((p) => !p)} disabled={finished}>
              {playing ? 'Pause' : 'Play the whole attack'}
            </button>
            <button type="button" className="btn" onClick={() => { setStep(0); setPlaying(false); }}>
              Restart
            </button>
            <span aria-live="polite" className="font-semibold">
              Step {step + 1} of {total}: {result.steps[step]?.title}
            </span>
          </div>

          <div className="lab-grid">
            {(['shielded', 'unshielded'] as const).map((side) => (
              <section key={side} className="lab-col" data-side={side} aria-label={side === 'shielded' ? 'With the Exorcist Shield' : 'Without the Shield'}>
                <h3 className="lab-col-title">
                  {side === 'shielded' ? '🛡 With the Exorcist Shield' : '☠ Without the Shield'}
                </h3>
                <ol className="m-0 flex list-none flex-col gap-2 p-0">
                  {result.steps.slice(0, step + 1).map((s, i) => {
                    const key = keyMoment(s[side]);
                    return i === step ? (
                      <li key={`${i}-${side}`} className="lab-step lab-step-current">
                        <p className="lab-step-title">{i + 1}. {s.title}</p>
                        <ul className="m-0 flex list-none flex-col gap-1 p-0">
                          {s[side].map((e, j) => <EventRow key={j} e={e} shielded={side === 'shielded'} />)}
                        </ul>
                      </li>
                    ) : (
                      <li key={`${i}-${side}`} className="lab-step lab-step-past">
                        <button type="button" className="lab-past" onClick={() => setStep(i)}>
                          <span className="font-bold">{i + 1}. {s.title}<span className="sr-only"> (go back to this step)</span></span>
                          {key && <span className={`lab-tag lab-tag-${key.tone}`}>{key.label}</span>}
                        </button>
                      </li>
                    );
                  })}
                </ol>
                {finished && (
                  <div className={side === 'shielded' ? 'lab-verdict lab-verdict-safe' : 'lab-verdict lab-verdict-harm'} role="status">
                    <span className="lab-stamp" aria-hidden="true">{side === 'shielded' ? 'EXORCISED' : 'POSSESSED'}</span>
                    <p className="m-0 font-bold">{side === 'shielded' ? 'Result: protected.' : 'Result: compromised.'}</p>
                    <p className="m-0">{result[side].verdict}</p>
                  </div>
                )}
              </section>
            ))}
          </div>

          <p className="m-0 text-[0.8rem]">
            Run it yourself with no browser: <code>node scripts/demo-rug-pull.mjs</code> in the repository runs the
            Shield as a real process between a real MCP client and server.
          </p>
        </>
      )}
    </div>
  );
}
