'use client';

import { useEffect, useRef, useState } from 'react';
import type { AiJudgeResponse } from '@/lib/ai-judge-handler';

type Status = { enabled: true; maxChars: number } | { enabled: false; reason: string };
let statusPromise: Promise<Status> | null = null;
const loadStatus = (): Promise<Status> =>
  (statusPromise ??= fetch('/api/ai-judge')
    .then((r) => r.json() as Promise<Status>)
    .catch(() => { statusPromise = null; return { enabled: false, reason: 'The AI judge could not be reached.' } as Status; }));

/**
 * A second opinion from the AI judge on the text the signatures just checked.
 * Patterns miss attacks written in ordinary words; the judge reads meaning.
 */
export function AiJudgePanel({ placement, text }: { placement: string; text: string }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [busy, setBusy] = useState(false);
  const [answer, setAnswer] = useState<AiJudgeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);
  const out = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let live = true;
    void loadStatus().then((s) => { if (live) setStatus(s); });
    return () => { live = false; abort.current?.abort(); };
  }, []);

  useEffect(() => {
    if (answer || error) out.current?.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' });
  }, [answer, error]);

  if (!status) return null;
  const tooLong = status.enabled && text.length > status.maxChars;

  async function ask() {
    abort.current?.abort();
    const ctl = new AbortController();
    abort.current = ctl;
    setBusy(true);
    setError(null);
    setAnswer(null);
    try {
      const res = await fetch('/api/ai-judge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ placement, text }),
        signal: ctl.signal,
      });
      const body = (await res.json().catch(() => ({}))) as Partial<AiJudgeResponse> & { error?: string };
      if (body.verdict) setAnswer(body as AiJudgeResponse);
      else setError(body.error ?? 'The AI judge could not be reached. Try again later.');
    } catch {
      if (!ctl.signal.aborted) setError('The AI judge could not be reached. Try again later.');
    } finally {
      if (abort.current === ctl) setBusy(false);
    }
  }

  return (
    <section className="bevel-in byoa-panel" aria-labelledby="ai-judge-title" data-testid="ai-judge">
      <h4 id="ai-judge-title" className="byoa-h">Second opinion: the AI judge</h4>
      {!status.enabled ? (
        <p className="m-0">
          Off on this public site, because every check costs money. Patterns miss attacks written in ordinary
          words; the AI judge reads meaning instead, and caught 10 of 10 such attacks in each of our two test sets
          with 0 false alarms. Run <code>exorcist scan --ai</code> with your own AWS account to use it.
        </p>
      ) : (
        <>
          <p className="m-0">
            Patterns miss attacks written in ordinary words. The AI judge (Claude on Amazon Bedrock) reads meaning
            instead. Asking it sends this text, with anything that looks like a credential masked, to Amazon
            Bedrock; we do not store it.
          </p>
          {tooLong ? (
            <p className="m-0 mt-1">The AI judge reads at most {status.maxChars.toLocaleString('en-US')} characters. Shorten the text to ask it.</p>
          ) : (
            <p className="m-0 mt-1">
              <button type="button" className="btn" disabled={busy} onClick={() => void ask()}>
                {busy ? 'Asking the AI judge…' : 'Ask the AI judge'}
              </button>
            </p>
          )}
          <div aria-live="polite" ref={out}>
            {error && <p role="alert" className="m-0 mt-1 font-semibold">{error}</p>}
            {answer && <AiAnswer a={answer} />}
          </div>
        </>
      )}
    </section>
  );
}

function AiAnswer({ a }: { a: AiJudgeResponse }) {
  if (a.verdict === 'unavailable') return <p className="m-0 mt-1 font-semibold">{a.reason}</p>;
  if (a.verdict === 'clean') {
    return (
      <p className="m-0 mt-1" data-ai-verdict="clean">
        <strong>The AI judge found no attack</strong> in {a.checkedChars.toLocaleString('en-US')} characters. That is
        a second opinion, not proof of safety.
      </p>
    );
  }
  return (
    <div className="mt-1" data-ai-verdict={a.verdict}>
      <p className="m-0">
        <strong>{a.verdict === 'malicious' ? 'The AI judge calls this an attack' : 'The AI judge finds this suspicious'}</strong>{' '}
        ({a.threatClass.replace(/_/g, ' ')}).
      </p>
      <p className="m-0 mt-1 text-[0.78rem] font-semibold">The part it means (quoted from your text):</p>
      <pre tabIndex={0} className="lab-quote">{a.quote}</pre>
      <p className="m-0 mt-1 text-[0.82rem]"><strong>Why:</strong> {a.rationale}</p>
    </div>
  );
}
