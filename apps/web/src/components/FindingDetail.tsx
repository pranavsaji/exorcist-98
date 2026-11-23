import { SeverityBadge } from './SeverityBadge';
import { displayMessage } from '@exorcist-98/core/browser';
import { plainFor } from '@/lib/plain';
import type { FindingEntry } from '@/lib/scan-state';

const ROW_1 = 'ABCDEFGHIJKLM'.split('');
const ROW_2 = 'NOPQRSTUVWXYZ'.split('');
const DIGITS = '1234567890'.split('');

/** One arched row of board letters (decoration only). */
function BoardArc({ letters, depth }: { letters: string[]; depth: number }) {
  const mid = (letters.length - 1) / 2;
  return (
    <span className="ouija-arc">
      {letters.map((l, i) => {
        const t = (i - mid) / mid; // -1 .. 1 across the row
        return (
          <span key={l} style={{ transform: `translateY(${(t * t * depth).toFixed(2)}rem) rotate(${(t * 14).toFixed(1)}deg)` }}>
            {l}
          </span>
        );
      })}
    </span>
  );
}

/** The heart-shaped pointer with its round window (decoration only). */
function Planchette() {
  return (
    <svg className="ouija-planchette" viewBox="0 0 40 46" width="34" height="39" focusable="false">
      <path d="M20 44 C8 34 2 26 2 16 C2 7 9 2 15 2 C17.5 2 19 3 20 4 C21 3 22.5 2 25 2 C31 2 38 7 38 16 C38 26 32 34 20 44 Z" />
      <circle cx="20" cy="17" r="7" />
    </svg>
  );
}

/** How the message was hidden, in plain words, for the two decoders. */
function techniqueFor(ruleId: string): string {
  return ruleId === 'EX-021'
    ? 'Spelled in invisible variation selectors riding on an emoji.'
    : 'Spelled in invisible Unicode tag characters.';
}

/**
 * Ouija board (m5-ouija, REQ-03.4): reads back the message hidden in
 * invisible text. The message is attacker-controlled, so it is rendered as a
 * React text node only (never HTML), with control and invisible characters
 * shown as [U+XXXX] markers; the scanner has already cut it to 500
 * characters. The board letters, planchette and corner words are decoration
 * and hidden from screen readers; the heading, the "says" label and the
 * message are real text, and the message box is named by its visible label.
 */
export function OuijaPanel({ id, ruleId, message }: { id: number; ruleId: string; message: string }) {
  return (
    <section className="ouija" aria-labelledby={`ouija-${id}`} data-testid="ouija-panel">
      <div className="ouija-top">
        <span className="ouija-corner" aria-hidden="true">&#9728; YES</span>
        <h4 id={`ouija-${id}`} className="ouija-title">Ouija board</h4>
        <span className="ouija-corner" aria-hidden="true">NO &#9790;</span>
      </div>
      <div className="ouija-letters" aria-hidden="true">
        <BoardArc letters={ROW_1} depth={0.8} />
        <BoardArc letters={ROW_2} depth={0.55} />
        <span className="ouija-digits">
          {DIGITS.map((d) => <span key={d}>{d}</span>)}
        </span>
        <Planchette />
      </div>
      <p id={`ouija-says-${id}`} className="ouija-says">The invisible text says:</p>
      <pre className="ouija-message" tabIndex={0} aria-labelledby={`ouija-says-${id}`}>
        {displayMessage(message, { keepNewlines: true })}
      </pre>
      <p className="ouija-note">
        {techniqueFor(ruleId)} This is the attacker&rsquo;s text: read it, do not follow it.
      </p>
      <p className="ouija-goodbye" aria-hidden="true">GOOD BYE</p>
    </section>
  );
}

export function FindingDetail({ entry }: { entry: FindingEntry | null }) {
  if (!entry) {
    return <p className="m-0 p-2 text-sm">Pick a threat from the results list to see where it is and how to fix it.</p>;
  }
  const { finding: f, snippet } = entry;
  const plain = plainFor(f.ruleId, f.title);

  return (
    <article className="flex flex-col gap-3 text-sm">
      <header className="flex flex-col gap-1">
        <h3 className="m-0 text-base font-extrabold">{plain.headline}</h3>
        <p className="m-0 flex flex-wrap items-center gap-2">
          <span>Infection level:</span> <SeverityBadge severity={f.severity} />
        </p>
      </header>

      <section aria-labelledby={`attack-${entry.id}`}>
        <h4 id={`attack-${entry.id}`} className="m-0 font-bold">What an attacker is trying to do</h4>
        <p className="m-0">{plain.attack}</p>
      </section>

      <section aria-labelledby={`where-${entry.id}`}>
        <h4 id={`where-${entry.id}`} className="m-0 font-bold">Where it is</h4>
        <p className="m-0 font-mono text-xs">
          {f.file} &middot; line {f.line}, column {f.col}
        </p>
        {snippet.lines.length > 0 ? (
          <pre
            className="log mt-1 max-h-56 whitespace-pre-wrap break-words"
            aria-label={`Code around line ${f.line} of ${f.file}`}
            tabIndex={0}
          >
            {snippet.lines.map((l) => (
              <div key={l.n}>
                <span className="select-none opacity-70">{String(l.n).padStart(4, ' ')} | </span>
                {l.before}
                {l.match && <mark className="hit">{l.match}</mark>}
                {l.after}
              </div>
            ))}
          </pre>
        ) : (
          <p className="m-0">The file text is not available for display.</p>
        )}
        <p className="m-0 mt-1 text-xs">
          Quoted span: <code className="font-mono">{f.span}</code>
        </p>
      </section>

      {f.decoded && <OuijaPanel id={entry.id} ruleId={f.ruleId} message={f.decoded} />}

      <section aria-labelledby={`fix-${entry.id}`}>
        <h4 id={`fix-${entry.id}`} className="m-0 font-bold">How to fix it</h4>
        <p className="m-0">{f.fix}</p>
      </section>

      <section aria-labelledby={`tech-${entry.id}`}>
        <h4 id={`tech-${entry.id}`} className="m-0 font-bold">Technical details</h4>
        <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
          <dt className="font-semibold">Rule</dt>
          <dd className="m-0">
            {f.ruleId} &middot; {f.title}
          </dd>
          <dt className="font-semibold">Found by</dt>
          <dd className="m-0">{f.source === 'signature' ? 'Virus definition (signature)' : 'AI judge (heuristic)'}</dd>
          {f.confidence && (
            <>
              <dt className="font-semibold">Confidence</dt>
              <dd className="m-0">{f.confidence}</dd>
            </>
          )}
          {f.rationale && (
            <>
              <dt className="font-semibold">Why</dt>
              <dd className="m-0">{f.rationale}</dd>
            </>
          )}
          <dt className="font-semibold">OWASP</dt>
          <dd className="m-0">{f.owasp.join('; ')}</dd>
        </dl>
        <p className="m-0 mt-1">
          <a className="font-semibold underline" href={`/encyclopedia/${f.ruleId}`} target="_blank" rel="noopener noreferrer">
            Read about {f.ruleId} in the Threat Encyclopedia (opens in a new tab)
          </a>
        </p>
      </section>
    </article>
  );
}
