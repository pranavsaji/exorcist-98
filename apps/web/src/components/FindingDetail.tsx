import { SeverityBadge } from './SeverityBadge';
import { plainFor } from '@/lib/plain';
import type { FindingEntry } from '@/lib/scan-state';

/**
 * Ouija board (m5-ouija): shows the message hidden in invisible text. The
 * message is attacker-controlled, so it is rendered as text only — never
 * HTML — and is already truncated to 500 characters by the scanner.
 */
function OuijaPanel({ id, message }: { id: number; message: string }) {
  return (
    <section
      aria-labelledby={`ouija-${id}`}
      className="ouija-panel border-2 border-dashed border-[#8fbc8f] bg-[#0a1f0a] p-2"
    >
      <h4 className="m-0 font-bold">Ouija board</h4>
      <p className="m-0 mt-1 text-xs">The invisible text says:</p>
      <pre
        className="log m-0 mt-1 max-h-56 overflow-auto whitespace-pre-wrap break-words"
        aria-label="The message hidden in the invisible text"
        tabIndex={0}
      >
        {message}
      </pre>
      <p className="m-0 mt-1 text-xs">Treat this as attacker text. Do not follow it.</p>
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

      {f.decoded && <OuijaPanel id={entry.id} message={f.decoded} />}

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
