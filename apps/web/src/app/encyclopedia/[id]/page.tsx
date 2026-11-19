import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { RetroFrame } from '@/components/RetroFrame';
import { SeverityBadge } from '@/components/SeverityBadge';
import { describeMatch, getDefinition, getExample } from '@/lib/encyclopedia';
import { plainFor } from '@/lib/plain';

export const dynamic = 'force-dynamic';

type Props = { params: { id: string } };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const def = await getDefinition(params.id);
  return { title: def ? `${def.id} ${def.title} | Exorcist 98` : 'Not found | Exorcist 98' };
}

export default async function ThreatPage({ params }: Props) {
  const def = await getDefinition(params.id);
  if (!def) notFound();

  const plain = plainFor(def.id, def.title);
  const example = await getExample(def.id);

  return (
    <RetroFrame title={`${def.id}: ${plain.headline}`}>
      <article className="flex flex-col gap-4">
        <header className="flex flex-col gap-1">
          <h2 className="m-0 text-lg font-extrabold">{plain.headline}</h2>
          <p className="m-0 flex flex-wrap items-center gap-2">
            <span>Infection level:</span> <SeverityBadge severity={def.severity} />
            <span className="font-mono text-xs">
              {def.id} &middot; {def.title}
            </span>
          </p>
        </header>

        <section aria-labelledby="attack">
          <h3 id="attack" className="m-0 font-bold">What the attacker is trying to do</h3>
          <p className="m-0">{plain.attack}</p>
        </section>

        <section aria-labelledby="example">
          <h3 id="example" className="m-0 font-bold">Defanged example</h3>
          {example ? (
            <>
              <p className="m-0 text-xs">
                From <code className="font-mono">fixtures/haunted-repo/{example.file}</code>. Hidden
                characters are shown as [U+XXXX]. Nothing here can run: domains use example.invalid
                and secrets are placeholders.
              </p>
              <pre
                className="log mt-1 max-h-96 whitespace-pre-wrap break-words"
                aria-label={`Example for ${def.id}`}
                tabIndex={0}
              >
                {example.text}
              </pre>
              {example.truncated && <p className="m-0 text-xs">Shortened. See the file for the rest.</p>}
            </>
          ) : (
            <p className="m-0">No example file exists for this rule yet.</p>
          )}
        </section>

        <section aria-labelledby="fix">
          <h3 id="fix" className="m-0 font-bold">How to fix it</h3>
          <p className="m-0">{def.fix}</p>
        </section>

        <section aria-labelledby="tech">
          <h3 id="tech" className="m-0 font-bold">Technical details</h3>
          <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
            <dt className="font-semibold">Detected by</dt>
            <dd className="m-0">{describeMatch(def)}</dd>
            <dt className="font-semibold">Checks files of type</dt>
            <dd className="m-0">{def.applies_to.join(', ')}</dd>
            <dt className="font-semibold">OWASP</dt>
            <dd className="m-0">{def.owasp.join('; ')}</dd>
          </dl>
        </section>
      </article>
    </RetroFrame>
  );
}
