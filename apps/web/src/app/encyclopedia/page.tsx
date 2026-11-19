import type { Metadata } from 'next';
import { RetroFrame } from '@/components/RetroFrame';
import { SeverityBadge } from '@/components/SeverityBadge';
import { listDefinitions } from '@/lib/encyclopedia';
import { plainFor } from '@/lib/plain';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Virus Definitions | Exorcist 98' };

export default async function EncyclopediaIndex() {
  const defs = await listDefinitions();
  return (
    <RetroFrame title="Virus Definitions: Threat Encyclopedia">
      <p className="mt-0">
        Every threat Exorcist 98 knows about, in plain words first. Each page shows what the attack
        does, a defanged example and how to fix it.
      </p>
      <ul className="bevel-in m-0 list-none p-1" aria-label="Virus definitions">
        {defs.map((d) => (
          <li key={d.id} className="border-b border-shade/40 last:border-b-0">
            <a
              className="flex flex-col gap-1 px-2 py-2 hover:bg-hilite"
              href={`/encyclopedia/${d.id}`}
            >
              <span className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={d.severity} />
                <span className="font-semibold">{plainFor(d.id, d.title).headline}</span>
              </span>
              <span className="font-mono text-xs">
                {d.id} &middot; {d.title}
              </span>
            </a>
          </li>
        ))}
      </ul>
    </RetroFrame>
  );
}
