import { SeverityBadge } from './SeverityBadge';
import { plainFor } from '@/lib/plain';
import { SEVERITY_ORDER, sortFindings } from '@/lib/severity';
import type { FindingEntry } from '@/lib/scan-state';

type Props = {
  findings:   FindingEntry[];
  selectedId: number | null;
  onSelect:   (id: number) => void;
};

export function ResultsWindow({ findings, selectedId, onSelect }: Props) {
  if (findings.length === 0) {
    return (
      <p className="m-0 p-2 text-sm">
        No threats yet. Run a scan and anything suspicious will be listed here, worst first.
      </p>
    );
  }

  const sorted = sortFindings(findings.map((e) => ({ ...e, ...e.finding })));
  const counts = SEVERITY_ORDER.map((s) => ({
    s,
    n: findings.filter((e) => e.finding.severity === s).length,
  })).filter((c) => c.n > 0);

  return (
    <div className="flex flex-col gap-2">
      <p className="m-0 text-sm font-semibold">
        {findings.length} threat{findings.length === 1 ? '' : 's'} found:{' '}
        {counts.map((c) => `${c.n} ${c.s}`).join(', ')}
      </p>
      <ul className="bevel-in m-0 max-h-80 list-none overflow-auto p-1" aria-label="Threats found, worst first">
        {sorted.map((e) => {
          const plain = plainFor(e.finding.ruleId, e.finding.title);
          const selected = e.id === selectedId;
          return (
            <li key={e.id}>
              <button
                type="button"
                className="flex w-full flex-col gap-1 border-b border-shade/40 px-2 py-2 text-left hover:bg-hilite"
                aria-current={selected ? 'true' : undefined}
                style={selected ? { background: '#f4f0fa', fontWeight: 700 } : undefined}
                onClick={() => onSelect(e.id)}
              >
                <span className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={e.finding.severity} />
                  <span className="text-sm font-semibold">{plain.headline}</span>
                </span>
                <span className="font-mono text-xs">
                  {e.finding.file}:{e.finding.line} &middot; {e.finding.ruleId}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
