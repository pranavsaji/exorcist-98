'use client';

import { useState } from 'react';
import { HauntedHouseMap } from './HauntedHouseMap';
import { SeverityBadge } from './SeverityBadge';
import { plainFor } from '@/lib/plain';
import { SEVERITY_ORDER, sortFindings } from '@/lib/severity';
import type { FindingEntry } from '@/lib/scan-state';
import type { HauntedMapMsg } from '@/lib/protocol';

type Props = {
  findings:   FindingEntry[];
  /** Whether a scan has finished, so an empty list can say "clean". */
  scanDone?:  boolean;
  selectedId: number | null;
  onSelect:   (id: number) => void;
  /** The Haunted House Map, when the scan found MCP configs (m5-trifecta). */
  map?:       HauntedMapMsg | null;
};

export type View = 'list' | 'map';

/**
 * The threats found, worst first. When the scan found MCP configs, a second
 * view shows the Haunted House Map of them.
 */
export function ResultsWindow({ findings, selectedId, onSelect, scanDone = false, map = null, initialView = 'list', view: viewProp, onViewChange }: Props & { initialView?: View; view?: View; onViewChange?: (v: View) => void }) {
  const [inner, setInner] = useState<View>(initialView);
  // Controlled when the desktop passes a view (a ?open=map link), uncontrolled otherwise.
  const view = viewProp ?? inner;
  const setView = onViewChange ?? setInner;
  const hasMap = map !== null && map.configs.length > 0;
  if (!hasMap) return <ThreatList findings={findings} selectedId={selectedId} onSelect={onSelect} scanDone={scanDone} />;
  const lethal = map.configs.filter((c) => c.trifecta).length;
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-2" role="group" aria-label="Results view">
        <button type="button" className="btn" aria-pressed={view === 'list'} onClick={() => setView('list')}>
          Threat list
        </button>
        <button type="button" className="btn" aria-pressed={view === 'map'} onClick={() => setView('map')}>
          Haunted House Map{lethal > 0 ? ` (${lethal} trifecta${lethal === 1 ? '' : 's'})` : ''}
        </button>
      </div>
      {view === 'map'
        ? <HauntedHouseMap map={map} />
        : <ThreatList findings={findings} selectedId={selectedId} onSelect={onSelect} scanDone={scanDone} />}
    </div>
  );
}

function ThreatList({ findings, selectedId, onSelect, scanDone = false }: Props) {
  if (findings.length === 0) {
    return (
      <p className="m-0 p-2 text-sm">
        {scanDone
          ? 'Clean. No threats found in this scan.'
          : 'No threats yet. Run a scan and anything suspicious will be listed here, worst first.'}
      </p>
    );
  }
  // One row per rule and line: several hits on the same line are one problem.
  const groups = new Map<string, { entry: FindingEntry; count: number }>();
  for (const e of findings) {
    const key = `${e.finding.ruleId}|${e.finding.severity}|${e.finding.file}|${e.finding.line}`;
    const g = groups.get(key);
    if (g) g.count++;
    else groups.set(key, { entry: e, count: 1 });
  }
  const counted = new Map([...groups.values()].map((g) => [g.entry.id, g.count]));
  const sorted = sortFindings([...groups.values()].map((g) => ({ ...g.entry, ...g.entry.finding })));
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
                  {(counted.get(e.id) ?? 1) > 1 && ` \u00b7 ${counted.get(e.id)} places on this line`}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
