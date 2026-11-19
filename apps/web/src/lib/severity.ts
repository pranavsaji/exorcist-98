import type { Severity } from './protocol';

export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low'];

export type Shape = 'diamond' | 'triangle' | 'square' | 'circle';

export const SEVERITY_INFO: Record<Severity, { label: string; shape: Shape; rank: number }> = {
  critical: { label: 'CRITICAL', shape: 'diamond',  rank: 0 },
  high:     { label: 'HIGH',     shape: 'triangle', rank: 1 },
  medium:   { label: 'MEDIUM',   shape: 'square',   rank: 2 },
  low:      { label: 'LOW',      shape: 'circle',   rank: 3 },
};

type Sortable = { severity: Severity; file: string; line: number };

/** Worst first; ties by file then line. Does not mutate the input. */
export function sortFindings<T extends Sortable>(findings: readonly T[]): T[] {
  return [...findings].sort((a, b) => {
    const r = SEVERITY_INFO[a.severity].rank - SEVERITY_INFO[b.severity].rank;
    if (r !== 0) return r;
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    return a.line - b.line;
  });
}

/** The worst severity present, or 'clean'. */
export function overallLevel(findings: readonly { severity: Severity }[]): Severity | 'clean' {
  let best: Severity | 'clean' = 'clean';
  for (const f of findings) {
    if (best === 'clean' || SEVERITY_INFO[f.severity].rank < SEVERITY_INFO[best].rank) {
      best = f.severity;
    }
  }
  return best;
}
