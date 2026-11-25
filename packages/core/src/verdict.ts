// Pure and browser-safe: no Node imports.
import type { Severity } from './types.js';

export type VerdictLevel = Severity | 'clean';
export type Verdict = { word: 'CLEAN' | 'HAUNTED' | 'POSSESSED'; line: string };

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function verdictFor(level: VerdictLevel): Verdict {
  if (level === 'clean') return { word: 'CLEAN', line: 'Nothing here tries to give your AI agent orders.' };
  if (level === 'critical' || level === 'high') return { word: 'POSSESSED', line: 'Your AI agent would read these as orders. Fix them first.' };
  return { word: 'HAUNTED', line: 'Nothing urgent, but worth a look before your agent reads it.' };
}

/** The worst severity in the list, or 'clean' when it is empty. */
export function worstLevel(findings: readonly { severity: Severity }[]): VerdictLevel {
  let best: VerdictLevel = 'clean';
  for (const f of findings) {
    if (best === 'clean' || RANK[f.severity] < RANK[best]) best = f.severity;
  }
  return best;
}

export function verdictForFindings(findings: readonly { severity: Severity }[]): Verdict {
  return verdictFor(worstLevel(findings));
}
