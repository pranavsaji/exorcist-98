// Pure and browser-safe: no Node imports.
export type Staleness = { stale: boolean; days: number };

const DAY_MS = 86_400_000;

/** Whole days from `dateIso` to `now`, and whether that is more than `days`. An invalid date is not stale. */
export function staleness(dateIso: string, now: Date = new Date(), days = 30): Staleness {
  const then = Date.parse(dateIso);
  const at = now.getTime();
  if (Number.isNaN(then) || Number.isNaN(at)) return { stale: false, days: 0 };
  const age = Math.floor((at - then) / DAY_MS);
  return { stale: age > days, days: age };
}
