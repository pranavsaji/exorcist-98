import { activeDefinitions, staleness } from '@exorcist-98/core';
import type { LookupOptions } from '@exorcist-98/core';
import type { Io } from './util.js';

/**
 * One warning on stderr, once per process run, when the definitions in use are more than 30
 * days old (m9-adoption 5). Compares two dates; no network. Never writes to stdout.
 */
let warned = false;
let clock: (() => Date) | null = null;

/** Tests only: allow the warning again. */
export function resetStaleWarning(): void { warned = false; }
/** Tests only: fix the clock the commands use (null restores the real one). */
export function setStaleClock(fn: (() => Date) | null): void { clock = fn; }

/** True when --definitions or EXORCIST_DEFINITIONS points to a custom folder. */
export function usesCustomDefinitions(explicit: string | undefined, env: NodeJS.ProcessEnv = process.env): boolean {
  return Boolean(explicit) || Boolean(env['EXORCIST_DEFINITIONS']);
}

export function warnIfStale(io: Io, o: { custom: boolean; now?: Date; lookup?: LookupOptions }): void {
  if (warned || o.custom) return;
  const active = activeDefinitions(o.lookup ?? {});
  const s = staleness(active.date, o.now ?? clock?.() ?? new Date());
  if (!s.stale) return;
  warned = true;
  io.err(
    `The virus definitions are ${s.days} days old (${active.date}). New attacks may be missed. ` +
    'Update: exorcist update --from <https-url-or-file>, or install the latest @exorcist-98/cli.',
  );
}
