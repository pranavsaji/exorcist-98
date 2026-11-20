import { findDefinitionsDir as sharedFindDefinitionsDir, findStateDir } from '@exorcist-98/shield';
import { parseArgs } from 'node:util';
import type { ParseArgsConfig } from 'node:util';

export type Io = { out: (s: string) => void; err: (s: string) => void };

export const stdio: Io = {
  out: (s) => void process.stdout.write(s.endsWith('\n') ? s : `${s}\n`),
  err: (s) => void process.stderr.write(s.endsWith('\n') ? s : `${s}\n`),
};


/**
 * Where the virus definitions are: --definitions, EXORCIST_DEFINITIONS, the
 * copy shipped next to the bundle, the repository's own folder (development),
 * or ./definitions.
 */
export function findDefinitionsDir(explicit?: string): string | null {
  return sharedFindDefinitionsDir({ ...(explicit ? { explicit } : {}), callerUrl: import.meta.url });
}

/** The Shield's state folder: `--dir`, else EXORCIST_DIR, else the project's `.exorcist` (S-013). */
export function stateDir(explicit?: string): string {
  return findStateDir(explicit ? { explicit } : {});
}

export type Parsed<T> = { ok: true; values: T; positionals: string[] } | { ok: false; error: string };

/** parseArgs that returns an error value instead of throwing. */
export function parse<T extends ParseArgsConfig['options']>(
  argv: string[],
  options: T,
): Parsed<Record<string, string | boolean | Array<string | boolean> | undefined>> {
  try {
    const r = parseArgs({ args: argv, options, allowPositionals: true, strict: true });
    return { ok: true, values: r.values as Record<string, string | boolean | Array<string | boolean> | undefined>, positionals: r.positionals };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

export const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
export const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

/** How the default state folder is described in help text. */
export const DEFAULT_DIR = "the project's .exorcist folder (or EXORCIST_DIR)";
