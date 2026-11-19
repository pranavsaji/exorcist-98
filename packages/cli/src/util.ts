import { existsSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import type { ParseArgsConfig } from 'node:util';

export type Io = { out: (s: string) => void; err: (s: string) => void };

export const stdio: Io = {
  out: (s) => void process.stdout.write(s.endsWith('\n') ? s : `${s}\n`),
  err: (s) => void process.stderr.write(s.endsWith('\n') ? s : `${s}\n`),
};

const hasDefinitions = (dir: string): boolean => {
  try { return existsSync(dir) && readdirSync(dir).some((f) => /^EX-\d{3}.*\.yaml$/.test(f)); } catch { return false; }
};

/**
 * Where the virus definitions are: --definitions, EXORCIST_DEFINITIONS, the
 * copy shipped next to the bundle, the repository's own folder (development),
 * or ./definitions.
 */
export function findDefinitionsDir(explicit?: string): string | null {
  if (explicit) return resolve(explicit);
  const env = process.env['EXORCIST_DEFINITIONS'];
  if (env) return resolve(env);
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [join(here, '..', 'definitions'), join(here, '..', '..', '..', 'definitions'), resolve('definitions')];
  return candidates.find(hasDefinitions) ?? null;
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

export const DEFAULT_DIR = '.exorcist';
