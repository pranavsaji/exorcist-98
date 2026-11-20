import { existsSync, readdirSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Shared lookups for the CLI and the MCP server, so they cannot drift (S-019).
 */

function hasDefinitions(dir: string): boolean {
  try {
    return statSync(dir).isDirectory() && readdirSync(dir).some((f) => /^EX-\d{3}.*\.yaml$/.test(f));
  } catch {
    return false;
  }
}

export type DefinitionsLookup = {
  /** `--definitions` from the command line. */
  explicit?: string;
  /** Usually `import.meta.url` of the caller's bundle: definitions ship next to it. */
  callerUrl: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
};

/** The virus definitions folder: explicit, then EXORCIST_DEFINITIONS, then next to the bundle, the repo, the cwd. */
export function findDefinitionsDir(o: DefinitionsLookup): string | null {
  const env = o.env ?? process.env;
  const cwd = o.cwd ?? process.cwd();
  if (o.explicit) return resolve(cwd, o.explicit);
  const fromEnv = env['EXORCIST_DEFINITIONS'];
  if (fromEnv) return resolve(cwd, fromEnv);
  const here = dirname(fileURLToPath(o.callerUrl));
  const candidates = [join(here, '..', 'definitions'), join(here, '..', '..', '..', 'definitions'), join(cwd, 'definitions')];
  return candidates.find(hasDefinitions) ?? null;
}

const PROJECT_MARKERS = ['.exorcist', '.kiro', '.git'];

/**
 * The Shield's state folder (pins, policy, alerts, vault) when `--dir` is not
 * given (S-013). An MCP client may start the server outside the project, so
 * a bare relative `.exorcist` could land anywhere. Order: `EXORCIST_DIR`, then
 * the nearest folder at or above `cwd` that holds `.exorcist`, `.kiro` or
 * `.git`, then `cwd`. Always absolute. The Shield, `approve` and `alerts` use
 * the same rule, so they always agree.
 */
export function findStateDir(o: { explicit?: string; cwd?: string; env?: NodeJS.ProcessEnv } = {}): string {
  const env = o.env ?? process.env;
  const cwd = resolve(o.cwd ?? process.cwd());
  if (o.explicit) return resolve(cwd, o.explicit);
  const fromEnv = env['EXORCIST_DIR'];
  if (fromEnv) return isAbsolute(fromEnv) ? fromEnv : resolve(cwd, fromEnv);
  const { root } = parse(cwd);
  for (let dir = cwd; ; dir = dirname(dir)) {
    if (PROJECT_MARKERS.some((m) => existsSync(join(dir, m)))) return join(dir, '.exorcist');
    if (dir === root || dirname(dir) === dir) break;
  }
  return join(cwd, '.exorcist');
}
