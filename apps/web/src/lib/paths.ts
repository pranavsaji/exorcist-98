import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

let cachedRoot: string | null = null;

/**
 * The monorepo root. EXORCIST_ROOT overrides it (use in deployments that copy
 * definitions/ and fixtures/ somewhere else). Otherwise walk up from the
 * working directory to the folder that holds pnpm-workspace.yaml.
 */
export function repoRoot(): string {
  const fromEnv = process.env['EXORCIST_ROOT'];
  if (fromEnv) return resolve(fromEnv);
  if (cachedRoot) return cachedRoot;

  let dir = process.cwd();
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(dir, 'pnpm-workspace.yaml'))) {
      cachedRoot = dir;
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('Could not locate the repository root (set EXORCIST_ROOT).');
}

export const definitionsDir = (): string => join(repoRoot(), 'definitions');
export const hauntedRepoDir = (): string => join(repoRoot(), 'fixtures', 'haunted-repo');
