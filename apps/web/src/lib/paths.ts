import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

let cachedRoot: string | null = null;

const isRoot = (dir: string): boolean =>
  existsSync(join(dir, 'pnpm-workspace.yaml')) ||
  // A standalone deployment ships only the files the server needs.
  (existsSync(join(dir, 'definitions')) && existsSync(join(dir, 'fixtures', 'haunted-repo')));

/**
 * The folder that holds definitions/ and fixtures/. EXORCIST_ROOT overrides it.
 * Otherwise walk up from the working directory: in the monorepo that finds
 * pnpm-workspace.yaml; in a standalone deployment it finds the traced copies.
 */
export function repoRoot(): string {
  const fromEnv = process.env['EXORCIST_ROOT'];
  if (fromEnv) return resolve(fromEnv);
  if (cachedRoot) return cachedRoot;

  let dir = process.cwd();
  for (let i = 0; i < 8; i++) {
    if (isRoot(dir)) {
      cachedRoot = dir;
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('Could not locate the definitions folder (set EXORCIST_ROOT).');
}

export const definitionsDir = (): string => join(repoRoot(), 'definitions');
export const hauntedRepoDir = (): string => join(repoRoot(), 'fixtures', 'haunted-repo');
