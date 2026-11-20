import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The repository root: the nearest folder above this file with pnpm-workspace.yaml (L-043). */
function findRoot(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    if (existsSync(resolve(dir, 'pnpm-workspace.yaml'))) return dir;
    const up = dirname(dir);
    if (up === dir) throw new Error('pnpm-workspace.yaml not found above the tests');
    dir = up;
  }
}

export const REPO_ROOT = findRoot();
/** A path inside the repository, e.g. fromRoot('definitions'). */
export const fromRoot = (...parts: string[]): string => resolve(REPO_ROOT, ...parts);
