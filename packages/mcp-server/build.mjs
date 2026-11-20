// Bundles the MCP server into one runnable file and ships the definitions.
//   node build.mjs  ->  dist/index.mjs  and  definitions/
import { build } from 'esbuild';
import { cpSync, mkdirSync, rmSync, existsSync, renameSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const here = fileURLToPath(new URL('.', import.meta.url));

rmSync(join(here, 'dist'), { recursive: true, force: true });
mkdirSync(join(here, 'dist'), { recursive: true });

await build({
  entryPoints: [join(here, 'src/index.ts')],
  outfile: join(here, 'dist/index.mjs'),
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  logLevel: 'warning',
  banner: {
    js: '#!/usr/bin/env node\nimport { createRequire as __exorcistCreateRequire } from "node:module";\nconst require = __exorcistCreateRequire(import.meta.url);',
  },
  external: ['@aws-sdk/*', 'simple-git'],
});

// Copy into a fresh folder, then swap it in with renames, so a process reading
// definitions/ while a build runs (parallel tests do) never sees it missing or
// half-copied.
const target = join(here, 'definitions');
const fresh = `${target}.new-${process.pid}`;
const stale = `${target}.old-${process.pid}`;
rmSync(fresh, { recursive: true, force: true });
cpSync(join(here, '../../definitions'), fresh, {
  recursive: true,
  filter: (src) => !src.endsWith('.gitkeep'),
});
if (existsSync(target)) renameSync(target, stale);
renameSync(fresh, target);
rmSync(stale, { recursive: true, force: true });
console.log('built dist/index.mjs and definitions/');
