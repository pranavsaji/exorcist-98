// Bundles the CLI (and the workspace packages it uses) into one runnable file
// and ships the virus definitions next to it.
//
//   node build.mjs   ->  dist/index.mjs  and  definitions/
import { build } from 'esbuild';
import { copyFileSync, mkdirSync, readdirSync, renameSync, rmSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const here = fileURLToPath(new URL('.', import.meta.url));

// Build to a temporary file and rename it into place, so a test file running
// the bundle while another test file rebuilds it (vitest runs files in
// parallel) never finds dist/index.mjs missing or half-written.
mkdirSync(join(here, 'dist'), { recursive: true });
const outfile = join(here, 'dist/index.mjs');
const tmpOut = join(here, `dist/index.mjs.tmp-${process.pid}`);

await build({
  entryPoints: [join(here, 'src/index.ts')],
  outfile: tmpOut,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  logLevel: 'warning',
  // Some bundled CommonJS packages call require().
  banner: {
    js: '#!/usr/bin/env node\nimport { createRequire as __exorcistCreateRequire } from "node:module";\nconst require = __exorcistCreateRequire(import.meta.url);',
  },
  // The AI heuristic layer is not part of the CLI.
  external: ['@aws-sdk/*', 'simple-git'],
});
renameSync(tmpOut, outfile);

// Update definitions/ in place, one file at a time: each file is written to a
// temporary name and renamed over the old one (an atomic replace), then files
// no longer in the source are removed. The folder itself never disappears, so
// a process reading it while a build runs (parallel tests do) always finds
// every file it listed, whole. (Swapping the whole folder with two renames
// left a moment with no folder at all, and a reader there got ENOENT.)
const source = join(here, '../../definitions');
const target = join(here, 'definitions');
mkdirSync(target, { recursive: true });
const wanted = new Set(readdirSync(source).filter((f) => !f.endsWith('.gitkeep') && statSync(join(source, f)).isFile()));
for (const f of wanted) {
  const tmp = join(target, `.${f}.tmp-${process.pid}`);
  copyFileSync(join(source, f), tmp);
  renameSync(tmp, join(target, f));
}
for (const f of readdirSync(target)) {
  if (!wanted.has(f) && !/\.tmp-\d+$/.test(f)) rmSync(join(target, f), { recursive: true, force: true });
}
console.log('built dist/index.mjs and definitions/');
