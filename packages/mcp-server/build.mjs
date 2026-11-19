// Bundles the MCP server into one runnable file and ships the definitions.
//   node build.mjs  ->  dist/index.mjs  and  definitions/
import { build } from 'esbuild';
import { cpSync, mkdirSync, rmSync } from 'node:fs';
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

rmSync(join(here, 'definitions'), { recursive: true, force: true });
cpSync(join(here, '../../definitions'), join(here, 'definitions'), {
  recursive: true,
  filter: (src) => !src.endsWith('.gitkeep'),
});
console.log('built dist/index.mjs and definitions/');
