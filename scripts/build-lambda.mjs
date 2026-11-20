// Bundles the scan Lambda (packages/core/src/lambda/handler.ts) into one file
// and copies definitions/ next to it (L-031). Zip the output folder's contents
// and upload; Lambda unpacks them to /var/task, where the handler looks for
// /var/task/definitions by default.
//
//   node scripts/build-lambda.mjs   ->  dist/lambda/index.mjs and dist/lambda/definitions/
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
// esbuild is a dev dependency of the CLI package; reuse it rather than add one.
const { build } = createRequire(join(ROOT, 'packages/cli/package.json'))('esbuild');
const OUT = join(ROOT, 'dist/lambda');
rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
await build({
  entryPoints: [join(ROOT, 'packages/core/src/lambda/handler.ts')],
  outfile: join(OUT, 'index.mjs'),
  bundle: true, platform: 'node', target: 'node22', format: 'esm',
  // The AWS SDK ships with the Lambda Node runtime.
  external: ['@aws-sdk/*'],
  banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
  logLevel: 'warning',
});
cpSync(join(ROOT, 'definitions'), join(OUT, 'definitions'), { recursive: true });
console.log(`Built ${OUT}`);
