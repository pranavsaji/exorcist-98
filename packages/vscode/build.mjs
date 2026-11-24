// Bundles the extension (and the parts of @exorcist-98/core it uses) into one
// file, and ships the virus definitions next to it.
//
//   node build.mjs   ->  dist/extension.js  and  dist/definitions/
//
// Same approach as packages/cli/build.mjs. `vscode` is provided by the editor.
// The core is marked side-effect free so modules the extension never calls
// (git, live update, the registry lookup, the AI layer) are left out of the
// bundle entirely; a check below fails the build if anything that can start
// a process or open a network connection is still required.
import { build } from 'esbuild';
import { copyFileSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const here = fileURLToPath(new URL('.', import.meta.url));
const dist = join(here, 'dist');
mkdirSync(dist, { recursive: true });
const outfile = join(dist, 'extension.js');
const tmpOut = join(dist, `extension.js.tmp-${process.pid}`);
const production = process.argv.includes('--production') || process.env.npm_lifecycle_event === 'vscode:prepublish';

/**
 * Treat the workspace core package as free of import-time side effects, so
 * esbuild drops every core module whose exports the extension does not use.
 */
const coreSideEffectFree = {
  name: 'core-side-effect-free',
  setup(b) {
    b.onResolve({ filter: /.*/ }, async (args) => {
      if (args.pluginData?.exorcistResolved) return undefined;
      const fromCore = /packages[\\/]core[\\/]src[\\/]/.test(args.importer);
      if (args.path !== '@exorcist-98/core' && !(fromCore && args.path.startsWith('.'))) return undefined;
      const r = await b.resolve(args.path, {
        kind: args.kind, importer: args.importer, resolveDir: args.resolveDir, pluginData: { exorcistResolved: true },
      });
      if (r.errors.length > 0) return { errors: r.errors };
      return { path: r.path, sideEffects: false };
    });
  },
};

const result = await build({
  entryPoints: [join(here, 'src/extension.ts')],
  outfile: tmpOut,
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node18',
  logLevel: 'warning',
  minify: production,
  sourcemap: false,
  metafile: true,
  external: ['vscode'],
  plugins: [coreSideEffectFree],
});
renameSync(tmpOut, outfile);

// Nothing that runs programs or talks to the network may be bundled.
const FORBIDDEN = ['child_process', 'node:child_process', 'http', 'node:http', 'https', 'node:https', 'net', 'node:net', 'tls', 'node:tls', 'dgram', 'node:dgram', 'worker_threads', 'node:worker_threads'];
const bundled = readFileSync(outfile, 'utf8');
const hits = FORBIDDEN.filter((m) => bundled.includes(`require("${m}")`));
const network = /\bfetch\s*\(/.test(bundled) ? ['fetch('] : [];
if (hits.length + network.length > 0) {
  rmSync(outfile, { force: true });
  console.error(`dist/extension.js would include ${[...hits, ...network].join(', ')}; the extension must not run programs or use the network.`);
  console.error('Inputs:', Object.keys(result.metafile.inputs).filter((p) => p.includes('core')).join('\n  '));
  process.exit(1);
}

// The virus definitions, copied in place (see packages/cli/build.mjs).
const source = join(here, '../../definitions');
const target = join(dist, 'definitions');
mkdirSync(target, { recursive: true });
const wanted = new Set(readdirSync(source).filter((f) => f.endsWith('.yaml') && statSync(join(source, f)).isFile()));
for (const f of wanted) {
  const tmp = join(target, `.${f}.tmp-${process.pid}`);
  copyFileSync(join(source, f), tmp);
  renameSync(tmp, join(target, f));
}
for (const f of readdirSync(target)) {
  if (!wanted.has(f) && !/\.tmp-\d+$/.test(f)) rmSync(join(target, f), { recursive: true, force: true });
}
console.log(`built dist/extension.js (${Math.round(bundled.length / 1024)} KB) and dist/definitions/ (${wanted.size} files)`);
