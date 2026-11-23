/**
 * Build and sign a LiveUpdate definitions bundle (m5-liveupdate).
 *
 *   EXORCIST_SIGNING_KEY="<pkcs8 PEM>" pnpm exec tsx scripts/sign-definitions.ts \
 *       --version 20261201.1 --out dist/exorcist-definitions.tar
 *
 * The private key is read from the environment (EXORCIST_SIGNING_KEY) and is
 * never written to the repository. To create a key pair once:
 *
 *   pnpm exec tsx scripts/sign-definitions.ts --generate-key
 *
 * which prints a fresh private key (for the environment) and the public key
 * to embed in DEFAULT_PUBLIC_KEY (packages/core/src/liveupdate.ts) — or to set
 * in EXORCIST_DEFINITIONS_PUBLIC_KEY for clients.
 *
 * The bundle is an uncompressed tar of definitions/*.yaml, manifest.json and
 * manifest.sig (Ed25519 over the manifest bytes).
 */
import { readdirSync, readFileSync, statSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeKeyPair, buildManifest, signManifest, buildTar, sha256, isValidVersion, DEFAULT_PUBLIC_KEY, trustedPublicKey } from '../packages/core/src/liveupdate.js';
import type { BundleFile } from '../packages/core/src/liveupdate.js';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..');

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? undefined : process.argv[i + 1];
}

if (process.argv.includes('--generate-key')) {
  const { privateKeyPem, publicKeyPem } = makeKeyPair();
  console.log('Private key — keep this in your password manager / CI secret, set as EXORCIST_SIGNING_KEY:');
  console.log(privateKeyPem);
  console.log('Public key — embed as DEFAULT_PUBLIC_KEY (packages/core/src/liveupdate.ts) or set EXORCIST_DEFINITIONS_PUBLIC_KEY:');
  console.log(publicKeyPem);
  process.exit(0);
}

const version = arg('version');
const outArg = arg('out');
const date = arg('date') ?? new Date().toISOString().slice(0, 10);
const defsDir = resolve(ROOT, arg('definitions') ?? 'definitions');

if (!version || !outArg) {
  console.error('Usage: EXORCIST_SIGNING_KEY=<PEM> tsx scripts/sign-definitions.ts --version <YYYYMMDD.N> [--date <YYYY-MM-DD>] [--definitions <dir>] --out <file.tar>');
  process.exit(2);
}
if (!isValidVersion(version)) {
  console.error(`--version must look like 20261201.1, got "${version}".`);
  process.exit(2);
}

// Accept the key either as real PEM (multiline in the environment) or as a
// single-line value with \n escapes, so it fits .env files.
const rawKey = process.env['EXORCIST_SIGNING_KEY'] ?? '';
const privateKeyPem = rawKey.includes('\\n') ? rawKey.replace(/\\n/g, '\n') : rawKey;
if (!privateKeyPem || !privateKeyPem.includes('PRIVATE KEY')) {
  console.error('Set EXORCIST_SIGNING_KEY to the PKCS#8 private key (see --generate-key). It is never committed.');
  process.exit(2);
}

if (!existsSync(defsDir) || !statSync(defsDir).isDirectory()) {
  console.error(`No definitions folder at ${defsDir}.`);
  process.exit(2);
}

const names = readdirSync(defsDir).filter((f) => /^EX-\d{3}.*\.yaml$/.test(f)).sort();
if (names.length === 0) {
  console.error(`No definition YAML files in ${defsDir}.`);
  process.exit(2);
}

const entries: BundleFile[] = names.map((name) => ({
  path: `definitions/${name}`,
  data: readFileSync(join(defsDir, name)),
}));

const manifestJson = buildManifest(entries, version, date);
const sig = signManifest(manifestJson, privateKeyPem);
const tar = buildTar([
  ...entries,
  { path: 'manifest.json', data: Buffer.from(manifestJson, 'utf8') },
  { path: 'manifest.sig', data: sig },
]);

const out = resolve(ROOT, outArg);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, tar);

console.log(`Signed ${names.length} definitions as version ${version} (${date}) -> ${out}`);
console.log(`Bundle: ${sha256(tar)}  ${tar.length} bytes`);
console.log(`Trusted public key (default embedded):\n${trustedPublicKey({ EXORCIST_DEFINITIONS_PUBLIC_KEY: process.env['EXORCIST_DEFINITIONS_PUBLIC_KEY'] } as NodeJS.ProcessEnv) === DEFAULT_PUBLIC_KEY ? 'embedded key' : 'environment override'}`);
