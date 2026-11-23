/**
 * Build and sign a LiveUpdate definitions bundle (m5-liveupdate).
 *
 *   tsx scripts/sign-definitions.ts --version 20261201.1 --key ~/.exorcist-98/liveupdate-signing-key.pem
 *       [--definitions definitions] [--out dist/exorcist-definitions-20261201.1.tar]
 *
 * The Ed25519 private key (PKCS#8 PEM) comes from, in order: --key <path>,
 * EXORCIST_SIGNING_KEY_FILE (a path), or EXORCIST_SIGNING_KEY (the PEM itself,
 * `\n` escapes allowed). A key file inside this repository is refused, and the
 * key is never printed or written anywhere by this script.
 *
 * To make a new key pair (only when rotating the key embedded in
 * packages/core/src/liveupdate.ts):
 *
 *   tsx scripts/sign-definitions.ts --generate-key --key-out ~/.exorcist-98/liveupdate-signing-key.pem
 *
 * which writes the private key to that path (mode 600, never overwriting) and
 * prints only the public key and its fingerprint.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import {
  DEFINITIONS_PUBLIC_KEY, buildSignedBundle, collectDefinitionFiles, isValidVersion, makeKeyPair, publicKeyFingerprint, sha256,
} from '../packages/core/src/liveupdate.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function die(msg: string, code = 2): never {
  process.stderr.write(`${msg}\n`);
  process.exit(code);
}

/** True when `p` (or the folder it would be created in) is inside this repository. */
function insideRepo(p: string): boolean {
  let real = resolve(p);
  for (let d = real; ; d = dirname(d)) {
    if (existsSync(d)) { real = resolve(realpathSync(d), relative(d, real)); break; }
    if (dirname(d) === d) break;
  }
  const rel = relative(realpathSync(ROOT), real);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

const OPTIONS = {
  'generate-key': { type: 'boolean' },
  'key-out': { type: 'string' },
  version: { type: 'string' },
  key: { type: 'string' },
  definitions: { type: 'string' },
  out: { type: 'string' },
} as const;

function readArgs(): ReturnType<typeof parseArgs<{ options: typeof OPTIONS; strict: true }>>['values'] {
  try {
    return parseArgs({ options: OPTIONS, strict: true }).values;
  } catch (e) {
    return die((e as Error).message);
  }
}
const args = readArgs();

if (args['generate-key']) {
  const out = args['key-out'];
  if (!out) die('--generate-key needs --key-out <path> (outside this repository). The private key is never printed.');
  const path = resolve(out);
  if (insideRepo(path)) die(`Refusing to write a private key inside the repository (${path}).`);
  if (existsSync(path)) die(`${path} already exists. Refusing to overwrite a key.`);
  const { privateKeyPem, publicKeyPem } = makeKeyPair();
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, privateKeyPem, { mode: 0o600, flag: 'wx' });
  chmodSync(path, 0o600);
  process.stdout.write(`Private key written to ${path} (mode 600). Keep it there; never commit it.\n`);
  process.stdout.write(`Public key (embed as DEFINITIONS_PUBLIC_KEY in packages/core/src/liveupdate.ts):\n${publicKeyPem}`);
  process.stdout.write(`Fingerprint sha256(SPKI DER): ${publicKeyFingerprint(publicKeyPem) ?? '?'}\n`);
  process.exit(0);
}

const version = args.version;
if (!version) die('Usage: tsx scripts/sign-definitions.ts --version <YYYYMMDD.N> [--key <path>] [--definitions <dir>] [--out <file.tar>]');
if (!isValidVersion(version)) die(`--version must look like 20261201.1, not "${version}".`);

function readKey(): string {
  const keyPath = args.key ?? process.env['EXORCIST_SIGNING_KEY_FILE'];
  if (keyPath) {
    const path = resolve(keyPath);
    if (insideRepo(path)) die(`Refusing to use a private key stored inside the repository (${path}). Move it outside, for example ~/.exorcist-98/.`);
    try {
      const st = statSync(path);
      if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
        process.stderr.write(`Warning: ${path} is readable by other users. Run: chmod 600 ${path}\n`);
      }
      return readFileSync(path, 'utf8');
    } catch (e) {
      die(`Could not read the signing key at ${path} (${(e as NodeJS.ErrnoException).code ?? 'error'}).`);
    }
  }
  const raw = process.env['EXORCIST_SIGNING_KEY'];
  if (raw) return raw.includes('\\n') ? raw.replace(/\\n/g, '\n') : raw;
  return die('No signing key. Pass --key <path>, or set EXORCIST_SIGNING_KEY_FILE or EXORCIST_SIGNING_KEY.');
}

const defsDir = resolve(ROOT, args.definitions ?? 'definitions');
if (!existsSync(defsDir) || !statSync(defsDir).isDirectory()) die(`No definitions folder at ${defsDir}.`);
const files = collectDefinitionFiles(defsDir);
if (files.length === 0) die(`No EX-NNN-*.yaml definitions in ${defsDir}.`);

const built = buildSignedBundle({ files, version, privateKeyPem: readKey() });
if (!built.ok) die(`Not signed: ${built.error}`, 1);

const out = resolve(ROOT, args.out ?? `dist/exorcist-definitions-${version}.tar`);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, built.tar);

const signer = publicKeyFingerprint(built.publicKeyPem) ?? '?';
const trusted = publicKeyFingerprint(DEFINITIONS_PUBLIC_KEY) ?? '?';
process.stdout.write(`Signed ${files.length} definitions as version ${version} (${built.manifest.date})\n`);
process.stdout.write(`  ${out}\n  ${built.tar.length} bytes, sha256 ${sha256(built.tar)}\n`);
process.stdout.write(`  Signing key sha256: ${signer}\n`);
if (signer !== trusted) {
  process.stderr.write(`Warning: this key is not the one built into Exorcist 98 (sha256 ${trusted}), so stock installs will refuse the bundle.\n`);
}
