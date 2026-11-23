/**
 * LiveUpdate (m5-liveupdate): signed definition update bundles.
 *
 * A bundle is an uncompressed tar holding exactly `manifest.json`,
 * `manifest.sig` and `definitions/EX-NNN*.yaml`. The manifest lists the
 * version, the date and the sha256 of every definition file; `manifest.sig` is
 * an Ed25519 signature of the exact manifest bytes. A definitions feed is
 * itself a perfect attack channel, so everything fails closed:
 *
 * - the tar reader accepts only plain files with those names: no links, no
 *   directories, no `..`, no absolute paths, no duplicates, no extras;
 * - the signature is checked before the manifest is even parsed;
 * - every hash, every YAML file (definitions schema) and the version must pass;
 * - the install writes to a staging folder, re-verifies it from disk, then
 *   renames it into `<root>/<version>/`, so a failure never touches the sets
 *   already there;
 * - an installed set is re-verified (signature, hashes, exact file list, no
 *   symlinks) every time it is chosen, so a tampered install folder is skipped.
 *
 * Node's `crypto` does all the cryptography: no new dependencies.
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as edSign, verify as edVerify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { z } from 'zod';
import yaml from 'js-yaml';
import { VirusDefinitionSchema } from './definitions/schema.js';
import type { VirusDefinition } from './definitions/schema.js';
import { BUNDLED_DEFINITIONS_DATE, BUNDLED_DEFINITIONS_VERSION } from './definitions/version.js';

export { BUNDLED_DEFINITIONS_DATE, BUNDLED_DEFINITIONS_VERSION };

/**
 * The only key this build trusts for definition bundles (Ed25519, SPKI PEM).
 * There is deliberately no environment override: the trust anchor ships with
 * the code. Its private half is kept outside the repository by the
 * maintainer; tests make their own throwaway key pairs in memory.
 */
export const DEFINITIONS_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAn4o+dmOJXIzsygT2CF/3go/1E/bk9Ub16r4hGtJJjhM=
-----END PUBLIC KEY-----
`;

export const DOWNLOAD_LIMIT_BYTES = 2 * 1024 * 1024;
export const DOWNLOAD_TIMEOUT_MS = 15_000;
const MAX_REDIRECTS = 3;
const MAX_ENTRIES = 256;
const MAX_FILE_BYTES = 512 * 1024;

export const MANIFEST_NAME = 'manifest.json';
export const SIGNATURE_NAME = 'manifest.sig';
/** `definitions/` plus a file name the loader and the lookup both accept. */
const DEFINITION_PATH_RE = /^definitions\/EX-\d{3}[A-Za-z0-9._-]*\.yaml$/;

export type Fail = { ok: false; error: string };
const fail = (error: string): Fail => ({ ok: false, error });

/** Untrusted text (tar names, YAML errors) made safe to print on a terminal. */
function printable(s: string, max = 120): string {
  const clean = s.replace(/[^\x20-\x7e]/g, (c) => `\\u{${(c.codePointAt(0) ?? 0).toString(16)}}`);
  return JSON.stringify(clean.length > max ? `${clean.slice(0, max)}...` : clean);
}

// ── Versions ─────────────────────────────────────────────────────────────

const VERSION_RE = /^(\d{4})(\d{2})(\d{2})\.(\d{1,4})$/;

/** A version is a release date and a same-day sequence: 20261123.4. */
export function isValidVersion(v: string): boolean {
  const m = VERSION_RE.exec(v);
  if (!m) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (y < 2020) return false;
  const t = new Date(Date.UTC(y, mo - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === mo - 1 && t.getUTCDate() === d;
}

/** The YYYY-MM-DD date a version was released on. Assumes a valid version. */
export function versionDate(v: string): string {
  return `${v.slice(0, 4)}-${v.slice(4, 6)}-${v.slice(6, 8)}`;
}

/** -1 when a < b, 0 when equal, 1 when a > b. Assumes valid versions. */
export function compareVersions(a: string, b: string): number {
  const [ad = '0', an = '0'] = a.split('.');
  const [bd = '0', bn = '0'] = b.split('.');
  const day = Number(ad) - Number(bd);
  if (day !== 0) return day < 0 ? -1 : 1;
  const n = Number(an) - Number(bn);
  return n < 0 ? -1 : n > 0 ? 1 : 0;
}

// ── Keys ──────────────────────────────────────────────────────────────────

/** A fresh Ed25519 key pair as PEM strings (for --generate-key and tests). */
export function makeKeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

function loadPublicKey(pem: string): KeyObject | null {
  try {
    const key = createPublicKey(pem);
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

/** sha256 (hex) of the key's SPKI DER encoding, or null when it is not an Ed25519 public key. */
export function publicKeyFingerprint(publicKeyPem: string): string | null {
  const key = loadPublicKey(publicKeyPem);
  return key ? sha256(key.export({ type: 'spki', format: 'der' })) : null;
}

/** Parse an Ed25519 private key (PKCS#8 PEM) and derive its public key. */
export function loadPrivateKey(pem: string): { ok: true; key: KeyObject; publicKeyPem: string } | Fail {
  try {
    const key = createPrivateKey(pem);
    if (key.asymmetricKeyType !== 'ed25519') return fail('The signing key is not an Ed25519 private key.');
    const publicKeyPem = createPublicKey(key).export({ type: 'spki', format: 'pem' }).toString();
    return { ok: true, key, publicKeyPem };
  } catch {
    return fail('The signing key is not a readable PKCS#8 PEM private key.');
  }
}

// ── Manifest ─────────────────────────────────────────────────────────────

export const ManifestSchema = z
  .object({
    format: z.literal(1),
    version: z.string().refine(isValidVersion, 'version must look like 20261123.4'),
    date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'date must be YYYY-MM-DD'),
    files: z
      .record(z.string().regex(DEFINITION_PATH_RE, 'every file must be definitions/EX-NNN-name.yaml'),
        z.string().regex(/^[0-9a-f]{64}$/, 'each file hash must be a lowercase sha256 hex string'))
      .refine((m) => Object.keys(m).length > 0, 'files must list at least one definition')
      .refine((m) => Object.keys(m).length <= MAX_ENTRIES, `files must list at most ${MAX_ENTRIES} definitions`),
  })
  .strict()
  .refine((m) => !isValidVersion(m.version) || m.date === versionDate(m.version), 'date must be the date in the version');
export type Manifest = z.infer<typeof ManifestSchema>;

export type BundleFile = { path: string; data: Buffer };

export function sha256(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

const byPath = (a: BundleFile, b: BundleFile): number => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);

/** The manifest bytes for a set of definition files: keys sorted, stable formatting. */
export function buildManifest(files: BundleFile[], version: string, date: string = versionDate(version)): Buffer {
  const sorted = [...files].sort(byPath);
  const manifest = { format: 1, version, date, files: Object.fromEntries(sorted.map((f) => [f.path, sha256(f.data)])) };
  return Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}

/** Sign the exact manifest bytes with an Ed25519 private key (PEM or KeyObject). */
export function signManifest(manifest: Buffer, privateKey: string | KeyObject): Buffer {
  return edSign(null, manifest, privateKey);
}

// ── Tar (ustar, plain files only) ───────────────────────────────────────────

const BLOCK = 512;

function tarHeader(name: string, size: number, mtime: number, type = '0'): Buffer {
  const h = Buffer.alloc(BLOCK);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100, 'ascii');
  h.write('0000000\0', 108, 'ascii');
  h.write('0000000\0', 116, 'ascii');
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'ascii');
  h.write(`${Math.max(0, Math.floor(mtime)).toString(8).padStart(11, '0')}\0`, 136, 'ascii');
  h.write('        ', 148, 'ascii');
  h.write(type, 156, 'ascii');
  h.write('ustar\0', 257, 'ascii');
  h.write('00', 263, 'ascii');
  const sum = h.reduce((a, b) => a + b, 0);
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
  return h;
}

/**
 * An uncompressed ustar archive. `type` defaults to '0' (plain file); tests
 * use other types to build hostile archives. Deterministic for a given mtime.
 */
export function buildTar(entries: Array<BundleFile & { type?: string }>, mtime = 0): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    if (Buffer.byteLength(e.path) > 99) throw new Error(`tar path too long: ${e.path}`);
    const pad = (BLOCK - (e.data.length % BLOCK)) % BLOCK;
    parts.push(tarHeader(e.path, e.data.length, mtime, e.type), e.data, Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(BLOCK * 2)); // end of archive
  return Buffer.concat(parts);
}

function cstr(b: Buffer): string {
  const z0 = b.indexOf(0);
  return (z0 === -1 ? b : b.subarray(0, z0)).toString('utf8');
}

function octal(b: Buffer): number | null {
  const s = cstr(b).trim();
  if (!/^[0-7]{1,12}$/.test(s)) return null;
  return parseInt(s, 8);
}

/**
 * Read a bundle tar, strictly. Every entry must be a plain file named
 * `manifest.json`, `manifest.sig` or `definitions/EX-NNN*.yaml`; anything
 * else fails the whole bundle rather than being skipped.
 */
export function readBundleTar(tar: Buffer): { ok: true; entries: BundleFile[] } | Fail {
  if (tar.length > DOWNLOAD_LIMIT_BYTES) return fail(`The bundle is larger than the ${DOWNLOAD_LIMIT_BYTES / 1048576} MB limit.`);
  if (tar.length === 0) return fail('The bundle is empty.');
  if (tar.length % BLOCK !== 0) return fail('The bundle is not a tar archive (its size is not a whole number of 512-byte blocks).');
  const entries: BundleFile[] = [];
  const seen = new Set<string>();
  for (let off = 0; ;) {
    if (off + BLOCK > tar.length) return fail('The bundle is truncated (no end-of-archive marker).');
    const h = tar.subarray(off, off + BLOCK);
    if (h.every((b) => b === 0)) {
      if (!tar.subarray(off).every((b) => b === 0)) return fail('The bundle has data after its end-of-archive marker.');
      break;
    }
    const stored = octal(h.subarray(148, 156));
    let sum = 0;
    for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : (h[i] ?? 0);
    if (stored === null || stored !== sum) return fail('The bundle has a tar header with a bad checksum.');
    const prefix = cstr(h.subarray(345, 500));
    const name = cstr(h.subarray(0, 100));
    const path = prefix ? `${prefix}/${name}` : name;
    const type = String.fromCharCode(h[156] ?? 0);
    if (type === '1' || type === '2') return fail(`The bundle entry ${printable(path)} is a link. Bundles hold plain files only.`);
    if (type !== '0' && type !== '\0') return fail(`The bundle entry ${printable(path)} is not a plain file (tar type ${printable(type)}).`);
    if (path.startsWith('/') || /^[A-Za-z]:/.test(path) || path.includes('\\') || path.split('/').includes('..')) {
      return fail(`The bundle entry ${printable(path)} tries to escape the install folder (path traversal).`);
    }
    if (path !== MANIFEST_NAME && path !== SIGNATURE_NAME && !DEFINITION_PATH_RE.test(path)) {
      return fail(`The bundle has an unexpected entry ${printable(path)}. Only manifest.json, manifest.sig and definitions/EX-NNN-*.yaml are allowed.`);
    }
    if (seen.has(path)) return fail(`The bundle has ${printable(path)} twice.`);
    seen.add(path);
    const size = octal(h.subarray(124, 136));
    if (size === null) return fail(`The bundle entry ${printable(path)} has an unreadable size.`);
    if (size > MAX_FILE_BYTES) return fail(`The bundle entry ${printable(path)} is larger than ${MAX_FILE_BYTES / 1024} KB.`);
    const start = off + BLOCK;
    if (start + size > tar.length) return fail('The bundle is truncated.');
    entries.push({ path, data: Buffer.from(tar.subarray(start, start + size)) });
    if (entries.length > MAX_ENTRIES + 2) return fail(`The bundle has more than ${MAX_ENTRIES} definitions.`);
    off = start + Math.ceil(size / BLOCK) * BLOCK;
  }
  return { ok: true, entries };
}

// ── Verifying a bundle ─────────────────────────────────────────────────────

export type VerifiedBundle = {
  manifest: Manifest;
  manifestBytes: Buffer;
  sig: Buffer;
  /** Definition files, sorted by path (`definitions/...`). */
  files: BundleFile[];
  definitions: VirusDefinition[];
};

function verifySignature(manifestBytes: Buffer, sig: Buffer, publicKeyPem: string): Fail | null {
  const key = loadPublicKey(publicKeyPem);
  if (!key) return fail('The trusted public key is not a usable Ed25519 key.');
  if (sig.length !== 64) return fail('manifest.sig is not a 64-byte Ed25519 signature.');
  if (!edVerify(null, manifestBytes, key, sig)) {
    return fail('The manifest signature does not match: the bundle was not signed by the Exorcist 98 definitions key, or it was changed after signing.');
  }
  return null;
}

function parseManifest(manifestBytes: Buffer): { ok: true; manifest: Manifest } | Fail {
  let json: unknown;
  try {
    json = JSON.parse(manifestBytes.toString('utf8'));
  } catch {
    return fail('manifest.json is not valid JSON.');
  }
  const parsed = ManifestSchema.safeParse(json);
  if (!parsed.success) return fail(`Invalid manifest: ${parsed.error.issues.map((i) => i.message).join('; ')}`);
  return { ok: true, manifest: parsed.data };
}

/** Every definition file must be valid YAML for the definitions schema, with its id matching its file name. */
export function validateDefinitionFiles(files: BundleFile[]): { ok: true; definitions: VirusDefinition[] } | Fail {
  const out: VirusDefinition[] = [];
  const ids = new Set<string>();
  for (const f of [...files].sort(byPath)) {
    let doc: unknown;
    try {
      doc = yaml.load(f.data.toString('utf8'));
    } catch (e) {
      return fail(`${f.path} is not valid YAML: ${printable((e as Error).message.split('\n')[0] ?? '')}`);
    }
    const parsed = VirusDefinitionSchema.safeParse(doc);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      return fail(`${f.path} is not a valid definition: ${issue ? `${issue.path.join('.') || '(root)'}: ${issue.message}` : 'schema error'}`);
    }
    const fileId = basename(f.path).slice(0, 6);
    if (parsed.data.id !== fileId) return fail(`${f.path} defines ${printable(parsed.data.id)}, not ${fileId}.`);
    if (ids.has(parsed.data.id)) return fail(`${parsed.data.id} is defined twice.`);
    ids.add(parsed.data.id);
    out.push(parsed.data);
  }
  return { ok: true, definitions: out };
}

/**
 * Full check of a bundle tarball: strict tar, signature (before the manifest
 * is parsed), manifest schema, every hash, no files outside the manifest,
 * every YAML file. Pure: touches no disk.
 */
export function checkBundle(tar: Buffer, o: { publicKeyPem?: string } = {}): { ok: true; bundle: VerifiedBundle } | Fail {
  const read = readBundleTar(tar);
  if (!read.ok) return read;
  const manifestBytes = read.entries.find((e) => e.path === MANIFEST_NAME)?.data;
  const sig = read.entries.find((e) => e.path === SIGNATURE_NAME)?.data;
  if (!manifestBytes) return fail('The bundle has no manifest.json.');
  if (!sig) return fail('The bundle has no manifest.sig.');
  const bad = verifySignature(manifestBytes, sig, o.publicKeyPem ?? DEFINITIONS_PUBLIC_KEY);
  if (bad) return bad;
  const m = parseManifest(manifestBytes);
  if (!m.ok) return m;
  const files = read.entries.filter((e) => DEFINITION_PATH_RE.test(e.path)).sort(byPath);
  const listed = m.manifest.files;
  for (const [path, hash] of Object.entries(listed)) {
    const f = files.find((x) => x.path === path);
    if (!f) return fail(`The bundle is missing ${path}, which its manifest lists.`);
    if (sha256(f.data) !== hash) return fail(`${path} does not match its hash in the manifest: the file was changed after signing.`);
  }
  const extra = files.filter((f) => listed[f.path] === undefined).map((f) => f.path);
  if (extra.length > 0) return fail(`The bundle hides files its manifest does not list: ${extra.join(', ')}.`);
  const valid = validateDefinitionFiles(files);
  if (!valid.ok) return valid;
  return { ok: true, bundle: { manifest: m.manifest, manifestBytes, sig, files, definitions: valid.definitions } };
}

/** Build and sign a bundle tarball. Fails when the files would not pass `checkBundle`. */
export function buildSignedBundle(o: {
  files: BundleFile[];
  version: string;
  privateKeyPem: string;
}): { ok: true; tar: Buffer; manifest: Manifest; publicKeyPem: string } | Fail {
  if (!isValidVersion(o.version)) return fail(`The version must look like 20261201.1, not ${printable(o.version)}.`);
  const key = loadPrivateKey(o.privateKeyPem);
  if (!key.ok) return key;
  const manifestBytes = buildManifest(o.files, o.version);
  const sig = signManifest(manifestBytes, key.key);
  const mtime = Date.parse(`${versionDate(o.version)}T00:00:00Z`) / 1000;
  const tar = buildTar([...[...o.files].sort(byPath), { path: MANIFEST_NAME, data: manifestBytes }, { path: SIGNATURE_NAME, data: sig }], mtime);
  const check = checkBundle(tar, { publicKeyPem: key.publicKeyPem });
  if (!check.ok) return check;
  return { ok: true, tar, manifest: check.bundle.manifest, publicKeyPem: key.publicKeyPem };
}

/** The definition files of a definitions folder, as bundle entries. */
export function collectDefinitionFiles(dir: string): BundleFile[] {
  return readdirSync(dir)
    .filter((f) => DEFINITION_PATH_RE.test(`definitions/${f}`) && lstatSync(join(dir, f)).isFile())
    .sort()
    .map((f) => ({ path: `definitions/${f}`, data: readFileSync(join(dir, f)) }));
}

// ── Installed sets ────────────────────────────────────────────────────────

export type InstalledSet = {
  /** `<root>/<version>` */
  dir: string;
  /** `<root>/<version>/definitions`, what the scanner loads. */
  definitionsDir: string;
  version: string;
  date: string;
  files: number;
};

/** Where installed sets live: EXORCIST_DEFINITIONS_HOME, else ~/.exorcist/definitions. */
export function installedDefinitionsRoot(env: NodeJS.ProcessEnv = process.env): string {
  const fromEnv = env['EXORCIST_DEFINITIONS_HOME'];
  if (fromEnv) return resolve(fromEnv);
  return join(env['HOME'] || env['USERPROFILE'] || homedir(), '.exorcist', 'definitions');
}

/**
 * Verify a set folder as `installBundle` writes it, from disk: no symlinks,
 * the signature over manifest.json, the version equal to `expectedVersion`,
 * exactly the listed files in definitions/ and every hash.
 */
function verifySetFolder(dir: string, expectedVersion: string, publicKeyPem: string): { ok: true; set: InstalledSet } | Fail {
  try {
    if (!lstatSync(dir).isDirectory()) return fail('not a real folder (a symlink or a file)');
    const defsDir = join(dir, 'definitions');
    for (const [p, kind] of [[join(dir, MANIFEST_NAME), 'file'], [join(dir, SIGNATURE_NAME), 'file'], [defsDir, 'dir']] as const) {
      const st = lstatSync(p);
      if (kind === 'file' ? !st.isFile() : !st.isDirectory()) return fail(`${basename(p)} is not a plain ${kind === 'file' ? 'file' : 'folder'}`);
    }
    const manifestBytes = readFileSync(join(dir, MANIFEST_NAME));
    const bad = verifySignature(manifestBytes, readFileSync(join(dir, SIGNATURE_NAME)), publicKeyPem);
    if (bad) return fail('the manifest signature does not verify');
    const m = parseManifest(manifestBytes);
    if (!m.ok) return m;
    if (m.manifest.version !== expectedVersion) return fail(`the folder is named ${expectedVersion} but holds version ${m.manifest.version}`);
    const listed = Object.keys(m.manifest.files).map((p) => p.slice('definitions/'.length)).sort();
    const onDisk = readdirSync(defsDir).sort();
    const extra = onDisk.filter((n) => !listed.includes(n));
    if (extra.length > 0) return fail(`definitions/ holds files the manifest does not list: ${extra.map((n) => printable(n)).join(', ')}`);
    for (const name of listed) {
      const p = join(defsDir, name);
      let st;
      try { st = lstatSync(p); } catch { return fail(`definitions/${name} is missing`); }
      if (!st.isFile()) return fail(`definitions/${name} is not a plain file`);
      if (sha256(readFileSync(p)) !== m.manifest.files[`definitions/${name}`]) return fail(`definitions/${name} was changed after it was installed`);
    }
    return { ok: true, set: { dir, definitionsDir: defsDir, version: m.manifest.version, date: m.manifest.date, files: listed.length } };
  } catch (e) {
    return fail(`unreadable (${(e as NodeJS.ErrnoException).code ?? 'error'})`);
  }
}

/** Verify one installed set folder `<root>/<version>`. */
export function verifyInstalledSet(dir: string, publicKeyPem: string = DEFINITIONS_PUBLIC_KEY): { ok: true; set: InstalledSet } | Fail {
  const name = basename(dir);
  if (!isValidVersion(name)) return fail(`${printable(name)} is not a version folder`);
  return verifySetFolder(dir, name, publicKeyPem);
}

export type InspectedSet = { name: string; dir: string } & ({ ok: true; set: InstalledSet } | Fail);

/** Every version folder under `root`, verified or with the reason it was rejected, newest first. */
export function inspectInstalledSets(root: string, publicKeyPem: string = DEFINITIONS_PUBLIC_KEY): InspectedSet[] {
  let names: string[];
  try {
    names = readdirSync(root);
  } catch {
    return []; // no root yet: nothing installed
  }
  return names
    .filter(isValidVersion)
    .sort((a, b) => compareVersions(b, a))
    .map((name) => ({ name, dir: join(root, name), ...verifyInstalledSet(join(root, name), publicKeyPem) }));
}

/** Every installed set that verifies, newest first. */
export function listInstalledSets(root: string, publicKeyPem: string = DEFINITIONS_PUBLIC_KEY): InstalledSet[] {
  return inspectInstalledSets(root, publicKeyPem).flatMap((s) => (s.ok ? [s.set] : []));
}

export type LookupOptions = { env?: NodeJS.ProcessEnv; root?: string; publicKeyPem?: string };

/**
 * The installed set to use instead of the bundled definitions: the newest one
 * that verifies right now, and only if it is newer than the bundled set.
 * Verifying one set reads a few dozen small files, so the folders are
 * checked newest first and the walk stops at the first good one.
 */
export function findActiveInstalledSet(o: LookupOptions = {}): InstalledSet | null {
  const root = o.root ?? installedDefinitionsRoot(o.env);
  const pem = o.publicKeyPem ?? DEFINITIONS_PUBLIC_KEY;
  let names: string[];
  try {
    names = readdirSync(root);
  } catch {
    return null;
  }
  const newer = names.filter((n) => isValidVersion(n) && compareVersions(n, BUNDLED_DEFINITIONS_VERSION) > 0).sort((a, b) => compareVersions(b, a));
  for (const name of newer) {
    const r = verifyInstalledSet(join(root, name), pem);
    if (r.ok) return r.set;
  }
  return null;
}

export type ActiveDefinitions = { version: string; date: string; source: 'installed' | 'bundled'; set?: InstalledSet };

/** The definitions version in use: the active installed set, else the bundled one. */
export function activeDefinitions(o: LookupOptions = {}): ActiveDefinitions {
  const set = findActiveInstalledSet(o);
  if (set) return { version: set.version, date: set.date, source: 'installed', set };
  return { version: BUNDLED_DEFINITIONS_VERSION, date: BUNDLED_DEFINITIONS_DATE, source: 'bundled' };
}

// ── Installing ────────────────────────────────────────────────────────────

/**
 * Verify a bundle and install it into `<root>/<version>/` atomically: it is
 * written to a staging folder, verified again from disk, then renamed into
 * place. Any failure removes the staging folder and leaves every existing set
 * as it was. Refuses a version that is not newer than `currentVersion`.
 */
export function installBundle(
  tar: Buffer,
  o: { root: string; currentVersion: string; publicKeyPem?: string },
): { ok: true; set: InstalledSet } | Fail {
  const pem = o.publicKeyPem ?? DEFINITIONS_PUBLIC_KEY;
  const checked = checkBundle(tar, { publicKeyPem: pem });
  if (!checked.ok) return checked;
  const b = checked.bundle;
  const version = b.manifest.version;
  if (compareVersions(version, o.currentVersion) <= 0) {
    return fail(`The bundle is version ${version}, which is not newer than the definitions in use (${o.currentVersion}).`);
  }
  const final = join(o.root, version);
  let exists = true;
  try { lstatSync(final); } catch { exists = false; }
  if (exists) return fail(`${final} already exists. Remove it to install version ${version} again.`);

  const staging = join(o.root, `.staging-${randomBytes(6).toString('hex')}`);
  try {
    mkdirSync(o.root, { recursive: true, mode: 0o700 });
    mkdirSync(staging, { mode: 0o700 });
    mkdirSync(join(staging, 'definitions'));
    for (const f of b.files) writeFileSync(join(staging, f.path), f.data, { flag: 'wx', mode: 0o644 });
    writeFileSync(join(staging, MANIFEST_NAME), b.manifestBytes, { flag: 'wx', mode: 0o644 });
    writeFileSync(join(staging, SIGNATURE_NAME), b.sig, { flag: 'wx', mode: 0o644 });
    const check = verifySetFolder(staging, version, pem);
    if (!check.ok) return fail(`The staged copy did not verify (${check.error}).`);
    renameSync(staging, final);
  } catch (e) {
    return fail(`The install failed (${(e as NodeJS.ErrnoException).code ?? (e as Error).message}).`);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
  const installed = verifyInstalledSet(final, pem);
  return installed.ok ? installed : fail(`The installed set did not verify (${installed.error}).`);
}

// ── Getting a bundle ─────────────────────────────────────────────────────

export type FetchResponse = {
  status: number;
  headers: { get(name: string): string | null };
  body: AsyncIterable<Uint8Array> | ReadableStream<Uint8Array> | null;
};
export type FetchLike = (
  url: string,
  init: { signal: AbortSignal; redirect: 'manual'; headers: Record<string, string> },
) => Promise<FetchResponse>;

function chunksOf(body: AsyncIterable<Uint8Array> | ReadableStream<Uint8Array>): AsyncIterator<Uint8Array> {
  if (Symbol.asyncIterator in body) return (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator]();
  const reader = (body as ReadableStream<Uint8Array>).getReader();
  return {
    next: async () => {
      const r = await reader.read();
      return r.done ? { done: true, value: undefined } : { done: false, value: r.value };
    },
    return: async () => {
      await reader.cancel().catch(() => undefined);
      return { done: true, value: undefined };
    },
  };
}

/**
 * Download a bundle: HTTPS only (redirects included, followed by hand so none
 * can drop to http), at most `limitBytes`, and the whole thing, redirects and
 * body, within `timeoutMs`.
 */
export async function downloadBundle(
  url: string,
  o: { limitBytes?: number; timeoutMs?: number; fetchImpl?: FetchLike } = {},
): Promise<{ ok: true; tar: Buffer } | Fail> {
  const limit = o.limitBytes ?? DOWNLOAD_LIMIT_BYTES;
  const timeout = o.timeoutMs ?? DOWNLOAD_TIMEOUT_MS;
  const doFetch: FetchLike = o.fetchImpl ?? ((u, init) => fetch(u, init));
  const ctrl = new AbortController();
  const aborted = new Promise<never>((_, rej) => {
    ctrl.signal.addEventListener('abort', () => rej(new Error('timeout')), { once: true });
  });
  aborted.catch(() => undefined);
  const timer = setTimeout(() => ctrl.abort(), timeout);
  let it: AsyncIterator<Uint8Array> | null = null;
  try {
    let current: URL;
    try { current = new URL(url); } catch { return fail('The update source is not a valid URL.'); }
    for (let hop = 0; ; hop++) {
      if (current.protocol !== 'https:') return fail(`Update downloads must use https://, not ${printable(current.protocol)}.`);
      const res = await Promise.race([doFetch(current.href, { signal: ctrl.signal, redirect: 'manual', headers: { 'user-agent': 'exorcist-98-liveupdate' } }), aborted]);
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get('location');
        if (!loc) return fail(`The update server answered ${res.status} without a location.`);
        if (hop >= MAX_REDIRECTS) return fail('The update server redirected too many times.');
        try { current = new URL(loc, current); } catch { return fail('The update server redirected to an invalid URL.'); }
        continue;
      }
      if (res.status !== 200) return fail(`The update server answered ${res.status}.`);
      const declared = Number(res.headers.get('content-length') ?? NaN);
      if (Number.isFinite(declared) && declared > limit) return fail(`The bundle is larger than the ${limit / 1048576} MB limit.`);
      if (!res.body) return fail('The update server sent no bundle.');
      it = chunksOf(res.body);
      const chunks: Buffer[] = [];
      let total = 0;
      for (;;) {
        const next = await Promise.race([it.next(), aborted]);
        if (next.done) break;
        total += next.value.length;
        if (total > limit) return fail(`The bundle is larger than the ${limit / 1048576} MB limit.`);
        chunks.push(Buffer.from(next.value));
      }
      it = null;
      if (total === 0) return fail('The update server sent an empty bundle.');
      return { ok: true, tar: Buffer.concat(chunks) };
    }
  } catch (e) {
    if (ctrl.signal.aborted) return fail(`The download did not finish within ${timeout / 1000} s.`);
    return fail(`The download failed: ${printable((e as Error).message)}`);
  } finally {
    clearTimeout(timer);
    if (it?.return) void it.return().catch(() => undefined);
    ctrl.abort();
  }
}

/** Read a local bundle file: a regular file of at most `limitBytes`. */
export function readBundleFile(path: string, limitBytes = DOWNLOAD_LIMIT_BYTES): { ok: true; tar: Buffer } | Fail {
  let fd: number | null = null;
  try {
    if (!statSync(path).isFile()) return fail(`${path} is not a regular file.`);
    fd = openSync(path, 'r');
    const st = fstatSync(fd);
    if (!st.isFile()) return fail(`${path} is not a regular file.`);
    if (st.size > limitBytes) return fail(`The bundle is larger than the ${limitBytes / 1048576} MB limit.`);
    const buf = Buffer.alloc(limitBytes + 1);
    let n = 0;
    for (;;) {
      const r = readSync(fd, buf, n, buf.length - n, null);
      if (r === 0) break;
      n += r;
      if (n > limitBytes) return fail(`The bundle is larger than the ${limitBytes / 1048576} MB limit.`);
    }
    if (n === 0) return fail('The bundle is empty.');
    return { ok: true, tar: Buffer.from(buf.subarray(0, n)) };
  } catch (e) {
    return fail(`Could not read ${path} (${(e as NodeJS.ErrnoException).code ?? 'error'}).`);
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

/** A bundle from an https:// URL or a local file path. Any other URL scheme is refused. */
export async function loadBundleSource(
  from: string,
  o: { fetchImpl?: FetchLike; timeoutMs?: number; cwd?: string } = {},
): Promise<{ ok: true; tar: Buffer } | Fail> {
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(from)) {
    if (!/^https:\/\//i.test(from)) return fail('The update source must be an https:// URL or a local file.');
    return downloadBundle(from, { ...(o.fetchImpl ? { fetchImpl: o.fetchImpl } : {}), ...(o.timeoutMs ? { timeoutMs: o.timeoutMs } : {}) });
  }
  return readBundleFile(resolve(o.cwd ?? process.cwd(), from));
}

/**
 * One LiveUpdate run: fetch or read the bundle, verify it and install it if
 * it is newer than the definitions in use.
 */
export async function runLiveUpdate(o: {
  from: string;
  root: string;
  publicKeyPem?: string;
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  cwd?: string;
}): Promise<{ ok: true; previous: ActiveDefinitions; set: InstalledSet } | (Fail & { previous: ActiveDefinitions })> {
  const lookup = { root: o.root, ...(o.publicKeyPem ? { publicKeyPem: o.publicKeyPem } : {}) };
  const previous = activeDefinitions(lookup);
  const src = await loadBundleSource(o.from, o);
  if (!src.ok) return { ...src, previous };
  const r = installBundle(src.tar, { ...lookup, currentVersion: previous.version });
  return r.ok ? { ok: true, previous, set: r.set } : { ...r, previous };
}
