/**
 * LiveUpdate (m5-liveupdate): signed definition update bundles.
 *
 * A bundle is an uncompressed tar of `definitions/*.yaml`, `manifest.json`
 * (version, date, sha256 per file) and `manifest.sig`, an Ed25519 signature
 * of the exact `manifest.json` bytes. Nothing is installed unless the
 * signature, every hash, every YAML file and the version all check out, and
 * the install itself is atomic, so a failed update never disturbs the
 * definitions in use.
 *
 * Node's `crypto` does all the cryptography: no new dependencies.
 */
import { createHash, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, renameSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { z } from 'zod';
import yaml from 'js-yaml';
import { readTar } from './remote/tarball.js';
import { VirusDefinitionSchema } from './definitions/schema.js';
import type { VirusDefinition } from './definitions/schema.js';

/** The public key this build trusts for definition bundles (Ed25519, SPKI PEM). */
export const DEFAULT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAui4+vxWUEpFiNqLN/uWfgazdJycpAtXhLW+bwH3OW+Y=
-----END PUBLIC KEY-----`;

/** Version and date of the definitions folder shipped with this build. */
export const BUNDLED_DEFINITIONS_VERSION = '20261123.0';
export const BUNDLED_DEFINITIONS_DATE = '2026-11-23';

export const DOWNLOAD_LIMIT_BYTES = 2 * 1024 * 1024;
export const DOWNLOAD_TIMEOUT_MS = 15_000;

export type LiveUpdateResult = { ok: true } | { ok: false; error: string };

// ── Versions ─────────────────────────────────────────────────────────────

const VERSION_RE = /^\d{8}\.\d{1,4}$/;

/** A version is a release date and a same-day sequence: 20261123.4. */
export function isValidVersion(v: string): boolean {
  if (!VERSION_RE.test(v)) return false;
  const y = Number(v.slice(0, 4));
  const m = Number(v.slice(4, 6));
  const d = Number(v.slice(6, 8));
  return y >= 2020 && m >= 1 && m <= 12 && d >= 1 && d <= 31;
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

export function makeKeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

function loadPublicKey(pem: string): KeyObject | null {
  try {
    return createPublicKey(pem);
  } catch {
    return null;
  }
}

/** The trust anchor: EXORCIST_DEFINITIONS_PUBLIC_KEY (PEM), else the embedded key. */
export function trustedPublicKey(env: NodeJS.ProcessEnv = process.env): string {
  return env['EXORCIST_DEFINITIONS_PUBLIC_KEY']?.trim() || DEFAULT_PUBLIC_KEY;
}

// ── Manifest and signing ─────────────────────────────────────────────────

export const ManifestSchema = z
  .object({
    version: z.string().refine(isValidVersion, 'version must look like 20261123.4'),
    date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'date must be YYYY-MM-DD'),
    files: z
      .record(z.string(), z.string().regex(/^[0-9a-f]{64}$/, 'each file hash must be a lowercase sha256 hex string'))
      .refine((m) => Object.keys(m).length > 0, 'files must list at least one definition')
      .refine(
        (m) => Object.keys(m).every((k) => /^definitions\/[A-Za-z0-9][A-Za-z0-9._-]*\.yaml$/.test(k)),
        'every file key must be definitions/<name>.yaml',
      ),
  })
  .strict();
export type Manifest = z.infer<typeof ManifestSchema>;

export type BundleFile = { path: string; data: Buffer };

export function sha256(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/** The manifest JSON for a set of files: keys sorted, stable formatting. */
export function buildManifest(files: BundleFile[], version: string, date: string): string {
  const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path));
  return `${JSON.stringify({ version, date, files: Object.fromEntries(sorted.map((f) => [f.path, sha256(f.data)])) }, null, 2)}\n`;
}

/** Sign the exact manifest.json bytes with an Ed25519 private key (PEM). */
export function signManifest(manifestJson: string, privateKeyPem: string): Buffer {
  return edSign(null, Buffer.from(manifestJson, 'utf8'), privateKeyPem);
}

// ── Tar writing (ustar, plain files only) ─────────────────────────────────

function tarHeader(name: string, size: number): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write('000644\0', 100, 'utf8');
  h.write('000000\0', 108, 'utf8');
  h.write('000000\0', 116, 'utf8');
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'utf8');
  h.write(`${Math.floor(Date.now() / 1000).toString(8).padStart(11, '0')}\0`, 136, 'utf8');
  h.write('        ', 148, 'utf8');
  h.write('0', 156, 'utf8');
  h.write('ustar\0', 257, 'utf8');
  h.write('00', 263, 'utf8');
  const sum = h.reduce((a, b) => a + b, 0);
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'utf8');
  return h;
}

/** Build an uncompressed ustar tarball of plain files. Paths must be short and relative. */
export function buildTar(entries: BundleFile[]): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    if (e.path.length > 99) throw new Error(`tar path too long: ${e.path}`);
    const pad = (512 - (e.data.length % 512)) % 512;
    parts.push(tarHeader(e.path, e.data.length), e.data, Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(1024)); // end of archive
  return Buffer.concat(parts);
}

// ── Parsing and verifying a bundle ─────────────────────────────────────────

export type ParsedBundle = {
  manifest: Manifest;
  manifestJson: string;
  sig: Buffer;
  /** Definition files keyed by their manifest path (`definitions/...`). */
  files: Map<string, Buffer>;
};

const BUNDLE_TAR_LIMITS = { maxFiles: 500, maxFileBytes: 512 * 1024, maxStoredBytes: DOWNLOAD_LIMIT_BYTES };

/** Read a bundle tarball into its manifest, signature and definition files. */
export function parseBundle(tar: Buffer): { ok: true; bundle: ParsedBundle } | { ok: false; error: string } {
  const r = readTar(tar, BUNDLE_TAR_LIMITS, false);
  if (!r.ok) return { ok: false, error: `The bundle is not a readable tar: ${r.error}` };
  const byPath = new Map(r.entries.filter((e) => e.path.startsWith('definitions/')).map((e) => [e.path, e.data]));
  const manifestEntry = r.entries.find((e) => e.path === 'manifest.json');
  const sigEntry = r.entries.find((e) => e.path === 'manifest.sig');
  if (!manifestEntry) return { ok: false, error: 'The bundle has no manifest.json.' };
  if (!sigEntry) return { ok: false, error: 'The bundle has no manifest.sig.' };
  const manifestJson = manifestEntry.data.toString('utf8');
  const parsed = ManifestSchema.safeParse(JSON.parse(manifestJson) as unknown);
  if (!parsed.success) {
    return { ok: false, error: `Invalid manifest: ${parsed.error.issues.map((i) => i.message).join('; ')}` };
  }
  if (sigEntry.data.length !== 64) return { ok: false, error: 'manifest.sig is not a 64-byte Ed25519 signature.' };
  return { ok: true, bundle: { manifest: parsed.data, manifestJson, sig: sigEntry.data, files: byPath } };
}

/**
 * Full verification: signature over the manifest bytes, every hash, and no
 * definition files hiding outside the manifest.
 */
export function verifyBundle(bundle: ParsedBundle, publicKeyPem: string): LiveUpdateResult {
  const key = loadPublicKey(publicKeyPem);
  if (!key) return { ok: false, error: 'The trusted public key is not a usable key.' };
  if (!edVerify(null, Buffer.from(bundle.manifestJson, 'utf8'), key, bundle.sig)) {
    return { ok: false, error: 'The manifest signature does not match: the bundle was not signed by the trusted key, or was tampered with.' };
  }
  for (const [path, hash] of Object.entries(bundle.manifest.files)) {
    const data = bundle.files.get(path);
    if (!data) return { ok: false, error: `The bundle is missing the listed file ${path}.` };
    if (sha256(data) !== hash) {
      return { ok: false, error: `${path} does not match its hash in the manifest: the file was changed after signing.` };
    }
  }
  const extra = [...bundle.files.keys()].filter((p) => bundle.manifest.files[p] === undefined);
  if (extra.length > 0) {
    return { ok: false, error: `The bundle hides files outside the manifest: ${extra.join(', ')}.` };
  }
  return { ok: true };
}

/** Every definition file must be valid YAML for the definitions schema. */
export function validateBundleDefinitions(
  bundle: ParsedBundle,
): { ok: true; definitions: VirusDefinition[] } | { ok: false; error: string } {
  const out: VirusDefinition[] = [];
  const sorted = [...bundle.files.keys()].sort();
  for (const path of sorted) {
    const raw = bundle.files.get(path)!.toString('utf8');
    let doc: unknown;
    try {
      doc = yaml.load(raw);
    } catch (e) {
      return { ok: false, error: `${path} is not valid YAML: ${(e as Error).message.split('\n')[0]}` };
    }
    const parsed = VirusDefinitionSchema.safeParse(doc);
    if (!parsed.success) {
      return { ok: false, error: `Invalid definition in ${path}: ${parsed.error.issues[0]?.message ?? 'schema error'}` };
    }
    out.push(parsed.data);
  }
  return { ok: true, definitions: out };
}

// ── Installed sets ────────────────────────────────────────────────────────

export type InstalledSet = { dir: string; version: string; date: string; files: number };

/** Where installed definition sets live: EXORCIST_DEFINITIONS_HOME, else ~/.exorcist/definitions. */
export function installedDefinitionsRoot(env: NodeJS.ProcessEnv = process.env, home: string = homedir()): string {
  const fromEnv = env['EXORCIST_DEFINITIONS_HOME'];
  if (fromEnv) return resolve(fromEnv);
  return join(home, '.exorcist', 'definitions');
}

/**
 * Verify a version folder on disk (the layout `installBundle` writes):
 * `definitions/*.yaml`, `manifest.json`, `manifest.sig`.
 */
export function verifyInstalledSet(dir: string, publicKeyPem: string): { ok: true; set: InstalledSet } | { ok: false; error: string } {
  try {
    const manifestJson = readFileSync(join(dir, 'manifest.json'), 'utf8');
    const sig = readFileSync(join(dir, 'manifest.sig'));
    const parsed = ManifestSchema.safeParse(JSON.parse(manifestJson) as unknown);
    if (!parsed.success) return { ok: false, error: 'manifest.json does not match the manifest schema.' };
    const key = loadPublicKey(publicKeyPem);
    if (!key) return { ok: false, error: 'unusable public key' };
    if (!edVerify(null, Buffer.from(manifestJson, 'utf8'), key, sig)) return { ok: false, error: 'bad signature' };
    const names = readdirSync(join(dir, 'definitions')).filter((f) => f.endsWith('.yaml'));
    for (const [path, hash] of Object.entries(parsed.data.files)) {
      if (!names.includes(path.replace(/^definitions\//, ''))) return { ok: false, error: `missing ${path}` };
      if (sha256(readFileSync(join(dir, path))) !== hash) return { ok: false, error: `hash mismatch for ${path}` };
    }
    if (names.length !== Object.keys(parsed.data.files).length) return { ok: false, error: 'files on disk outside the manifest' };
    return { ok: true, set: { dir, version: parsed.data.version, date: parsed.data.date, files: names.length } };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

/** Every installed set that still verifies, newest first. */
export function listInstalledSets(
  root: string = installedDefinitionsRoot(),
  publicKeyPem: string = trustedPublicKey(),
): InstalledSet[] {
  const out: InstalledSet[] = [];
  try {
    for (const name of readdirSync(root)) {
      const dir = join(root, name);
      if (!/^\d{8}\.\d{1,4}$/.test(name)) continue;
      const r = verifyInstalledSet(dir, publicKeyPem);
      if (r.ok) out.push(r.set);
    }
  } catch {
    /* no root, or unreadable: no installed sets */
  }
  return out.sort((a, b) => compareVersions(b.version, a.version));
}

/** The newest installed set that verifies, or null. */
export function findNewestInstalledSet(o: { env?: NodeJS.ProcessEnv; root?: string; publicKeyPem?: string } = {}): InstalledSet | null {
  const root = o.root ?? installedDefinitionsRoot(o.env);
  const pem = o.publicKeyPem ?? trustedPublicKey(o.env);
  return listInstalledSets(root, pem)[0] ?? null;
}

/**
 * The definitions version currently in use: the newest verified installed
 * set, else the set bundled with the build.
 */
export function activeVersion(o: { env?: NodeJS.ProcessEnv; root?: string; publicKeyPem?: string } = {}): {
  version: string;
  date: string;
  source: 'installed' | 'bundled';
} {
  const installed = findNewestInstalledSet(o);
  if (installed && compareVersions(installed.version, BUNDLED_DEFINITIONS_VERSION) > 0) {
    return { version: installed.version, date: installed.date, source: 'installed' };
  }
  return { version: BUNDLED_DEFINITIONS_VERSION, date: BUNDLED_DEFINITIONS_DATE, source: 'bundled' };
}

// ── Installing ────────────────────────────────────────────────────────────

/**
 * Verify and install a bundle tarball into `<root>/<version>/`, atomically:
 * everything is written to a staging folder first and renamed into place
 * only when the whole set is on disk. Any failure leaves everything as it
 * was. Refuses a version that is not newer than the current one.
 */
export function installBundle(
  tar: Buffer,
  o: { root: string; currentVersion: string; publicKeyPem: string },
): { ok: true; set: InstalledSet } | { ok: false; error: string } {
  const parsed = parseBundle(tar);
  if (!parsed.ok) return parsed;
  const bundle = parsed.bundle;
  const verified = verifyBundle(bundle, o.publicKeyPem);
  if (!verified.ok) return verified;
  const valid = validateBundleDefinitions(bundle);
  if (!valid.ok) return valid;
  const cmp = compareVersions(bundle.manifest.version, o.currentVersion);
  if (cmp <= 0) {
    return {
      ok: false,
      error: `The bundle is version ${bundle.manifest.version}, which is not newer than the definitions in use (${o.currentVersion}). Nothing was installed.`,
    };
  }
  const final = join(o.root, bundle.manifest.version);
  if (existsSync(final)) {
    return { ok: false, error: `Version ${bundle.manifest.version} is already installed. Nothing was installed.` };
  }
  mkdirSync(o.root, { recursive: true });
  const staging = join(o.root, `.staging-${process.pid.toString(36)}-${Math.random().toString(36).slice(2, 8)}`);
  rmSync(staging, { recursive: true, force: true });
  try {
    mkdirSync(join(staging, 'definitions'), { recursive: true });
    for (const [path, data] of bundle.files) {
      writeFileSync(join(staging, path), data, { flag: 'wx' });
    }
    writeFileSync(join(staging, 'manifest.json'), bundle.manifestJson, 'utf8');
    writeFileSync(join(staging, 'manifest.sig'), bundle.sig);
    renameSync(staging, final);
  } catch (e) {
    rmSync(staging, { recursive: true, force: true });
    return { ok: false, error: `The install failed and was rolled back: ${(e as Error).message}` };
  }
  const check = verifyInstalledSet(final, o.publicKeyPem);
  if (!check.ok) {
    rmSync(final, { recursive: true, force: true });
    return { ok: false, error: `The installed set did not verify after install: ${check.error}. It was removed.` };
  }
  return { ok: true, set: check.set };
}

// ── Downloading ───────────────────────────────────────────────────────────

export type FetchLike = (
  url: string,
  init: { signal: AbortSignal; redirect: 'follow' },
) => Promise<{ ok: boolean; status: number; body: AsyncIterable<Uint8Array> | ReadableStream<Uint8Array> | null }>;

/** Download a bundle over HTTPS only, capped and on a timer. */
export async function downloadBundle(
  url: string,
  o: { limitBytes?: number; timeoutMs?: number; fetchImpl?: FetchLike } = {},
): Promise<{ ok: true; tar: Buffer } | { ok: false; error: string }> {
  if (!/^https:\/\//i.test(url)) {
    return { ok: false, error: 'Update URLs must be https:// addresses or local file paths.' };
  }
  const limit = o.limitBytes ?? DOWNLOAD_LIMIT_BYTES;
  const timeout = o.timeoutMs ?? DOWNLOAD_TIMEOUT_MS;
  const doFetch: FetchLike = o.fetchImpl ?? ((u, init) => fetch(u, init));
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await doFetch(url, { signal: ctrl.signal, redirect: 'follow' });
    if (!res.ok) return { ok: false, error: `The update server answered ${res.status}.` };
    if (!res.body) return { ok: false, error: 'The update server sent no bundle.' };
    const chunks: Buffer[] = [];
    let total = 0;
    // The read races the abort timer: a stalled (or hostile) server cannot
    // hold the download open past the timeout, signal or no signal.
    const aborted = new Promise<never>((_, rej) => {
      ctrl.signal.addEventListener('abort', () => rej(new Error('aborted')), { once: true });
    });
    const it = (res.body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator]();
    for (;;) {
      const next = await Promise.race([it.next(), aborted]);
      if (next.done) break;
      total += next.value.length;
      if (total > limit) {
        return { ok: false, error: `The bundle is larger than the ${Math.round(limit / 1024)} KB limit.` };
      }
      chunks.push(Buffer.from(next.value));
    }
    if (total === 0) return { ok: false, error: 'The update server sent an empty bundle.' };
    return { ok: true, tar: Buffer.concat(chunks) };
  } catch (e) {
    const err = e as Error;
    const msg = err.name === 'AbortError' || err.message === 'aborted'
      ? `The download did not finish within ${timeout / 1000} s.`
      : err.message;
    return { ok: false, error: `The download failed: ${msg}` };
  } finally {
    clearTimeout(timer);
  }
}
