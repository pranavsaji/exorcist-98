/**
 * m5-liveupdate: signed definition bundles. Every key pair here is generated
 * in memory by the test; no private key is stored anywhere.
 */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import * as fc from 'fast-check';
import { appendFileSync, lstatSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BUNDLED_DEFINITIONS_DATE, BUNDLED_DEFINITIONS_VERSION, DEFINITIONS_PUBLIC_KEY, DOWNLOAD_LIMIT_BYTES,
  activeDefinitions, buildManifest, buildSignedBundle, buildTar, checkBundle, collectDefinitionFiles, compareVersions,
  downloadBundle, findActiveInstalledSet, inspectInstalledSets, installBundle, installedDefinitionsRoot, isValidVersion,
  loadBundleSource, makeKeyPair, publicKeyFingerprint, readBundleFile, runLiveUpdate, sha256, signManifest, verifyInstalledSet,
  versionDate,
} from '../liveupdate.js';
import type { BundleFile, FetchLike, FetchResponse } from '../liveupdate.js';
import { fromRoot } from './repo-root.js';

const DEF = (id: string, title: string): string => `id: ${id}
title: ${title}
severity: high
applies_to:
  - instruction
match:
  regex: "LIVEUPDATE-TEST-[0-9]{4}"
owasp:
  - "LLM01:2025 Prompt Injection"
fix: Remove it.
`;

const KEY = makeKeyPair();
const OTHER = makeKeyPair();
const pem = KEY.publicKeyPem;
const BASE = BUNDLED_DEFINITIONS_VERSION;
const NEWER = '20261201.1';

const goodFiles = (): BundleFile[] => [
  { path: 'definitions/EX-900-demo-a.yaml', data: Buffer.from(DEF('EX-900', 'Demo A')) },
  { path: 'definitions/EX-901-demo-b.yaml', data: Buffer.from(DEF('EX-901', 'Demo B')) },
];

type Entry = BundleFile & { type?: string };

/** A bundle assembled by hand, so tests can break any part of it. */
function assemble(o: {
  files?: Entry[];
  version?: string;
  manifest?: Buffer;
  sig?: Buffer;
  key?: string;
  extra?: Entry[];
  omit?: Array<'manifest' | 'sig'>;
} = {}): Buffer {
  const files = o.files ?? goodFiles();
  const manifest = o.manifest ?? buildManifest(files, o.version ?? NEWER);
  const sig = o.sig ?? signManifest(manifest, o.key ?? KEY.privateKeyPem);
  return buildTar([
    ...files,
    ...(o.omit?.includes('manifest') ? [] : [{ path: 'manifest.json', data: manifest }]),
    ...(o.omit?.includes('sig') ? [] : [{ path: 'manifest.sig', data: sig }]),
    ...(o.extra ?? []),
  ]);
}

const dirs: string[] = [];
const tmp = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'exorcist-liveupdate-'));
  dirs.push(d);
  return d;
};
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** Every path and file hash under a folder, to prove a failed install changed nothing. */
function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string, rel: string): void => {
    let names: string[];
    try { names = readdirSync(d).sort(); } catch { return; }
    for (const n of names) {
      const p = join(d, n);
      const st = lstatSync(p);
      if (st.isDirectory()) { out.push(`${rel}${n}/`); walk(p, `${rel}${n}/`); } else out.push(`${rel}${n} ${st.isFile() ? sha256(readFileSync(p)) : 'link'}`);
    }
  };
  walk(dir, '');
  return out;
}

let root: string;
beforeEach(() => {
  root = join(tmp(), 'definitions');
});

function expectFail(r: { ok: boolean; error?: string }, text: string | RegExp): void {
  expect(r.ok).toBe(false);
  if (!r.ok) expect(r.error).toMatch(text);
}

/** Install must fail with `text` and leave an existing installed set exactly as it was. */
function expectInstallRefused(tar: Buffer, text: string | RegExp, currentVersion = BASE): void {
  if (!existsIn(root, '20261124.1')) {
    expect(installBundle(assemble({ version: '20261124.1' }), { root, currentVersion: BASE, publicKeyPem: pem }).ok).toBe(true);
  }
  const before = snapshot(root);
  expectFail(installBundle(tar, { root, currentVersion, publicKeyPem: pem }), text);
  expect(snapshot(root)).toEqual(before);
}

describe('versions and constants', () => {
  it('compares date-sequence versions and rejects malformed ones', () => {
    expect(compareVersions('20261201.1', '20261201.2')).toBe(-1);
    expect(compareVersions('20261202.1', '20261201.9')).toBe(1);
    expect(compareVersions('20261201.10', '20261201.9')).toBe(1);
    expect(compareVersions('20261201.3', '20261201.3')).toBe(0);
    for (const v of ['99.1', '20261332.1', '20260230.1', '20261201', '20261201.', '20261201.12345', '20191231.1', ' 20261201.1']) {
      expect(isValidVersion(v)).toBe(false);
    }
    expect(isValidVersion('20240229.0')).toBe(true);
    expect(versionDate('20261201.4')).toBe('2026-12-01');
  });

  it('the bundled version is valid and its date matches', () => {
    expect(isValidVersion(BUNDLED_DEFINITIONS_VERSION)).toBe(true);
    expect(BUNDLED_DEFINITIONS_DATE).toBe(versionDate(BUNDLED_DEFINITIONS_VERSION));
  });

  it('embeds an Ed25519 public key, and not the one whose private half was lost', () => {
    expect(publicKeyFingerprint(DEFINITIONS_PUBLIC_KEY)).toMatch(/^[0-9a-f]{64}$/);
    expect(DEFINITIONS_PUBLIC_KEY).not.toContain('ui4+vxWUEpFiNqLN');
    expect(publicKeyFingerprint('not a key')).toBeNull();
  });

  it('installs under ~/.exorcist/definitions unless EXORCIST_DEFINITIONS_HOME says otherwise', () => {
    expect(installedDefinitionsRoot({ HOME: '/home/someone' })).toBe(join('/home/someone', '.exorcist', 'definitions'));
    expect(installedDefinitionsRoot({ HOME: '/home/someone', EXORCIST_DEFINITIONS_HOME: '/x/y' })).toBe('/x/y');
  });
});

describe('a good bundle', () => {
  it('verifies, validates and installs atomically into <root>/<version>/', () => {
    const tar = assemble();
    const c = checkBundle(tar, { publicKeyPem: pem });
    expect(c.ok).toBe(true);
    if (c.ok) expect(c.bundle.definitions.map((d) => d.id)).toEqual(['EX-900', 'EX-901']);

    const r = installBundle(tar, { root, currentVersion: BASE, publicKeyPem: pem });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.set).toMatchObject({ version: NEWER, date: '2026-12-01', files: 2, dir: join(root, NEWER) });
    expect(readdirSync(root)).toEqual([NEWER]); // no staging folder left behind
    expect(readdirSync(join(root, NEWER)).sort()).toEqual(['definitions', 'manifest.json', 'manifest.sig']);
    expect(readdirSync(join(root, NEWER, 'definitions')).sort()).toEqual(['EX-900-demo-a.yaml', 'EX-901-demo-b.yaml']);
    expect(activeDefinitions({ root, publicKeyPem: pem })).toMatchObject({ version: NEWER, source: 'installed' });
  });

  it('the real definitions folder signs into a bundle that passes every check', () => {
    const files = collectDefinitionFiles(fromRoot('definitions'));
    expect(files.length).toBeGreaterThan(10);
    const b = buildSignedBundle({ files, version: NEWER, privateKeyPem: KEY.privateKeyPem });
    expect(b.ok).toBe(true);
    if (!b.ok) return;
    expect(b.tar.length).toBeLessThan(DOWNLOAD_LIMIT_BYTES);
    const c = checkBundle(b.tar, { publicKeyPem: pem });
    expect(c.ok && c.bundle.definitions.length).toBe(files.length);
    // ... and it is rejected by the embedded key, because this key is a throwaway.
    expectFail(checkBundle(b.tar), /signature/);
  });

  it('an installed set is only used while it is newer than the bundled definitions', () => {
    const old = installBundle(assemble({ version: '20261101.1' }), { root, currentVersion: '20200101.0', publicKeyPem: pem });
    expect(old.ok).toBe(true);
    expect(findActiveInstalledSet({ root, publicKeyPem: pem })).toBeNull();
    expect(activeDefinitions({ root, publicKeyPem: pem })).toMatchObject({ version: BASE, source: 'bundled' });
  });

  it('with no install folder at all, the bundled definitions are active', () => {
    expect(activeDefinitions({ root: join(tmp(), 'missing'), publicKeyPem: pem }).source).toBe('bundled');
  });
});

describe('fail closed: nothing is installed and existing sets are untouched', () => {
  it('tampered manifest (bytes changed after signing)', () => {
    const files = goodFiles();
    const manifest = buildManifest(files, NEWER);
    const sig = signManifest(manifest, KEY.privateKeyPem);
    const altered = Buffer.from(manifest.toString().replace(NEWER, '20261201.2'));
    expectInstallRefused(assemble({ files, manifest: altered, sig }), /signature does not match/);
  });

  it('tampered manifest that still parses: a hash swapped for another file', () => {
    const files = goodFiles();
    const manifest = buildManifest(files, NEWER);
    const sig = signManifest(manifest, KEY.privateKeyPem);
    const text = manifest.toString();
    const h0 = sha256(files[0]!.data);
    const evil = Buffer.from(text.replace(h0, sha256(Buffer.from('evil'))));
    expectInstallRefused(assemble({ files, manifest: evil, sig }), /signature does not match/);
  });

  it('tampered definition file', () => {
    const files = goodFiles();
    const manifest = buildManifest(files, NEWER);
    const tampered = files.map((f, i) => (i === 0 ? { ...f, data: Buffer.concat([f.data, Buffer.from('# evil\n')]) } : f));
    expectInstallRefused(assemble({ files: tampered, manifest }), /EX-900-demo-a\.yaml does not match its hash/);
  });

  it('wrong key', () => {
    expectInstallRefused(assemble({ key: OTHER.privateKeyPem }), /signature does not match/);
  });

  it('older and equal versions', () => {
    expectInstallRefused(assemble({ version: '20261101.1' }), /not newer/, '20261124.1');
    expectInstallRefused(assemble({ version: '20261124.1' }), /not newer|already exists/, '20261124.1');
    expect(existsIn(root, '20261101.1')).toBe(false);
  });

  it('a version folder that already exists', () => {
    expect(installBundle(assemble(), { root, currentVersion: BASE, publicKeyPem: pem }).ok).toBe(true);
    const before = snapshot(root);
    expectFail(installBundle(assemble(), { root, currentVersion: BASE, publicKeyPem: pem }), /already exists/);
    expect(snapshot(root)).toEqual(before);
  });

  it('oversize bundle', () => {
    const big = Buffer.alloc(DOWNLOAD_LIMIT_BYTES + 512);
    expectInstallRefused(big, /larger than the 2 MB limit/);
  });

  it('invalid YAML, a schema violation, an id that does not match its file, a duplicate id', () => {
    const one = (text: string, name = 'definitions/EX-902-bad.yaml'): Buffer => assemble({ files: [{ path: name, data: Buffer.from(text) }] });
    expectInstallRefused(one('id: EX-902\ntitle: [unclosed\n'), /is not valid YAML/);
    expectInstallRefused(one('id: EX-902\nseverity: bogus\n'), /is not a valid definition/);
    expectInstallRefused(one(DEF('EX-001', 'Impostor')), /defines "EX-001", not EX-902/);
    expectInstallRefused(assemble({ files: [
      { path: 'definitions/EX-903-a.yaml', data: Buffer.from(DEF('EX-903', 'A')) },
      { path: 'definitions/EX-903-b.yaml', data: Buffer.from(DEF('EX-903', 'B')) },
    ] }), /EX-903 is defined twice/);
  });

  it('path traversal in tar entry names', () => {
    for (const path of ['../EX-900-escape.yaml', 'definitions/../../EX-900-escape.yaml', '/tmp/EX-900-escape.yaml', 'definitions/..', 'C:/EX-900.yaml', 'definitions\\..\\EX-900.yaml']) {
      expectInstallRefused(assemble({ extra: [{ path, data: Buffer.from(DEF('EX-900', 'X')) }] }), /path traversal/);
    }
  });

  it('symlink and hard-link entries', () => {
    expectInstallRefused(assemble({ extra: [{ path: 'definitions/EX-904-link.yaml', data: Buffer.alloc(0), type: '2' }] }), /is a link/);
    expectInstallRefused(assemble({ extra: [{ path: 'definitions/EX-905-link.yaml', data: Buffer.alloc(0), type: '1' }] }), /is a link/);
  });

  it('directories, pax headers and any name that is not manifest.json, manifest.sig or definitions/EX-NNN*.yaml', () => {
    expectInstallRefused(assemble({ extra: [{ path: 'definitions/', data: Buffer.alloc(0), type: '5' }] }), /not a plain file/);
    expectInstallRefused(assemble({ extra: [{ path: 'PaxHeader', data: Buffer.from('20 path=../../x.yaml\n'), type: 'x' }] }), /not a plain file/);
    expectInstallRefused(assemble({ extra: [{ path: 'definitions/notes.txt', data: Buffer.from('hi') }] }), /unexpected entry/);
    expectInstallRefused(assemble({ extra: [{ path: 'install.sh', data: Buffer.from('echo hi') }] }), /unexpected entry/);
    expectInstallRefused(assemble({ extra: [{ path: 'definitions/sub/EX-906.yaml', data: Buffer.from('x') }] }), /unexpected entry/);
  });

  it('duplicate entries, unlisted files, missing files, missing manifest or signature', () => {
    const files = goodFiles();
    const manifest = buildManifest(files, NEWER);
    expectInstallRefused(assemble({ files, manifest, extra: [files[0]!] }), /twice/);
    expectInstallRefused(assemble({ files, manifest, extra: [{ path: 'definitions/EX-907-smuggled.yaml', data: Buffer.from(DEF('EX-907', 'S')) }] }), /does not list: definitions\/EX-907/);
    expectInstallRefused(assemble({ files: [files[0]!], manifest }), /missing definitions\/EX-901/);
    expectInstallRefused(assemble({ omit: ['manifest'] }), /no manifest\.json/);
    expectInstallRefused(assemble({ omit: ['sig'] }), /no manifest\.sig/);
    expectInstallRefused(assemble({ sig: Buffer.alloc(10) }), /64-byte/);
  });

  it('malformed archives: truncated, bad checksum, data after the end, not a tar', () => {
    const good = assemble();
    expectInstallRefused(good.subarray(0, 1024), /truncated/);
    const bad = Buffer.from(good);
    bad[0] = (bad[0] ?? 0) ^ 1;
    expectInstallRefused(bad, /checksum/);
    expectInstallRefused(Buffer.concat([good, Buffer.from('x'.repeat(512))]), /after its end-of-archive/);
    expectInstallRefused(Buffer.from('not a tar'), /not a tar archive/);
    expectInstallRefused(Buffer.alloc(0), /empty/);
  });

  it('a signed manifest that is not valid JSON, has the wrong format, or a date that is not its version date', () => {
    const files = goodFiles();
    expectInstallRefused(assemble({ files, manifest: Buffer.from('{not json') }), /not valid JSON/);
    const withFormat = (f: number): Buffer => Buffer.from(buildManifest(files, NEWER).toString().replace('"format": 1', `"format": ${f}`));
    expectInstallRefused(assemble({ files, manifest: withFormat(2) }), /Invalid manifest/);
    const wrongDate = Buffer.from(buildManifest(files, NEWER).toString().replace('"2026-12-01"', '"2026-12-02"'));
    expectInstallRefused(assemble({ files, manifest: wrongDate }), /date must be the date in the version/);
    expectInstallRefused(assemble({ files, version: '99.1' }), /Invalid manifest/);
  });

  it('checks the signature before it parses the manifest', () => {
    expectFail(checkBundle(assemble({ manifest: Buffer.from('{not json'), key: OTHER.privateKeyPem }), { publicKeyPem: pem }), /signature/);
  });

  it('property: flipping any byte never yields a verified bundle with different content', () => {
    const tar = assemble();
    const original = checkBundle(tar, { publicKeyPem: pem });
    expect(original.ok).toBe(true);
    if (!original.ok) return;
    const contents = original.bundle.files.map((f) => `${f.path}:${sha256(f.data)}`).join('|');
    fc.assert(
      fc.property(fc.integer({ min: 0, max: tar.length - 1 }), fc.integer({ min: 1, max: 255 }), (pos, mask) => {
        const t = Buffer.from(tar);
        t[pos] = (t[pos] ?? 0) ^ mask;
        const r = checkBundle(t, { publicKeyPem: pem });
        if (r.ok) expect(r.bundle.files.map((f) => `${f.path}:${sha256(f.data)}`).join('|')).toBe(contents);
      }),
      { numRuns: 300 },
    );
  });
});

function existsIn(dir: string, name: string): boolean {
  try { return readdirSync(dir).includes(name); } catch { return false; }
}

describe('an installed set is re-verified every time it is chosen', () => {
  function installTwo(): { older: string; newer: string } {
    expect(installBundle(assemble({ version: '20261124.1' }), { root, currentVersion: BASE, publicKeyPem: pem }).ok).toBe(true);
    expect(installBundle(assemble({ version: NEWER }), { root, currentVersion: '20261124.1', publicKeyPem: pem }).ok).toBe(true);
    expect(findActiveInstalledSet({ root, publicKeyPem: pem })?.version).toBe(NEWER);
    return { older: join(root, '20261124.1'), newer: join(root, NEWER) };
  }
  const reasonFor = (name: string): string => {
    const s = inspectInstalledSets(root, pem).find((x) => x.name === name);
    return s && !s.ok ? s.error : 'ok';
  };

  it('a changed definition file: the set is skipped and the next good one is used', () => {
    const { newer } = installTwo();
    appendFileSync(join(newer, 'definitions', 'EX-900-demo-a.yaml'), '# changed\n');
    expect(findActiveInstalledSet({ root, publicKeyPem: pem })?.version).toBe('20261124.1');
    expect(reasonFor(NEWER)).toMatch(/changed after it was installed/);
  });

  it('a changed manifest', () => {
    const { newer } = installTwo();
    const m = join(newer, 'manifest.json');
    writeFileSync(m, readFileSync(m, 'utf8').replace(/"[0-9a-f]{64}"/, `"${'0'.repeat(64)}"`));
    expect(findActiveInstalledSet({ root, publicKeyPem: pem })?.version).toBe('20261124.1');
    expect(reasonFor(NEWER)).toMatch(/signature/);
  });

  it('an extra file dropped into definitions/', () => {
    const { newer } = installTwo();
    writeFileSync(join(newer, 'definitions', 'EX-999-dropped.yaml'), DEF('EX-999', 'Dropped'));
    expect(findActiveInstalledSet({ root, publicKeyPem: pem })?.version).toBe('20261124.1');
    expect(reasonFor(NEWER)).toMatch(/does not list/);
  });

  it('a file replaced by a symlink, even to identical content', () => {
    const { newer } = installTwo();
    const f = join(newer, 'definitions', 'EX-900-demo-a.yaml');
    const copy = join(tmp(), 'copy.yaml');
    writeFileSync(copy, readFileSync(f));
    rmSync(f);
    symlinkSync(copy, f);
    expect(findActiveInstalledSet({ root, publicKeyPem: pem })?.version).toBe('20261124.1');
    expect(reasonFor(NEWER)).toMatch(/not a plain file/);
  });

  it('a set folder that is itself a symlink', () => {
    const { newer } = installTwo();
    const elsewhere = join(tmp(), 'moved');
    renameSync(newer, elsewhere);
    symlinkSync(elsewhere, newer);
    expect(findActiveInstalledSet({ root, publicKeyPem: pem })?.version).toBe('20261124.1');
  });

  it('an old set renamed to look newer', () => {
    const { older } = installTwo();
    renameSync(older, join(root, '20261231.9'));
    expect(findActiveInstalledSet({ root, publicKeyPem: pem })?.version).toBe(NEWER);
    expect(reasonFor('20261231.9')).toMatch(/holds version 20261124\.1/);
  });

  it('a set signed by another key is never used', () => {
    installTwo();
    expect(findActiveInstalledSet({ root, publicKeyPem: OTHER.publicKeyPem })).toBeNull();
    expect(verifyInstalledSet(join(root, NEWER), OTHER.publicKeyPem).ok).toBe(false);
  });

  it('every set tampered: back to the bundled definitions', () => {
    const { older, newer } = installTwo();
    for (const d of [older, newer]) appendFileSync(join(d, 'definitions', 'EX-901-demo-b.yaml'), '#\n');
    expect(activeDefinitions({ root, publicKeyPem: pem }).source).toBe('bundled');
  });
});

describe('downloading', () => {
  const resp = (status: number, body: Buffer | null, headers: Record<string, string> = {}): FetchResponse => ({
    status,
    headers: { get: (n: string) => headers[n.toLowerCase()] ?? null },
    body: body === null ? null : (async function* () { yield body; })(),
  });
  const serve = (routes: Record<string, () => FetchResponse>): FetchLike => async (url: string) => {
    const r = routes[url];
    if (!r) throw new Error(`unexpected ${url}`);
    return r();
  };
  const URL1 = 'https://updates.example.invalid/defs.tar';

  it('refuses non-HTTPS URLs, including a redirect down to http', async () => {
    expectFail(await downloadBundle('http://updates.example.invalid/x.tar'), /https/);
    expectFail(await loadBundleSource('ftp://updates.example.invalid/x.tar'), /https/);
    expectFail(await loadBundleSource('file:///etc/passwd'), /https/);
    const f = serve({ [URL1]: () => resp(302, null, { location: 'http://updates.example.invalid/defs.tar' }) });
    expectFail(await downloadBundle(URL1, { fetchImpl: f }), /must use https/);
  });

  it('follows a few HTTPS redirects, then stops', async () => {
    const tar = assemble();
    const ok = serve({
      [URL1]: () => resp(301, null, { location: '/v2/defs.tar' }),
      'https://updates.example.invalid/v2/defs.tar': () => resp(200, tar),
    });
    const r = await downloadBundle(URL1, { fetchImpl: ok });
    expect(r.ok && r.tar.equals(tar)).toBe(true);
    const loop = serve({ [URL1]: () => resp(302, null, { location: URL1 }) });
    expectFail(await downloadBundle(URL1, { fetchImpl: loop }), /too many times/);
  });

  it('refuses a download over the 2 MB limit, declared or streamed', async () => {
    const big = Buffer.alloc(DOWNLOAD_LIMIT_BYTES + 1);
    expectFail(await downloadBundle(URL1, { fetchImpl: serve({ [URL1]: () => resp(200, Buffer.alloc(10), { 'content-length': String(big.length) }) }) }), /larger than/);
    expectFail(await downloadBundle(URL1, { fetchImpl: serve({ [URL1]: () => resp(200, big) }) }), /larger than/);
  });

  it('refuses error statuses and empty bodies', async () => {
    expectFail(await downloadBundle(URL1, { fetchImpl: serve({ [URL1]: () => resp(404, null) }) }), /answered 404/);
    expectFail(await downloadBundle(URL1, { fetchImpl: serve({ [URL1]: () => resp(200, Buffer.alloc(0)) }) }), /empty/);
  });

  it('gives up when the body stalls or the server never answers', async () => {
    const stall: FetchLike = async () => ({
      status: 200,
      headers: { get: () => null },
      body: (async function* () {
        yield Buffer.alloc(1024);
        await new Promise((r) => setTimeout(r, 10_000));
      })(),
    });
    expectFail(await downloadBundle(URL1, { timeoutMs: 150, fetchImpl: stall }), /did not finish within/);
    const never: FetchLike = () => new Promise(() => undefined);
    expectFail(await downloadBundle(URL1, { timeoutMs: 150, fetchImpl: never }), /did not finish within/);
  });

  it('runLiveUpdate: download, verify and install', async () => {
    const r = await runLiveUpdate({ from: URL1, root, publicKeyPem: pem, fetchImpl: serve({ [URL1]: () => resp(200, assemble()) }) });
    expect(r.ok).toBe(true);
    if (r.ok) expect([r.previous.source, r.set.version]).toEqual(['bundled', NEWER]);
    const again = await runLiveUpdate({ from: URL1, root, publicKeyPem: pem, fetchImpl: serve({ [URL1]: () => resp(200, assemble()) }) });
    expectFail(again, /not newer/);
  });
});

describe('local bundle files', () => {
  it('reads a regular file and refuses folders, missing files and oversize files', () => {
    const d = tmp();
    const f = join(d, 'b.tar');
    writeFileSync(f, assemble());
    expect(readBundleFile(f).ok).toBe(true);
    expectFail(readBundleFile(d), /not a regular file/);
    expectFail(readBundleFile(join(d, 'missing.tar')), /ENOENT/);
    const big = join(d, 'big.tar');
    writeFileSync(big, Buffer.alloc(DOWNLOAD_LIMIT_BYTES + 1));
    expectFail(readBundleFile(big), /larger than/);
    writeFileSync(join(d, 'empty.tar'), '');
    expectFail(readBundleFile(join(d, 'empty.tar')), /empty/);
  });
});
