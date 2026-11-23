import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  activeVersion,
  buildManifest,
  buildTar,
  compareVersions,
  downloadBundle,
  installBundle,
  makeKeyPair,
  parseBundle,
  signManifest,
  validateBundleDefinitions,
  verifyBundle,
} from '../liveupdate.js';
import type { BundleFile, FetchLike } from '../liveupdate.js';

const DEF = (id: string, title: string): string => `id: ${id}
title: ${title}
severity: high
applies_to:
  - instruction
match:
  regex: "a\\\\u200Bb"
owasp:
  - "LLM01:2025 Prompt Injection"
fix: Remove it.
`;

const { privateKeyPem, publicKeyPem } = makeKeyPair();

type Built = { tar: Buffer; entries: BundleFile[]; manifestJson: string; sig: Buffer };

function build(files: { name: string; text: string }[], version = '20261201.1', date = '2026-12-01', key = privateKeyPem): Built {
  const entries: BundleFile[] = files.map((f) => ({
    path: `definitions/${f.name}`,
    data: Buffer.from(f.text, 'utf8'),
  }));
  const manifestJson = buildManifest(entries, version, date);
  const sig = signManifest(manifestJson, key);
  return { tar: buildTar([...entries, { path: 'manifest.json', data: Buffer.from(manifestJson, 'utf8') }, { path: 'manifest.sig', data: sig }]), entries, manifestJson, sig };
}

/** Rebuild a tar with the same files but a different manifest/signature. */
function rebuild(entries: BundleFile[], manifestJson: string, sig: Buffer): Buffer {
  return buildTar([...entries, { path: 'manifest.json', data: Buffer.from(manifestJson, 'utf8') }, { path: 'manifest.sig', data: sig }]);
}

const good = () => [{ name: 'EX-900-demo-a.yaml', text: DEF('EX-900', 'Demo A') }, { name: 'EX-901-demo-b.yaml', text: DEF('EX-901', 'Demo B') }];

let root: string;
const roots: string[] = [];
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'exorcist-liveupdate-'));
  roots.push(root);
});
afterAll(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});

describe('versions', () => {
  it('compares date-sequence versions', () => {
    expect(compareVersions('20261201.1', '20261201.2')).toBeLessThan(0);
    expect(compareVersions('20261202.1', '20261201.9')).toBeGreaterThan(0);
    expect(compareVersions('20261201.3', '20261201.3')).toBe(0);
  });
});

describe('a good bundle', () => {
  it('verifies, validates and installs atomically', () => {
    const b = build(good());
    const current = '20261123.0';
    const r = installBundle(b.tar, { root, currentVersion: current, publicKeyPem });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.set.version).toBe('20261201.1');
      const dir = join(root, '20261201.1');
      expect(readdirSync(join(dir, 'definitions')).sort()).toEqual(['EX-900-demo-a.yaml', 'EX-901-demo-b.yaml']);
      expect(existsSync(join(dir, 'manifest.sig'))).toBe(true);
    }
    const active = activeVersion({ root, publicKeyPem });
    expect(active).toMatchObject({ version: '20261201.1', source: 'installed' });
  });

  it('round-trips through the tar reader', () => {
    const b = build(good());
    const parsed = parseBundle(b.tar);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.bundle.manifest.version).toBe('20261201.1');
      expect(parsed.bundle.files.size).toBe(2);
      const v = verifyBundle(parsed.bundle, publicKeyPem);
      expect(v.ok).toBe(true);
      const defs = validateBundleDefinitions(parsed.bundle);
      expect(defs.ok && defs.definitions.length === 2).toBe(true);
    }
  });
});

describe('fail closed', () => {
  it('rejects a tampered manifest (re-signed content changed)', () => {
    const b = build(good());
    const altered = b.manifestJson.replace('20261201.1', '20261201.2');
    // signature is over the original bytes, so the new manifest does not verify
    const tar = rebuild(b.entries, altered, b.sig);
    const parsed = parseBundle(tar);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(verifyBundle(parsed.bundle, publicKeyPem).ok).toBe(false);
  });

  it('rejects a tampered definition file and installs nothing', () => {
    const b = build(good());
    const tampered = b.entries.map((e) =>
      e.path === 'definitions/EX-900-demo-a.yaml' ? { path: e.path, data: Buffer.concat([e.data, Buffer.from('\n# evil\n')]) } : e,
    );
    const tar = rebuild(tampered, b.manifestJson, b.sig);
    const before = readdirSync(root).filter((d) => /^\d{8}/.test(d));
    const r = installBundle(tar, { root, currentVersion: '20261123.0', publicKeyPem });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('EX-900-demo-a.yaml');
    expect(readdirSync(root).filter((d) => /^\d{8}/.test(d))).toEqual(before);
  });

  it('rejects a bundle signed with the wrong key', () => {
    const other = makeKeyPair();
    const b = build(good(), '20261202.1', '2026-12-02', other.privateKeyPem);
    const parsed = parseBundle(b.tar);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      const v = verifyBundle(parsed.bundle, publicKeyPem);
      expect(v.ok).toBe(false);
      if (!v.ok) expect(v.error).toContain('signature');
    }
  });

  it('refuses an older or equal version', () => {
    const b = build(good(), '20261101.1', '2026-11-01');
    const r = installBundle(b.tar, { root, currentVersion: '20261201.1', publicKeyPem });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('not newer');
    expect(existsSync(join(root, '20261101.1'))).toBe(false);
  });

  it('rejects invalid YAML inside a signed bundle', () => {
    const b = build([{ name: 'EX-902-bad.yaml', text: 'id: EX-902\nseverity: bogus\n' }]);
    const parsed = parseBundle(b.tar);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      const v = verifyBundle(parsed.bundle, publicKeyPem);
      expect(v.ok).toBe(true);
      const d = validateBundleDefinitions(parsed.bundle);
      expect(d.ok).toBe(false);
    }
  });

  it('rejects a definition file hidden outside the manifest', () => {
    const files = good();
    const entries: BundleFile[] = files.map((f) => ({ path: `definitions/${f.name}`, data: Buffer.from(f.text, 'utf8') }));
    const manifestJson = buildManifest(entries, '20261203.1', '2026-12-03');
    const sig = signManifest(manifestJson, privateKeyPem);
    // an extra file the manifest does not know about
    entries.push({ path: 'definitions/EX-999-extra.yaml', data: Buffer.from(DEF('EX-999', 'Smuggled'), 'utf8') });
    const tar = buildTar([...entries, { path: 'manifest.json', data: Buffer.from(manifestJson, 'utf8') }, { path: 'manifest.sig', data: sig }]);
    const parsed = parseBundle(tar);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      const v = verifyBundle(parsed.bundle, publicKeyPem);
      expect(v.ok).toBe(false);
      if (!v.ok) expect(v.error).toContain('outside the manifest');
    }
  });

  it('refuses a manifest whose version is not a date sequence', () => {
    const entries: BundleFile[] = [{ path: 'definitions/EX-903-x.yaml', data: Buffer.from(DEF('EX-903', 'X'), 'utf8') }];
    const manifestJson = buildManifest(entries, '99.1', '2026-12-03');
    const sig = signManifest(manifestJson, privateKeyPem);
    const tar = buildTar([...entries, { path: 'manifest.json', data: Buffer.from(manifestJson, 'utf8') }, { path: 'manifest.sig', data: sig }]);
    expect(parseBundle(tar).ok).toBe(false);
  });
});

describe('downloading', () => {
  const big = Buffer.alloc(3 * 1024 * 1024, 0x20);
  const fetchOf = (body: Buffer, status = 200): FetchLike =>
    (async () => ({ ok: status === 200, status, body: (async function* () { yield body; })() }));

  it('refuses a non-HTTPS URL', async () => {
    const r = await downloadBundle('http://updates.example.invalid/x.tar');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('https');
  });

  it('refuses a download over the 2 MB limit', async () => {
    const r = await downloadBundle('https://updates.example.invalid/x.tar', { fetchImpl: fetchOf(big) });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('larger than');
  });

  it('refuses a download that never finishes', async () => {
    const slow: FetchLike = async () => ({
      ok: true,
      status: 200,
      body: (async function* () {
        yield Buffer.alloc(1024);
        await new Promise((r2) => setTimeout(r2, 5000));
        yield Buffer.alloc(1024);
      })(),
    });
    const r = await downloadBundle('https://updates.example.invalid/x.tar', { timeoutMs: 200, fetchImpl: slow });
    expect(r.ok).toBe(false);
  });

  it('downloads a small bundle', async () => {
    const b = build(good());
    const r = await downloadBundle('https://updates.example.invalid/x.tar', { fetchImpl: fetchOf(b.tar) });
    expect(r.ok && parseBundle(r.tar).ok).toBe(true);
  });
});
