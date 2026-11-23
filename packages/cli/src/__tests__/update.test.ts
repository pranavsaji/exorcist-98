import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildManifest, buildTar, makeKeyPair, signManifest } from '@exorcist-98/core';
import type { BundleFile } from '@exorcist-98/core';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../../..');
const CLI_DIR = join(ROOT, 'packages/cli');
const BUNDLE = join(CLI_DIR, 'dist/index.mjs');

beforeAll(() => {
  execFileSync(process.execPath, [join(CLI_DIR, 'build.mjs')], { cwd: CLI_DIR, stdio: 'pipe' });
}, 60_000);

const dirs: string[] = [];
afterAll(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-update-')); dirs.push(d); return d; };

/** A definition that only the updated set contains, matching a unique probe token. */
const PROBE_RULE = `id: EX-950
title: LiveUpdate probe rule
severity: high
applies_to:
  - instruction
  - docs
match:
  regex: "LIVEUPDATE-PROBE-[0-9A-Z]{8}"
owasp:
  - "LLM01:2025 Prompt Injection"
fix: Test rule, remove the probe.
`;

const STALE_RULE = `id: EX-951
title: LiveUpdate stale rule
severity: high
applies_to:
  - instruction
match:
  regex: "LIVEUPDATE-STALE-[0-9A-Z]{8}"
owasp:
  - "LLM01:2025 Prompt Injection"
fix: Test rule.
`;

function bundleTar(files: { name: string; text: string }[], version: string, date: string, privateKeyPem: string): Buffer {
  const entries: BundleFile[] = files.map((f) => ({ path: `definitions/${f.name}`, data: Buffer.from(f.text, 'utf8') }));
  const manifestJson = buildManifest(entries, version, date);
  const sig = signManifest(manifestJson, privateKeyPem);
  return buildTar([...entries, { path: 'manifest.json', data: Buffer.from(manifestJson, 'utf8') }, { path: 'manifest.sig', data: sig }]);
}

function run(args: string[], env: Record<string, string>) {
  const r = spawnSync(process.execPath, [BUNDLE, ...args], { cwd: ROOT, encoding: 'utf8', env: { ...process.env, ...env } });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

describe('exorcist update', () => {
  it('installs a good signed bundle, and --status reports it active', () => {
    const key = makeKeyPair();
    const home = tmp();
    const tar = bundleTar([{ name: 'EX-950-liveupdate-probe.yaml', text: PROBE_RULE }], '20261201.1', '2026-12-01', key.privateKeyPem);
    const tarFile = join(tmp(), 'bundle.tar');
    writeFileSync(tarFile, tar);

    const before = run(['update', '--status'], { EXORCIST_DEFINITIONS_HOME: home, EXORCIST_DEFINITIONS_PUBLIC_KEY: key.publicKeyPem });
    expect(before.code).toBe(0);
    expect(before.out).toContain('bundled');

    const r = run(['update', '--from', tarFile, '--home', home], { EXORCIST_DEFINITIONS_PUBLIC_KEY: key.publicKeyPem });
    expect(r.code).toBe(0);
    if (r.code !== 0) console.error(r.err);
    expect(r.out).toContain('20261201.1');
    expect(existsSync(join(home, '20261201.1', 'definitions', 'EX-950-liveupdate-probe.yaml'))).toBe(true);

    const status = run(['update', '--status'], { EXORCIST_DEFINITIONS_HOME: home, EXORCIST_DEFINITIONS_PUBLIC_KEY: key.publicKeyPem });
    expect(status.code).toBe(0);
    expect(status.out).toContain('Active');
    expect(status.out).toContain('20261201.1');
    expect(status.out).toContain('LiveUpdate');
  });

  it('refuses a bundle signed with the wrong key and installs nothing', () => {
    const good = makeKeyPair();
    const bad = makeKeyPair();
    const home = tmp();
    const tar = bundleTar([{ name: 'EX-950-liveupdate-probe.yaml', text: PROBE_RULE }], '20261202.1', '2026-12-02', bad.privateKeyPem);
    const tarFile = join(tmp(), 'bundle.tar');
    writeFileSync(tarFile, tar);
    const r = run(['update', '--from', tarFile, '--home', home], { EXORCIST_DEFINITIONS_PUBLIC_KEY: good.publicKeyPem });
    expect(r.code).toBe(1);
    expect(r.err).toContain('signature');
    expect(readdirSync(home).filter((d) => /^\d{8}/.test(d))).toEqual([]);
  });

  it('refuses an older bundle', () => {
    const key = makeKeyPair();
    const home = tmp();
    // Install a current set first.
    const newer = bundleTar([{ name: 'EX-950-liveupdate-probe.yaml', text: PROBE_RULE }], '20261205.1', '2026-12-05', key.privateKeyPem);
    const newerFile = join(tmp(), 'newer.tar');
    writeFileSync(newerFile, newer);
    expect(run(['update', '--from', newerFile, '--home', home], { EXORCIST_DEFINITIONS_PUBLIC_KEY: key.publicKeyPem }).code).toBe(0);

    const older = bundleTar([{ name: 'EX-951-liveupdate-stale.yaml', text: STALE_RULE }], '20261201.1', '2026-12-01', key.privateKeyPem);
    const olderFile = join(tmp(), 'older.tar');
    writeFileSync(olderFile, older);
    const r = run(['update', '--from', olderFile, '--home', home], { EXORCIST_DEFINITIONS_PUBLIC_KEY: key.publicKeyPem });
    expect(r.code).toBe(1);
    expect(r.err).toContain('not newer');
    expect(existsSync(join(home, '20261201.1'))).toBe(false);
    expect(existsSync(join(home, '20261205.1'))).toBe(true);
  });

  it('refuses an http:// source', () => {
    const key = makeKeyPair();
    const home = tmp();
    const r = run(['update', '--from', 'http://updates.example.invalid/x.tar', '--home', home], { EXORCIST_DEFINITIONS_PUBLIC_KEY: key.publicKeyPem });
    expect(r.code).toBe(1);
    expect(r.err).toContain('https');
  });

  it('makes the next scan use the installed definitions', () => {
    const key = makeKeyPair();
    const home = tmp();
    const tar = bundleTar([{ name: 'EX-950-liveupdate-probe.yaml', text: PROBE_RULE }], '20261210.1', '2026-12-10', key.privateKeyPem);
    const tarFile = join(tmp(), 'bundle.tar');
    writeFileSync(tarFile, tar);
    expect(run(['update', '--from', tarFile, '--home', home], { EXORCIST_DEFINITIONS_PUBLIC_KEY: key.publicKeyPem }).code).toBe(0);

    const scanDir = tmp();
    writeFileSync(join(scanDir, 'AGENTS.md'), 'Follow these notes.\nLIVEUPDATE-PROBE-ABCDEF12\n');

    // With the installed set active, the new rule fires.
    const withUpdate = run(['scan', scanDir, '--format', 'json', '--fail-on', 'none'], {
      EXORCIST_DEFINITIONS_HOME: home,
      EXORCIST_DEFINITIONS_PUBLIC_KEY: key.publicKeyPem,
    });
    expect(withUpdate.code).toBe(0);
    const report = JSON.parse(withUpdate.out) as { findings: { ruleId: string }[] };
    expect(report.findings.some((f) => f.ruleId === 'EX-950')).toBe(true);

    // Without it, the bundled definitions do not know the probe rule.
    const plain = run(['scan', scanDir, '--format', 'json', '--fail-on', 'none'], {
      EXORCIST_DEFINITIONS_HOME: join(tmpdir(), 'exorcist-empty-home-that-does-not-exist'),
      EXORCIST_DEFINITIONS_PUBLIC_KEY: key.publicKeyPem,
    });
    expect(plain.code).toBe(0);
    const plainReport = JSON.parse(plain.out) as { findings: { ruleId: string }[] };
    expect(plainReport.findings.some((f) => f.ruleId === 'EX-950')).toBe(false);
  });
});
