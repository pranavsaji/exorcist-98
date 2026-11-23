/**
 * m5-liveupdate: `exorcist update` and `--status`. Key pairs are generated in
 * memory per run. The in-process tests inject a throwaway trusted key; the
 * built-bundle tests run the real CLI, which trusts only the embedded key, so
 * every throwaway-signed bundle must be refused there.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { appendFileSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEFINITIONS_PUBLIC_KEY, buildSignedBundle, installBundle, makeKeyPair, publicKeyFingerprint, scanRepo,
} from '@exorcist-98/core';
import type { Finding, UpdateFetchLike } from '@exorcist-98/core';
import { findDefinitionsDir } from '@exorcist-98/shield';
import { updateCommand } from '../commands/update.js';
import type { Io } from '../util.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../../..');
const CLI_DIR = join(ROOT, 'packages/cli');
const BUNDLE = join(CLI_DIR, 'dist/index.mjs');

const dirs: string[] = [];
afterAll(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-update-')); dirs.push(d); return d; };

const KEY = makeKeyPair();
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

function bundle(version: string, privateKeyPem = KEY.privateKeyPem): Buffer {
  const b = buildSignedBundle({ files: [{ path: 'definitions/EX-950-liveupdate-probe.yaml', data: Buffer.from(PROBE_RULE) }], version, privateKeyPem });
  if (!b.ok) throw new Error(b.error);
  return b.tar;
}
function bundleFile(version: string, privateKeyPem = KEY.privateKeyPem): string {
  const f = join(tmp(), `defs-${version}.tar`);
  writeFileSync(f, bundle(version, privateKeyPem));
  return f;
}

function capture(): Io & { o: string; e: string } {
  const c = { o: '', e: '', out: (s: string) => { c.o += `${s}\n`; }, err: (s: string) => { c.e += `${s}\n`; } };
  return c;
}
/** `exorcist update` in-process, trusting the throwaway key, with HOME at a temp folder. */
async function update(args: string[], home: string, extra: { fetchImpl?: UpdateFetchLike } = {}) {
  const io = capture();
  const code = await updateCommand(args, io, { publicKeyPem: KEY.publicKeyPem, env: { HOME: home }, ...extra });
  return { code, out: io.o, err: io.e };
}
const versionsIn = (home: string): string[] => {
  try { return readdirSync(join(home, '.exorcist', 'definitions')).filter((d) => /^\d{8}\./.test(d)).sort(); } catch { return []; }
};

describe('exorcist update (in-process, throwaway trusted key)', () => {
  it('installs a good bundle into ~/.exorcist/definitions/<version>/ and the next scan uses it', async () => {
    const home = tmp();
    const before = await update(['--status'], home);
    expect(before.code).toBe(0);
    expect(before.out).toContain('bundled with this build');
    expect(before.out).toContain('Installed sets: none');

    const r = await update(['--from', bundleFile('20261201.1')], home);
    expect(r.err).toBe('');
    expect(r.code).toBe(0);
    expect(r.out).toContain('Installed definitions 20261201.1 (2026-12-01)');
    expect(versionsIn(home)).toEqual(['20261201.1']);

    const status = await update(['--status'], home);
    expect(status.out).toMatch(/Active definitions: 20261201\.1 \(2026-12-01, installed by LiveUpdate\)/);
    expect(status.out).toContain('20261201.1  2026-12-01  1 definitions  active');

    // The shared lookup (CLI scan, Shield, MCP server) now picks the installed set.
    const defs = findDefinitionsDir({ callerUrl: pathUrl(join(CLI_DIR, 'src', 'util.ts')), env: { HOME: home }, publicKeyPem: KEY.publicKeyPem });
    expect(defs).toBe(join(home, '.exorcist', 'definitions', '20261201.1', 'definitions'));
    const scanDir = tmp();
    writeFileSync(join(scanDir, 'AGENTS.md'), 'Follow these notes.\nLIVEUPDATE-PROBE-ABCDEF12\n');
    const findings: Finding[] = [];
    for await (const ev of scanRepo(scanDir, { definitionsDir: defs ?? '' })) if (ev.type === 'finding') findings.push(ev.finding);
    expect(findings.some((f) => f.ruleId === 'EX-950')).toBe(true);
  });

  it('refuses a bundle signed with another key and installs nothing', async () => {
    const home = tmp();
    const r = await update(['--from', bundleFile('20261202.1', makeKeyPair().privateKeyPem)], home);
    expect(r.code).toBe(1);
    expect(r.err).toContain('signature does not match');
    expect(r.err).toContain('Nothing was installed');
    expect(versionsIn(home)).toEqual([]);
  });

  it('refuses an older bundle and keeps the newer set', async () => {
    const home = tmp();
    expect((await update(['--from', bundleFile('20261205.1')], home)).code).toBe(0);
    const r = await update(['--from', bundleFile('20261201.1')], home);
    expect(r.code).toBe(1);
    expect(r.err).toContain('not newer');
    expect(versionsIn(home)).toEqual(['20261205.1']);
  });

  it('downloads over https (injected fetch) and refuses http', async () => {
    const home = tmp();
    const tar = bundle('20261203.1');
    const fetchImpl: UpdateFetchLike = async () => ({ status: 200, headers: { get: () => null }, body: (async function* () { yield tar; })() });
    expect((await update(['--from', 'https://updates.example.invalid/defs.tar'], home, { fetchImpl })).code).toBe(0);
    const http = await update(['--from', 'http://updates.example.invalid/defs.tar'], home);
    expect(http.code).toBe(1);
    expect(http.err).toContain('https');
  });

  it('--status shows a tampered set as rejected and falls back to the bundled definitions', async () => {
    const home = tmp();
    expect((await update(['--from', bundleFile('20261204.1')], home)).code).toBe(0);
    appendFileSync(join(home, '.exorcist', 'definitions', '20261204.1', 'definitions', 'EX-950-liveupdate-probe.yaml'), '# tampered\n');
    const s = await update(['--status'], home);
    expect(s.out).toContain('bundled with this build');
    expect(s.out).toMatch(/20261204\.1 {2}REJECTED, not used: definitions\/EX-950-liveupdate-probe\.yaml was changed after it was installed/);
  });

  it('usage errors', async () => {
    const home = tmp();
    expect((await update([], home)).code).toBe(2);
    expect((await update(['--status', '--from', 'x.tar'], home)).code).toBe(2);
    expect((await update(['stray'], home)).code).toBe(2);
    expect((await update(['--from', join(home, 'missing.tar')], home)).err).toContain('ENOENT');
  });
});

function pathUrl(p: string): string {
  return new URL(`file://${p}`).href;
}

describe('the built CLI trusts only the embedded key', () => {
  beforeAll(() => {
    execFileSync(process.execPath, [join(CLI_DIR, 'build.mjs')], { cwd: CLI_DIR, stdio: 'pipe' });
  }, 60_000);

  const run = (args: string[], home: string) => {
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home };
    delete env['EXORCIST_DEFINITIONS'];
    delete env['EXORCIST_DEFINITIONS_HOME'];
    delete env['EXORCIST_UPDATE_URL'];
    const r = spawnSync(process.execPath, [BUNDLE, ...args], { cwd: ROOT, encoding: 'utf8', env });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };

  it('update --status in a fresh HOME: bundled definitions and the embedded key fingerprint', () => {
    const home = tmp();
    const r = run(['update', '--status'], home);
    expect(r.code).toBe(0);
    expect(r.out).toContain('bundled with this build');
    expect(r.out).toContain(`sha256:${publicKeyFingerprint(DEFINITIONS_PUBLIC_KEY) ?? 'x'}`);
    expect(run(['--help'], home).out).toContain('update');
  });

  it('refuses a bundle signed by any other key, and installs nothing', () => {
    const home = tmp();
    const r = run(['update', '--from', bundleFile('20261206.1')], home);
    expect(r.code).toBe(1);
    expect(r.err).toContain('signature does not match');
    expect(versionsIn(home)).toEqual([]);
  });

  it('a set planted in ~/.exorcist/definitions without the real signature is never used by scan', () => {
    const home = tmp();
    const root = join(home, '.exorcist', 'definitions');
    expect(installBundle(bundle('20261207.1'), { root, currentVersion: '20200101.0', publicKeyPem: KEY.publicKeyPem }).ok).toBe(true);
    const scanDir = tmp();
    writeFileSync(join(scanDir, 'AGENTS.md'), 'Follow these notes.\nLIVEUPDATE-PROBE-ABCDEF12\n');
    const r = run(['scan', scanDir, '--format', 'json', '--fail-on', 'none'], home);
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out) as { findings: { ruleId: string }[] };
    expect(report.findings.some((f) => f.ruleId === 'EX-950')).toBe(false);
    expect(run(['update', '--status'], home).out).toMatch(/20261207\.1 {2}REJECTED, not used: the manifest signature does not verify/);
  });
});
