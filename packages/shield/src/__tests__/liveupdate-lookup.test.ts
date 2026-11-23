/**
 * m5-liveupdate: the CLI, the Shield and the MCP server share one definitions
 * lookup, which prefers the newest verified LiveUpdate set over the bundled
 * definitions and re-verifies it every time. Throwaway keys only.
 */
import { describe, expect, it, afterEach } from 'vitest';
import { appendFileSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSignedBundle, installBundle, makeKeyPair, BUNDLED_DEFINITIONS_VERSION } from '@exorcist-98/core';
import { findDefinitionsDir } from '../locate.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = realpathSync(mkdtempSync(join(tmpdir(), 'x98-lu-'))); dirs.push(d); return d; };

const KEY = makeKeyPair();
const RULE = `id: EX-950
title: LiveUpdate probe
severity: high
applies_to: [instruction]
match:
  regex: "LIVEUPDATE-PROBE"
owasp: ["LLM01:2025 Prompt Injection"]
fix: Remove the probe.
`;

function install(root: string, version: string): string {
  const b = buildSignedBundle({ files: [{ path: 'definitions/EX-950-probe.yaml', data: Buffer.from(RULE) }], version, privateKeyPem: KEY.privateKeyPem });
  if (!b.ok) throw new Error(b.error);
  const r = installBundle(b.tar, { root, currentVersion: '20200101.0', publicKeyPem: KEY.publicKeyPem });
  if (!r.ok) throw new Error(r.error);
  return r.set.definitionsDir;
}

function setup(): { callerUrl: string; bundled: string; root: string; env: NodeJS.ProcessEnv } {
  const d = tmp();
  mkdirSync(join(d, 'definitions'));
  writeFileSync(join(d, 'definitions', 'EX-001-x.yaml'), 'id: EX-001');
  const root = join(d, 'home', '.exorcist', 'definitions');
  return { callerUrl: new URL(`file://${join(d, 'dist', 'index.mjs')}`).href, bundled: join(d, 'definitions'), root, env: { HOME: join(d, 'home') } };
}

describe('definitions lookup with LiveUpdate sets', () => {
  it('prefers the newest verified installed set under ~/.exorcist/definitions', () => {
    const s = setup();
    install(s.root, '20261201.1');
    const newest = install(s.root, '20261202.1');
    expect(findDefinitionsDir({ callerUrl: s.callerUrl, env: s.env, cwd: '/', publicKeyPem: KEY.publicKeyPem })).toBe(newest);
  });

  it('--definitions and EXORCIST_DEFINITIONS still win', () => {
    const s = setup();
    install(s.root, '20261201.1');
    expect(findDefinitionsDir({ callerUrl: s.callerUrl, env: s.env, cwd: '/', explicit: '/y', publicKeyPem: KEY.publicKeyPem })).toBe('/y');
    expect(findDefinitionsDir({ callerUrl: s.callerUrl, env: { ...s.env, EXORCIST_DEFINITIONS: '/x' }, cwd: '/', publicKeyPem: KEY.publicKeyPem })).toBe('/x');
  });

  it('skips a tampered set and falls back to the next good one, then to the bundled definitions', () => {
    const s = setup();
    const older = install(s.root, '20261201.1');
    const newer = install(s.root, '20261202.1');
    appendFileSync(join(newer, 'EX-950-probe.yaml'), '# tampered\n');
    expect(findDefinitionsDir({ callerUrl: s.callerUrl, env: s.env, cwd: '/', publicKeyPem: KEY.publicKeyPem })).toBe(older);
    appendFileSync(join(older, 'EX-950-probe.yaml'), '# tampered\n');
    expect(findDefinitionsDir({ callerUrl: s.callerUrl, env: s.env, cwd: '/', publicKeyPem: KEY.publicKeyPem })).toBe(s.bundled);
  });

  it('never uses a set the embedded key did not sign', () => {
    const s = setup();
    install(s.root, '20261201.1');
    expect(findDefinitionsDir({ callerUrl: s.callerUrl, env: s.env, cwd: '/' })).toBe(s.bundled);
  });

  it('ignores a set that is not newer than the bundled definitions', () => {
    const s = setup();
    install(s.root, '20261101.1');
    expect('20261101.1' < BUNDLED_DEFINITIONS_VERSION).toBe(true);
    expect(findDefinitionsDir({ callerUrl: s.callerUrl, env: s.env, cwd: '/', publicKeyPem: KEY.publicKeyPem })).toBe(s.bundled);
  });
});
