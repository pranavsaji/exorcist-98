/**
 * m5-liveupdate: no private key ever lives in this repository. The LiveUpdate
 * signing key stays outside it; tests build throwaway keys at run time. This
 * walks every file git tracks or would add (not ignored) and fails on:
 *
 * - any PEM private key with key material, anywhere;
 * - the PEM marker (PRIVATE KEY plus five dashes) in any file except the few defanged samples
 *   listed below, which hold only a header with the key body removed.
 *
 * The needle is assembled at run time so this file does not contain it.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { findPrivateKeyBlocks, findStagedSecrets } from '../secrets-check.js';
import { makeKeyPair } from '../liveupdate.js';
import { REPO_ROOT } from './repo-root.js';

const NEEDLE = ['PRIVATE', 'KEY-----'].join(' ');

/** Defanged samples (header only, key body removed) that the scanner itself detects. */
const DEFANGED_SAMPLES = new Set([
  'fixtures/benchmark/attacks/private-key-in-docs/docs/deploy.md',
  'packages/core/src/__tests__/precision-round2.test.ts',
  'packages/shield/src/simulator.ts',
]);

function repoFiles(): string[] {
  const out = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return out.split('\0').filter(Boolean);
}

function readText(rel: string): string | null {
  try {
    const p = join(REPO_ROOT, rel);
    if (!statSync(p).isFile() || statSync(p).size > 8 * 1024 * 1024) return null;
    return readFileSync(p, 'latin1');
  } catch {
    return null; // deleted in the working tree
  }
}

describe('no private keys in the repository', () => {
  it('no file holds PEM private key material, and the bare marker appears only in defanged samples', () => {
    const files = repoFiles();
    expect(files.length).toBeGreaterThan(100);
    const withKeys: string[] = [];
    const withMarker: string[] = [];
    for (const rel of files) {
      const text = readText(rel);
      if (text === null) continue;
      if (findPrivateKeyBlocks(text).length > 0) withKeys.push(rel);
      if (text.includes(NEEDLE) && !DEFANGED_SAMPLES.has(rel)) withMarker.push(rel);
    }
    expect(withKeys).toEqual([]);
    expect(withMarker).toEqual([]);
    expect(files.filter((f) => /\.(pem|key|p8|p12|pfx)$/i.test(f))).toEqual([]);
  });

  it('the detector finds real keys, escaped or not, and passes defanged samples', () => {
    const { privateKeyPem } = makeKeyPair();
    expect(findPrivateKeyBlocks(privateKeyPem)).toEqual([0]);
    expect(findPrivateKeyBlocks(`KEY="${privateKeyPem.replace(/\n/g, '\\n')}"`)).toHaveLength(1);
    expect(findPrivateKeyBlocks(`x\r\n${privateKeyPem.replace(/\n/g, '\r\n')}`)).toHaveLength(1);
    expect(findPrivateKeyBlocks(`-----BEGIN OPENSSH ${NEEDLE}\n(defanged: key body removed)\n-----END OPENSSH ${NEEDLE}\n`)).toEqual([]);
    expect(findPrivateKeyBlocks(`-----BEGIN RSA ${NEEDLE}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCDEF\n\n${'A'.repeat(64)}\n`)).toHaveLength(1);
  });
});

describe('the pre-commit check refuses a staged private key', () => {
  const dirs: string[] = [];
  afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

  it('reports the file and line, never the key', () => {
    const repo = mkdtempSync(join(tmpdir(), 'exorcist-pk-'));
    dirs.push(repo);
    execFileSync('git', ['init', '-q'], { cwd: repo });
    const { privateKeyPem } = makeKeyPair();
    writeFileSync(join(repo, 'signing.pem'), `# oops\n${privateKeyPem}`);
    execFileSync('git', ['add', 'signing.pem'], { cwd: repo });
    const r = findStagedSecrets(repo);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.hits).toHaveLength(1);
    expect(r.hits[0]).toMatchObject({ file: 'signing.pem', line: 2, pattern: 'private-key' });
    const body = privateKeyPem.split('\n')[1] ?? 'x';
    expect(JSON.stringify(r.hits)).not.toContain(body);
  });
});
