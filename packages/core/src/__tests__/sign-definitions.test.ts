/**
 * m5-liveupdate task 2: scripts/sign-definitions.ts. The test key pair is
 * generated here at run time and written only to a temp folder outside the
 * repository, which is deleted afterwards.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkBundle, collectDefinitionFiles, makeKeyPair } from '../liveupdate.js';
import { REPO_ROOT, fromRoot } from './repo-root.js';

const TSX = fromRoot('node_modules', '.bin', 'tsx');
const SCRIPT = fromRoot('scripts', 'sign-definitions.ts');
const dirs: string[] = [];
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-sign-')); dirs.push(d); return d; };

function sign(args: string[], env: Record<string, string> = {}) {
  const clean: NodeJS.ProcessEnv = { ...process.env, ...env };
  if (!('EXORCIST_SIGNING_KEY' in env)) delete clean['EXORCIST_SIGNING_KEY'];
  if (!('EXORCIST_SIGNING_KEY_FILE' in env)) delete clean['EXORCIST_SIGNING_KEY_FILE'];
  const r = spawnSync(TSX, [SCRIPT, ...args], { cwd: REPO_ROOT, encoding: 'utf8', env: clean });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

const KEY = makeKeyPair();
const definitionCount = collectDefinitionFiles(fromRoot('definitions')).length;

describe('scripts/sign-definitions.ts', () => {
  it('signs the definitions with a key read from a file path', () => {
    const d = tmp();
    const keyFile = join(d, 'key.pem');
    writeFileSync(keyFile, KEY.privateKeyPem, { mode: 0o600 });
    const out = join(d, 'bundle.tar');
    const r = sign(['--version', '20261201.1', '--key', keyFile, '--out', out]);
    expect(r.err).toContain('not the one built into Exorcist 98'); // a throwaway key
    expect(r.code).toBe(0);
    expect(r.out).toContain(`Signed ${definitionCount} definitions as version 20261201.1 (2026-12-01)`);
    const c = checkBundle(readFileSync(out), { publicKeyPem: KEY.publicKeyPem });
    expect(c.ok && c.bundle.definitions.length).toBe(definitionCount);
    expect(r.out + r.err).not.toContain('PRIVATE');
  }, 30_000);

  it('signs with a key from EXORCIST_SIGNING_KEY_FILE or EXORCIST_SIGNING_KEY (escaped newlines allowed)', () => {
    const d = tmp();
    const keyFile = join(d, 'key.pem');
    writeFileSync(keyFile, KEY.privateKeyPem, { mode: 0o600 });
    const a = join(d, 'a.tar');
    expect(sign(['--version', '20261201.2', '--out', a], { EXORCIST_SIGNING_KEY_FILE: keyFile }).code).toBe(0);
    const b = join(d, 'b.tar');
    expect(sign(['--version', '20261201.3', '--out', b], { EXORCIST_SIGNING_KEY: KEY.privateKeyPem.replace(/\n/g, '\\n') }).code).toBe(0);
    for (const f of [a, b]) expect(checkBundle(readFileSync(f), { publicKeyPem: KEY.publicKeyPem }).ok).toBe(true);
  }, 30_000);

  it('refuses: no key, a bad version, a non-Ed25519 key, a key file inside the repository', () => {
    const d = tmp();
    expect(sign(['--version', '20261201.1', '--out', join(d, 'x.tar')]).err).toContain('No signing key');
    expect(sign(['--version', '2026-12-01', '--out', join(d, 'x.tar')], { EXORCIST_SIGNING_KEY: KEY.privateKeyPem }).code).toBe(2);
    expect(sign(['--version', '20261201.1', '--out', join(d, 'x.tar')], { EXORCIST_SIGNING_KEY: 'not a key' }).err).toContain('not a readable PKCS#8');
    const inRepo = sign(['--version', '20261201.1', '--key', fromRoot('package.json'), '--out', join(d, 'x.tar')]);
    expect(inRepo.code).toBe(2);
    expect(inRepo.err).toContain('inside the repository');
  }, 30_000);

  it('--generate-key writes the private key with mode 600 and prints only the public key', () => {
    const d = tmp();
    const keyFile = join(d, 'nested', 'signing.pem');
    const r = sign(['--generate-key', '--key-out', keyFile]);
    expect(r.code).toBe(0);
    expect(r.out).toContain('BEGIN PUBLIC KEY');
    expect(r.out).toMatch(/Fingerprint sha256\(SPKI DER\): [0-9a-f]{64}/);
    expect(r.out + r.err).not.toContain('PRIVATE');
    expect(statSync(keyFile).mode & 0o777).toBe(0o600);
    expect(sign(['--generate-key', '--key-out', keyFile]).err).toContain('Refusing to overwrite');
    expect(sign(['--generate-key', '--key-out', fromRoot('dist', 'k.pem')]).err).toContain('inside the repository');
    expect(sign(['--generate-key']).code).toBe(2);
  }, 30_000);
});
