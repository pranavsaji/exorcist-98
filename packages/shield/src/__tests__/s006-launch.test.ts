/**
 * S-006: the Shield pins the program behind a server (command, arguments and
 * the files they name), so a server whose code changes while its tool list
 * stays the same is caught before it starts.
 */
import { describe, it, expect, afterEach } from 'vitest';
import fc from 'fast-check';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { checkLaunch, launchFingerprint, packageSpec, specIsPinned } from '../launch.js';
import type { FileReader } from '../launch.js';
import { runProxy, FAIL_CLOSED_EXIT } from '../proxy.js';
import { alertsPath, approveServer, emptyState, loadState, saveState, serverState, statePath } from '../state.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FAKE = join(__dirname, 'fake-mcp-server.mjs');
const DEFS = resolve(__dirname, '../../../../definitions');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-launch-')); dirs.push(d); return d; };

/** An in-memory file system for the pure tests. */
const memReader = (files: Record<string, string>): FileReader => (path) => {
  const c = files[path];
  return c === undefined ? { kind: 'other' } : { kind: 'file', size: c.length, mtimeMs: 0, read: () => Buffer.from(c) };
};

describe('package specs', () => {
  it('finds the package a runner downloads', () => {
    expect(packageSpec('npx', ['-y', '@scope/server@1.2.3', '--flag'])).toBe('@scope/server@1.2.3');
    expect(packageSpec('/usr/local/bin/npx', ['server-notes'])).toBe('server-notes');
    expect(packageSpec('pnpm', ['dlx', 'server-notes@2.0.0'])).toBe('server-notes@2.0.0');
    expect(packageSpec('npx', ['--package=tool@1.0.0', 'tool-bin'])).toBe('tool@1.0.0');
    expect(packageSpec('uvx', ['mcp-server-notes==0.4.1'])).toBe('mcp-server-notes==0.4.1');
    expect(packageSpec('pnpm', ['run', 'serve'])).toBeUndefined();
    expect(packageSpec('node', ['server.js'])).toBeUndefined();
  });
  it('a spec is pinned only with an exact version', () => {
    expect(specIsPinned('@scope/server@1.2.3')).toBe(true);
    expect(specIsPinned('server@1.2.3-beta.1')).toBe(true);
    expect(specIsPinned('mcp-server-notes==0.4.1')).toBe(true);
    expect(specIsPinned('@scope/server')).toBe(false);
    expect(specIsPinned('server@latest')).toBe(false);
    expect(specIsPinned('server@^1.2.0')).toBe(false);
    expect(specIsPinned('server')).toBe(false);
  });
});

describe('launch fingerprint', () => {
  it('hashes the contents of every argument that is a file', () => {
    const a = launchFingerprint('node', ['dist/index.mjs'], '/w', memReader({ '/w/dist/index.mjs': 'v1' }));
    const b = launchFingerprint('node', ['dist/index.mjs'], '/w', memReader({ '/w/dist/index.mjs': 'v2' }));
    expect(a.hash).not.toBe(b.hash);
    expect(a.parts.join('\n')).toContain('file dist/index.mjs sha256:');
  });
  it('never stores argument text, which can hold a token', () => {
    fc.assert(fc.property(fc.string({ minLength: 8, maxLength: 60 }).filter((s) => !s.includes('/')), (secret) => {
      const pin = launchFingerprint('node', ['server.js', '--api-key', secret], '/w', memReader({}));
      return !pin.parts.join('\n').includes(secret);
    }));
  });
  it('any change to a file or an argument changes the pin', () => {
    fc.assert(fc.property(fc.string(), fc.string(), fc.array(fc.string(), { maxLength: 4 }), (c1, c2, args) => {
      fc.pre(c1 !== c2);
      const one = launchFingerprint('node', ['s.js', ...args], '/w', memReader({ '/w/s.js': c1 }));
      const two = launchFingerprint('node', ['s.js', ...args], '/w', memReader({ '/w/s.js': c2 }));
      const more = launchFingerprint('node', ['s.js', ...args, 'x'], '/w', memReader({ '/w/s.js': c1 }));
      return one.hash !== two.hash && one.hash !== more.hash;
    }));
  });
  it('does not hash an interpreter, so a runtime upgrade is not an alarm', () => {
    const pin = launchFingerprint('/opt/node/bin/node', ['s.js'], '/w', memReader({ '/opt/node/bin/node': 'binary', '/w/s.js': 'x' }));
    expect(pin.parts[0]).toBe('command /opt/node/bin/node');
    const own = launchFingerprint('/opt/tools/notes-server', [], '/w', memReader({ '/opt/tools/notes-server': 'binary' }));
    expect(own.parts[0]).toMatch(/^command file \/opt\/tools\/notes-server sha256:/);
  });
});

describe('launch fingerprint: the entry\'s env and cwd (m5-lockfile)', () => {
  const r = memReader({ '/w/s.js': 'v1' });
  it('an entry with no env and no cwd gives exactly the pin it gave before', () => {
    const before = launchFingerprint('node', ['s.js'], '/w', r);
    expect(launchFingerprint('node', ['s.js'], '/w', r, {})).toEqual(before);
    expect(launchFingerprint('node', ['s.js'], '/w', r, { env: {} })).toEqual(before);
  });
  it('adding NODE_OPTIONS or LD_PRELOAD changes the pin and says why, without storing the value', () => {
    const base = launchFingerprint('node', ['s.js'], '/w', r, { env: { NOTES_DIR: '/n' } });
    const evil = launchFingerprint('node', ['s.js'], '/w', r, { env: { NOTES_DIR: '/n', NODE_OPTIONS: '--require ./evil.js' } });
    expect(evil.hash).not.toBe(base.hash);
    expect(evil.parts).toContainEqual(expect.stringMatching(/^env NODE_OPTIONS sha256:[0-9a-f]{16} \(changes how the program loads\)$/));
    expect(evil.parts.join('\n')).not.toContain('evil.js');
    expect(launchFingerprint('node', ['s.js'], '/w', r, { env: { LD_PRELOAD: './x.so' } }).hash).not.toBe(launchFingerprint('node', ['s.js'], '/w', r).hash);
  });
  it('any change to an env key, an env value or the cwd changes the pin; the order keys are written in does not', () => {
    const envArb = fc.dictionary(fc.string({ minLength: 1, maxLength: 8 }).filter((k) => k !== '__proto__'), fc.string({ maxLength: 12 }), { maxKeys: 5 });
    fc.assert(fc.property(envArb, fc.string({ minLength: 1, maxLength: 8 }).filter((k) => k !== '__proto__'), fc.string(), fc.option(fc.string({ maxLength: 10 }), { nil: undefined }), (env, key, value, cwd) => {
      const entry = { env, ...(cwd !== undefined ? { cwd } : {}) };
      const pin = launchFingerprint('node', ['s.js'], '/w', r, entry);
      const reordered = launchFingerprint('node', ['s.js'], '/w', r, { ...entry, env: Object.fromEntries(Object.entries(env).reverse()) });
      expect(reordered.hash).toBe(pin.hash);
      if (env[key] !== value) expect(launchFingerprint('node', ['s.js'], '/w', r, { ...entry, env: { ...env, [key]: value } }).hash).not.toBe(pin.hash);
      expect(launchFingerprint('node', ['s.js'], '/w', r, { ...entry, cwd: `${cwd ?? ''}/other` }).hash).not.toBe(pin.hash);
      for (const v of Object.values(env)) if (v.length >= 6) expect(pin.parts.join('\n')).not.toContain(`sha256:${v}`);
    }), { numRuns: 200 });
  });
});

describe('checkLaunch and approve server', () => {
  it('pins on first start, passes the same program, holds a changed one until approved', () => {
    const state = emptyState();
    const s = serverState(state, 'notes');
    const v1 = launchFingerprint('node', ['s.js'], '/w', memReader({ '/w/s.js': 'v1' }));
    const v2 = launchFingerprint('node', ['s.js'], '/w', memReader({ '/w/s.js': 'v2' }));
    expect(checkLaunch(s, v1).result).toBe('pinned');
    expect(checkLaunch(s, v1).result).toBe('same');
    const changed = checkLaunch(s, v2);
    expect(changed.result).toBe('changed');
    if (changed.result === 'changed') {
      expect(changed.removed[0]).toContain('s.js');
      expect(changed.added[0]).toContain('s.js');
    }
    expect(s.launch?.hash).toBe(v1.hash); // the old pin stays until approval
    expect(approveServer(state, 'notes')).toMatchObject({ ok: true });
    expect(state.servers['notes']?.launch?.hash).toBe(v2.hash);
    expect(state.servers['notes']?.pendingLaunch).toBeUndefined();
    expect(checkLaunch(s, v2).result).toBe('same');
    expect(approveServer(state, 'notes')).toMatchObject({ ok: false });
  });
});

/** Start the real proxy on a copy of the fake server, send initialize and tools/list, then close. */
async function startOnce(root: string, policy?: object, configPath?: string): Promise<{ code: number; err: string; listed: boolean }> {
  const dir = join(root, '.exorcist');
  if (policy) { mkdirSync(dir, { recursive: true }); writeFileSync(join(dir, 'policy.json'), JSON.stringify(policy)); }
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  let err = '';
  let out = '';
  stderr.on('data', (c: Buffer) => { err += c.toString(); });
  stdout.on('data', (c: Buffer) => { out += c.toString(); });
  const done = runProxy({
    server: 'notes', command: process.execPath, args: ['server.mjs'], cwd: root, dir, definitionsDir: DEFS, pollMs: 50,
    ...(configPath ? { configPath } : {}),
    env: { ...process.env, FAKE_MCP_CONTROL: join(root, 'control.json'), FAKE_MCP_LOG: join(root, 'calls.log') },
    stdin, stdout, stderr,
  });
  stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })}\n`);
  const deadline = Date.now() + 5000;
  const settled = await Promise.race([done.then((c) => ({ c })), (async () => {
    while (!out.includes('"id":1') && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
    return undefined;
  })()]);
  if (settled && 'c' in settled) return { code: settled.c, err, listed: false };
  stdin.end();
  const code = await done;
  return { code, err, listed: out.includes('read_note') };
}

describe('the proxy with a launch pin', () => {
  it('starts a pinned server, refuses a changed one, and starts it again after approve server', async () => {
    const root = tmp();
    copyFileSync(FAKE, join(root, 'server.mjs'));
    const first = await startOnce(root);
    expect(first.listed).toBe(true);
    expect(first.err).toContain('Pinned the program behind "notes"');
    expect(loadState(statePath(join(root, '.exorcist')))).toMatchObject({ ok: true });

    // The same tools, new code: an update that adds behaviour without changing any description.
    appendFileSync(join(root, 'server.mjs'), '\n// update 1.0.1\n');
    const changed = await startOnce(root);
    expect(changed.code).toBe(FAIL_CLOSED_EXIT);
    expect(changed.listed).toBe(false);
    expect(changed.err).toContain('exorcist approve server notes');
    const alerts = readFileSync(alertsPath(join(root, '.exorcist')), 'utf8');
    expect(alerts).toContain('"ruleId":"EX-010"');
    expect(alerts).toContain('It was not started');
    expect(existsSync(join(root, 'calls.log')) ? readFileSync(join(root, 'calls.log'), 'utf8') : '').toBe('');

    const loaded = loadState(statePath(join(root, '.exorcist')));
    if (!loaded.ok) throw new Error(loaded.error);
    expect(approveServer(loaded.state, 'notes')).toMatchObject({ ok: true });
    saveState(statePath(join(root, '.exorcist')), loaded.state);
    const again = await startOnce(root);
    expect(again.listed).toBe(true);
  }, 30_000);

  it('a config change that only adds NODE_OPTIONS to the server env is a changed program (m5-lockfile)', async () => {
    const root = tmp();
    copyFileSync(FAKE, join(root, 'server.mjs'));
    const config = join(root, 'mcp.json');
    const write = (env: Record<string, string>) => writeFileSync(config, JSON.stringify({ mcpServers: { notes: { command: 'exorcist', args: ['shield', '--server', 'notes', '--config', config, '--', 'node', 'server.mjs'], env } } }));
    write({ NOTES_DIR: '/tmp/notes' });
    expect((await startOnce(root, undefined, config)).listed).toBe(true);
    expect((await startOnce(root, undefined, config)).listed).toBe(true); // same env: same program

    write({ NOTES_DIR: '/tmp/notes', NODE_OPTIONS: '--require ./evil.js' });
    const changed = await startOnce(root, undefined, config);
    expect(changed.code).toBe(FAIL_CLOSED_EXIT);
    expect(changed.listed).toBe(false);
    const alerts = readFileSync(alertsPath(join(root, '.exorcist')), 'utf8');
    expect(alerts).toContain('"ruleId":"EX-010"');
    expect(alerts).toContain('+ env NODE_OPTIONS sha256:');
    expect(alerts).not.toContain('evil.js');
  }, 30_000);

  it('policy launchPin "warn" starts a changed server with an alert; "off" pins nothing', async () => {
    const root = tmp();
    copyFileSync(FAKE, join(root, 'server.mjs'));
    expect((await startOnce(root)).listed).toBe(true);
    appendFileSync(join(root, 'server.mjs'), '\n// update\n');
    const warned = await startOnce(root, { launchPin: 'warn' });
    expect(warned.listed).toBe(true);
    expect(warned.err).toContain('It was started anyway');

    const other = tmp();
    copyFileSync(FAKE, join(other, 'server.mjs'));
    expect((await startOnce(other, { launchPin: 'off' })).listed).toBe(true);
    const st = loadState(statePath(join(other, '.exorcist')));
    expect(st.ok && st.state.servers['notes']?.launch).toBeFalsy();
  }, 30_000);
});
