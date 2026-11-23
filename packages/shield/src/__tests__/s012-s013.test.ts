import { describe, expect, it, afterEach } from 'vitest';
import fc from 'fast-check';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PassThrough } from 'node:stream';
import { cleanText, notifyCommand, throttle } from '../notify.js';
import { findDefinitionsDir, findStateDir } from '../locate.js';
import { runProxy } from '../proxy.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = () => { const d = realpathSync(mkdtempSync(join(tmpdir(), 'x98-s012-'))); dirs.push(d); return d; };

describe('S-012 desktop notifications', () => {
  const hostile = 'Ends "quote" `tick` $(rm -rf ~) ; & | \' end\nnext\u202eline\u200b';

  it('macOS: text goes in argv to a fixed AppleScript, never into the script', () => {
    const c = notifyCommand('darwin', 'Exorcist 98', hostile);
    expect(c?.file).toBe('/usr/bin/osascript');
    const script = c?.args.filter((_, i, a) => a[i - 1] === '-e') ?? [];
    expect(script.join('\n')).not.toContain('rm -rf');
    expect(c?.args.at(-1)).toBe(cleanText(hostile));
  });

  it('Linux: notify-send with the text as plain arguments', () => {
    const c = notifyCommand('linux', 't', hostile);
    expect(c).toMatchObject({ file: 'notify-send' });
    expect(c?.args.at(-1)).toBe(cleanText(hostile));
  });

  it('Windows: the text is passed in environment variables, the script is fixed', () => {
    const c = notifyCommand('win32', 't', hostile);
    expect(c?.file).toBe('powershell.exe');
    expect(c?.args.join(' ')).not.toContain('rm -rf');
    expect(c?.env?.['X98_BODY']).toBe(cleanText(hostile));
  });

  it('other platforms: no command', () => {
    expect(notifyCommand('aix', 't', 'b')).toBeNull();
  });

  it('cleaned text is one short line with no control or hidden characters', () => {
    fc.assert(fc.property(fc.string({ maxLength: 500 }), (s) => {
      const c = cleanText(s);
      expect(c.length).toBeLessThanOrEqual(220);
      expect(c).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/);
    }));
  });

  it('a burst is throttled: once per key per minute, at most five a minute', () => {
    let t = 0;
    const allow = throttle({ now: () => t });
    expect(allow('EX-006:read_note')).toBe(true);
    expect(allow('EX-006:read_note')).toBe(false);
    for (const k of ['a', 'b', 'c', 'd']) expect(allow(k)).toBe(true);
    expect(allow('e')).toBe(false);
    t = 61_000;
    expect(allow('EX-006:read_note')).toBe(true);
  });

  it('the proxy notifies for critical alerts, not for medium ones, and the policy can turn it off', async () => {
    const run = async (policy?: object) => {
      const root = tmp();
      const dir = join(root, '.exorcist');
      mkdirSync(dir, { recursive: true });
      if (policy) writeFileSync(join(dir, 'policy.json'), JSON.stringify(policy));
      const seen: string[] = [];
      const stdin = new PassThrough();
      const stdout = new PassThrough();
      const stderr = new PassThrough();
      const done = runProxy({
        server: 'notes', command: process.execPath, args: [join(import.meta.dirname, 'fake-mcp-server.mjs')], dir,
        definitionsDir: resolve(import.meta.dirname, '../../../../definitions'), stdin, stdout, stderr,
        env: { ...process.env, FAKE_MCP_LOG: join(root, 'log'), FAKE_MCP_CONTROL: join(root, 'control.json') },
        notify: (title, body) => seen.push(`${title} | ${body}`),
      });
      const secret = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
      stdin.write('not json\n'); // a medium alert: no notification
      stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'send_report', arguments: { url: 'http://localhost', body: secret } } })}\n`);
      await new Promise((r) => setTimeout(r, 600));
      stdin.end();
      await done;
      return seen;
    };
    const on = await run();
    expect(on).toHaveLength(1);
    expect(on[0]).toMatch(/threat blocked \(notes\)/);
    expect(on[0]).not.toContain(['AKIA', 'ABCDEFGHIJKLMNOP'].join(''));
    expect(await run({ notify: false })).toEqual([]);
  }, 30_000);
});

describe('S-013 where the state folder is', () => {
  it('uses --dir, then EXORCIST_DIR, then the nearest project folder, then cwd; always absolute', () => {
    const proj = tmp();
    mkdirSync(join(proj, '.git'));
    const deep = join(proj, 'a', 'b');
    mkdirSync(deep, { recursive: true });
    expect(findStateDir({ cwd: deep, env: {} })).toBe(join(proj, '.exorcist'));
    expect(findStateDir({ cwd: deep, env: { EXORCIST_DIR: '/srv/x98' } })).toBe('/srv/x98');
    expect(findStateDir({ cwd: deep, env: { EXORCIST_DIR: 'rel' } })).toBe(join(deep, 'rel'));
    expect(findStateDir({ cwd: deep, env: {}, explicit: 'here' })).toBe(join(deep, 'here'));
    const bare = tmp();
    expect(findStateDir({ cwd: bare, env: {} }).startsWith('/')).toBe(true);
  });

  it('an existing .exorcist folder wins over a .git further up', () => {
    const proj = tmp();
    mkdirSync(join(proj, '.git'));
    mkdirSync(join(proj, 'pkg', '.exorcist'), { recursive: true });
    expect(findStateDir({ cwd: join(proj, 'pkg'), env: {} })).toBe(join(proj, 'pkg', '.exorcist'));
  });

  it('the proxy logs the absolute state folder it uses', async () => {
    const root = tmp();
    const stderr = new PassThrough();
    let err = '';
    stderr.on('data', (c: Buffer) => { err += c.toString(); });
    const stdin = new PassThrough();
    const done = runProxy({ server: 'notes', command: process.execPath, args: [join(import.meta.dirname, 'fake-mcp-server.mjs')], dir: join(root, '.exorcist'), definitionsDir: resolve(import.meta.dirname, '../../../../definitions'), stdin, stdout: new PassThrough(), stderr });
    stdin.end();
    await done;
    expect(err).toContain(`State folder: ${join(root, '.exorcist')}`);
  });
});

describe('S-019 one definitions lookup', () => {
  it('explicit, then EXORCIST_DEFINITIONS, then next to the caller, then cwd', () => {
    const d = tmp();
    mkdirSync(join(d, 'definitions'));
    writeFileSync(join(d, 'definitions', 'EX-001-x.yaml'), 'id: EX-001');
    const callerUrl = new URL(`file://${join(d, 'dist', 'index.mjs')}`).href;
    // No LiveUpdate sets: point the install folder somewhere empty, never at the real home.
    const env = { EXORCIST_DEFINITIONS_HOME: join(d, 'no-updates') };
    expect(findDefinitionsDir({ callerUrl, env, cwd: '/' })).toBe(join(d, 'definitions'));
    expect(findDefinitionsDir({ callerUrl, env: { ...env, EXORCIST_DEFINITIONS: '/x' }, cwd: '/' })).toBe('/x');
    expect(findDefinitionsDir({ callerUrl, env, cwd: '/', explicit: '/y' })).toBe('/y');
    expect(findDefinitionsDir({ callerUrl: 'file:///nowhere/dist/index.mjs', env, cwd: d })).toBe(join(d, 'definitions'));
    expect(findDefinitionsDir({ callerUrl: 'file:///nowhere/dist/index.mjs', env, cwd: '/nowhere' })).toBeNull();
  });
});
