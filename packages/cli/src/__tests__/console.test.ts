/**
 * `exorcist console`: the server (token, Host check, CSP, read-only, escaping,
 * the event stream) and the model (held calls, dead Shields, sessions).
 */
import { describe, expect, it, afterEach } from 'vitest';
import fc from 'fast-check';
import { createHash } from 'node:crypto';
import { request } from 'node:http';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventLog, FileSessionStore } from '@exorcist-98/shield';
import { startConsole, safeJson, pageCsp, MAX_CLIENTS } from '../console/server.js';
import type { ConsoleServer } from '../console/server.js';
import { ConsoleModel } from '../console/model.js';
import { consolePage } from '../console/page.js';
import { consoleCommand, openCommand } from '../commands/console.js';

const dirs: string[] = [];
const servers: ConsoleServer[] = [];
afterEach(async () => {
  for (const s of servers.splice(0)) await s.close();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-console-')); dirs.push(d); return d; };
const TOKEN = 'T'.repeat(43);
const alive = () => true;

async function serve(dir: string, o: { alive?: (pid: number) => boolean } = {}): Promise<ConsoleServer> {
  const s = await startConsole({ dir, token: TOKEN, pollMs: 25, alive: o.alive ?? alive });
  servers.push(s);
  return s;
}

type Res = { status: number; headers: Record<string, string | string[] | undefined>; body: string };
function get(port: number, path: string, o: { method?: string; headers?: Record<string, string> } = {}): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method: o.method ?? 'GET', headers: { Host: `127.0.0.1:${port}`, ...o.headers } }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

/** Open the event stream and collect its events. */
function stream(port: number): Promise<{ events: Array<{ event: string; data: any }>; close: () => void; until: (f: (e: Array<{ event: string; data: any }>) => boolean, ms?: number) => Promise<void> }> {
  return new Promise((resolve, reject) => {
    const events: Array<{ event: string; data: any }> = [];
    const req = request({ host: '127.0.0.1', port, path: `/${TOKEN}/api/stream`, headers: { Host: `127.0.0.1:${port}` } }, (res) => {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c: string) => {
        buf += c;
        let i = buf.indexOf('\n\n');
        while (i !== -1) {
          const block = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const ev = /^event: (.*)$/m.exec(block)?.[1];
          const data = /^data: (.*)$/m.exec(block)?.[1];
          if (ev && data) events.push({ event: ev, data: JSON.parse(data) });
          i = buf.indexOf('\n\n');
        }
      });
      resolve({
        events,
        close: () => req.destroy(),
        until: async (f, ms = 5000) => {
          const end = Date.now() + ms;
          while (!f(events)) {
            if (Date.now() > end) throw new Error(`timed out; got ${JSON.stringify(events.map((e) => e.event))}`);
            await new Promise((r) => setTimeout(r, 20));
          }
        },
      });
    });
    req.on('error', reject);
    req.end();
  });
}

/** Every file under a folder with its size, mode, mtime and content hash. */
function fingerprint(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const n of readdirSync(d).sort()) {
      const p = join(d, n);
      const st = statSync(p);
      if (st.isDirectory()) { out.push(`${p}/ ${st.mtimeMs}`); walk(p); }
      else out.push(`${p} ${st.size} ${st.mode} ${st.mtimeMs} ${createHash('sha256').update(readFileSync(p)).digest('hex')}`);
    }
  };
  walk(dir);
  return out;
}

describe('console server: who may connect', () => {
  it('serves only on 127.0.0.1 and only under the token; anything else is 404', async () => {
    const dir = tmp();
    const s = await serve(dir);
    expect(s.url).toBe(`http://127.0.0.1:${s.port}/${TOKEN}/`);
    expect((await get(s.port, `/${TOKEN}/`)).status).toBe(200);
    for (const path of ['/', '/api/state', `/${TOKEN.slice(1)}/`, `/${TOKEN}x/`, `/x${TOKEN}/`, `/${TOKEN.toLowerCase()}/api/state`, `/${TOKEN}/../api/state`, '/favicon.ico', `/${TOKEN}/nope`]) {
      const r = await get(s.port, path);
      expect([404, 308], path).toContain(r.status);
      expect(r.body).not.toContain('"state"');
    }
  });

  it('the default token is long and random', async () => {
    const a = await startConsole({ dir: tmp(), alive }); servers.push(a);
    const b = await startConsole({ dir: tmp(), alive }); servers.push(b);
    expect(a.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.token).not.toBe(b.token);
    expect(a.port).not.toBe(b.port);
  });

  it('refuses a request whose Host is not this console (DNS rebinding), and cross-site requests', async () => {
    const s = await serve(tmp());
    for (const host of ['evil.example', `evil.example:${s.port}`, `127.0.0.1:${s.port + 1}`, `127.0.0.1`, `0.0.0.0:${s.port}`, `[::1]:${s.port}`]) {
      const r = await get(s.port, `/${TOKEN}/api/state`, { headers: { Host: host } });
      expect(r.status, host).toBe(421);
    }
    expect((await get(s.port, `/${TOKEN}/api/state`, { headers: { Host: `localhost:${s.port}` } })).status).toBe(200);
    expect((await get(s.port, `/${TOKEN}/api/state`, { headers: { Origin: 'https://evil.example' } })).status).toBe(403);
    expect((await get(s.port, `/${TOKEN}/api/state`, { headers: { Origin: `http://127.0.0.1:${s.port}` } })).status).toBe(200);
    expect((await get(s.port, `/${TOKEN}/api/stream`, { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status).toBe(403);
  });

  it('is read-only: every method but GET and HEAD is refused, and the state folder is never changed', async () => {
    const dir = tmp();
    new EventLog(dir, { server: 'notes', pid: 99 }).write({ kind: 'call', tool: 't', decision: 'held', ruleId: 'EX-016', prompt: 1 });
    new FileSessionStore(dir, 'demo').write({ version: 1, writer: '99', updated: new Date().toISOString(), facts: [{ kind: 'untrusted', server: 's', tool: 't', ruleId: 'CAP-012', time: new Date().toISOString() }], grants: [] });
    const before = fingerprint(dir);
    const s = await serve(dir);
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
      for (const path of [`/${TOKEN}/`, `/${TOKEN}/api/state`, `/${TOKEN}/api/approve`, `/${TOKEN}/api/release`]) {
        const r = await get(s.port, path, { method });
        expect(r.status, `${method} ${path}`).toBe(405);
        expect(r.headers['allow']).toBe('GET, HEAD');
      }
    }
    await get(s.port, `/${TOKEN}/`);
    await get(s.port, `/${TOKEN}/api/state`);
    const st = await stream(s.port);
    await st.until((e) => e.length > 0);
    st.close();
    await new Promise((r) => setTimeout(r, 100));
    expect(fingerprint(dir)).toEqual(before);
  });

  it('the page has no form, no input and no write endpoint, and says it is read-only', () => {
    const html = consolePage('A'.repeat(24));
    expect(html).not.toMatch(/<form|<input|<textarea|method=/i);
    expect(html).toContain('Read-only view');
    expect(html).toContain('exorcist approve session');
    expect(html).not.toMatch(/fetch\(|XMLHttpRequest|sendBeacon/);
  });
});

describe('console server: CSP and escaping', () => {
  it('sends a strict CSP whose fresh nonce matches the page\'s one script and one style', async () => {
    const s = await serve(tmp());
    const a = await get(s.port, `/${TOKEN}/`);
    const b = await get(s.port, `/${TOKEN}/`);
    const csp = String(a.headers['content-security-policy']);
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)?.[1];
    expect(nonce).toBeTruthy();
    expect(csp).toBe(pageCsp(nonce!));
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toMatch(/unsafe-inline|unsafe-eval|\*|https?:/);
    expect(String(b.headers['content-security-policy'])).not.toContain(nonce!);
    expect(a.body.match(/<script/g)).toHaveLength(1);
    expect(a.body.match(/<style/g)).toHaveLength(1);
    expect(a.body).toContain(`<script nonce="${nonce}">`);
    expect(a.body).toContain(`<style nonce="${nonce}">`);
    // No external anything.
    expect(a.body).not.toMatch(/(?:src|href)="https?:/);
    expect(a.body).not.toMatch(/ style="/);
    for (const h of ['x-content-type-options', 'referrer-policy', 'x-frame-options', 'cache-control']) expect(a.headers[h]).toBeTruthy();
    expect(a.headers['x-content-type-options']).toBe('nosniff');
  });

  it('the page script never parses data as HTML', () => {
    const html = consolePage('A'.repeat(24));
    const script = /<script nonce="[^"]+">([\s\S]*)<\/script>/.exec(html)?.[1] ?? '';
    expect(script.length).toBeGreaterThan(1000);
    expect(script).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|setAttribute\(['"]on/);
  });

  it('JSON and the stream escape <, >, & and line separators, so log text cannot break out', async () => {
    const dir = tmp();
    const evil = '</script><img src=x onerror=alert(1)>&\u2028\u2029';
    const log = new EventLog(dir, { server: evil, pid: 99 });
    log.write({ kind: 'call', tool: evil, decision: 'blocked', why: evil });
    log.write({ kind: 'alert', severity: 'critical', ruleId: 'EX-005', tool: evil, message: evil });
    const s = await serve(dir);
    const r = await get(s.port, `/${TOKEN}/api/state`);
    expect(r.headers['content-type']).toBe('application/json; charset=utf-8');
    expect(r.body).not.toMatch(/[<>&\u2028\u2029]/);
    const parsed = JSON.parse(r.body) as { events: Array<{ tool: string }> };
    expect(parsed.events[0]!.tool).toContain('<img src=x');
    // The page itself carries no data at all.
    expect((await get(s.port, `/${TOKEN}/`)).body).not.toContain('onerror=alert');
  });

  it('property: safeJson round-trips and never contains < > & or line separators', () => {
    fc.assert(fc.property(fc.jsonValue(), (v) => {
      const s = safeJson(v);
      expect(s).not.toMatch(/[<>&\u2028\u2029]/);
      expect(JSON.parse(s)).toEqual(JSON.parse(JSON.stringify(v)));
    }), { numRuns: 300 });
  });
});

describe('console server: the event stream', () => {
  it('sends everything on connect, then each new event and state change', async () => {
    const dir = tmp();
    const log = new EventLog(dir, { server: 'notes', pid: 77, session: 'demo' });
    log.write({ kind: 'start', mode: 'enforce', guard: 'hold', remote: false });
    const s = await serve(dir);
    const st = await stream(s.port);
    await st.until((e) => e.some((x) => x.event === 'hello'));
    const hello = st.events.find((x) => x.event === 'hello')!.data;
    expect(hello.events).toHaveLength(1);
    expect(hello.state.shields).toEqual([expect.objectContaining({ server: 'notes', pid: 77, running: true })]);
    log.write({ kind: 'call', tool: 'send_report', decision: 'blocked', ruleId: 'EX-017', why: 'A secret is in the arguments.' });
    await st.until((e) => e.some((x) => x.event === 'events'));
    expect(st.events.find((x) => x.event === 'events')!.data).toEqual([expect.objectContaining({ kind: 'call', decision: 'blocked', ruleId: 'EX-017' })]);
    await st.until((e) => e.some((x) => x.event === 'state' && x.data.counts.blocked === 1));
    st.close();
  });

  it(`accepts at most ${MAX_CLIENTS} open pages`, async () => {
    const s = await serve(tmp());
    const open = await Promise.all(Array.from({ length: MAX_CLIENTS }, () => stream(s.port)));
    await Promise.all(open.map((o) => o.until((e) => e.length > 0)));
    expect((await get(s.port, `/${TOKEN}/api/stream`)).status).toBe(503);
    for (const o of open) o.close();
  });
});

describe('console model', () => {
  it('a held call waits until the user answers, or until its Shield exits', () => {
    const dir = tmp();
    const log = new EventLog(dir, { server: 'slack', pid: 501, session: 'demo' });
    log.write({ kind: 'call', tool: 'post_message', decision: 'held', ruleId: 'EX-027', prompt: 1 });
    log.write({ kind: 'call', tool: 'post_message', decision: 'held', ruleId: 'EX-027', prompt: 2 });
    log.write({ kind: 'call', tool: 'post_message', decision: 'blocked', ruleId: 'EX-027', prompt: 1, by: 'user' });
    let running = true;
    const m = new ConsoleModel(dir, { alive: () => running });
    m.poll();
    const s = m.state();
    expect(s.sessions).toHaveLength(1);
    expect(s.sessions[0]!.waiting.map((w) => w.prompt)).toEqual([2]);
    expect(s.counts).toEqual({ allowed: 0, held: 2, blocked: 1, withheld: 0, flagged: 0, alerts: 0 });
    running = false;
    expect(m.state().sessions).toEqual([]);
  });

  it('shows a session\'s facts, armed or not, once per fact, and a release from the terminal', () => {
    const dir = tmp();
    const now = new Date();
    const t = (ms: number) => new Date(now.getTime() - ms).toISOString();
    const store = new FileSessionStore(dir, 'p9-abc');
    store.write({ version: 1, writer: '11', updated: t(0), facts: [{ kind: 'untrusted', server: 'github', tool: 'get_issue', ruleId: 'CAP-012', time: t(5000) }], grants: [] });
    store.write({ version: 1, writer: '12', updated: t(0), facts: [
      { kind: 'private', server: 'files', tool: 'read_file', ruleId: 'EX-011', time: t(4000) },
      { kind: 'untrusted', server: 'github', tool: 'get_issue', ruleId: 'CAP-012', time: t(3000) },
    ], grants: [] });
    const m = new ConsoleModel(dir, { alive, now: () => now, rules: [{ id: 'CAP-012', capability: 'untrusted-input', label: 'reads issues and pull requests written by anyone', match: {} } as never] });
    const s = m.state().sessions[0]!;
    expect(s.key).toBe('p9-abc');
    expect(s.armed).toBe(true);
    expect(s.untrusted).toEqual([expect.objectContaining({ tool: 'get_issue', time: t(3000), text: 'reads issues and pull requests written by anyone' })]);
    expect(s.private).toEqual([expect.objectContaining({ tool: 'read_file', ruleId: 'EX-011' })]);

    store.write({ version: 1, writer: 'cli', updated: t(0), facts: [], grants: [{ time: t(1000), by: 'cli' }] });
    const after = m.state().sessions[0]!;
    expect(after.armed).toBe(false);
    expect(after.releasedAt).toBe(t(1000));
  });

  it('says where a held call is released: the system prompt under OS release, the terminal otherwise', () => {
    const dir = tmp();
    const os = new EventLog(dir, { server: 'mail', pid: 601, session: 'osdemo' });
    os.write({ kind: 'start', mode: 'enforce', guard: 'hold', remote: false, release: 'os' });
    os.write({ kind: 'call', tool: 'send_message', decision: 'held', ruleId: 'EX-027', via: 'os', prompt: 1 });
    const term = new EventLog(dir, { server: 'chat', pid: 602, session: 'termdemo' });
    term.write({ kind: 'start', mode: 'enforce', guard: 'hold', remote: false });
    term.write({ kind: 'call', tool: 'post', decision: 'held', ruleId: 'EX-027', prompt: 1 });
    const m = new ConsoleModel(dir, { alive });
    m.poll();
    const s = m.state();
    expect(s.release).toBe('mixed');
    expect(s.sessions.find((x) => x.key === 'osdemo')?.release).toBe('os');
    expect(s.sessions.find((x) => x.key === 'termdemo')?.release).toBe('terminal');
    // A system-prompt hold is answered with the same system prompt number: it stops waiting.
    os.write({ kind: 'call', tool: 'send_message', decision: 'allowed', ruleId: 'EX-027', via: 'os', prompt: 1, by: 'user' });
    m.poll();
    expect(m.state().sessions.find((x) => x.key === 'osdemo')).toBeUndefined();
  });
  it('the page text names the system prompt for OS release and the terminal command for terminal mode', () => {
    const html = consolePage('abcdefghijklmnop1234');
    expect(html).toContain('Touch ID');
    expect(html).toContain('exorcist approve session');
    expect(html).toContain('release-how');
  });
  it('a damaged session file is reported, not fatal', () => {
    const dir = tmp();
    mkdirSync(join(dir, 'sessions', 'demo'), { recursive: true });
    writeFileSync(join(dir, 'sessions', 'demo', '5.json'), '{broken');
    const s = new ConsoleModel(dir, { alive }).state();
    expect(s.sessions[0]!.problems.join()).toContain('not valid JSON');
  });
});

describe('exorcist console command', () => {
  it('prints the URL, opens it, and stops cleanly', async () => {
    const out: string[] = [];
    const opened: string[] = [];
    const code = await consoleCommand(['--dir', tmp()], { out: (s) => out.push(s), err: (s) => out.push(s) }, {
      open: (u) => opened.push(u),
      until: async (server) => {
        const r = await get(server.port, new URL(server.url).pathname);
        expect(r.status).toBe(200);
      },
    });
    expect(code).toBe(0);
    expect(opened).toHaveLength(1);
    expect(out.join('\n')).toContain(opened[0]!);
    expect(out.join('\n')).toContain('read-only');
  });

  it('--no-open does not open a browser; a bad port is an error', async () => {
    const opened: string[] = [];
    const io = { out: () => {}, err: () => {} };
    expect(await consoleCommand(['--dir', tmp(), '--no-open'], io, { open: (u) => opened.push(u), until: async () => {} })).toBe(0);
    expect(opened).toEqual([]);
    expect(await consoleCommand(['--port', 'abc'], io, { until: async () => {} })).toBe(2);
    expect(await consoleCommand(['--port', '70000'], io, { until: async () => {} })).toBe(2);
  });

  it('opens only its own URL, without a shell', () => {
    expect(openCommand('darwin', `http://127.0.0.1:5000/${TOKEN}/`)).toEqual({ file: 'open', args: [`http://127.0.0.1:5000/${TOKEN}/`] });
    expect(openCommand('linux', 'http://evil.example/')).toBeNull();
    expect(openCommand('win32', `http://127.0.0.1:5000/${TOKEN}/" & calc`)).toBeNull();
  });
});
