/**
 * The live console's web server (`exorcist console`).
 *
 * - Listens on 127.0.0.1 only, on a random port unless one is given.
 * - Every URL starts with an unguessable token (/<token>/...): a request
 *   without it, or with a wrong one, gets 404 (compared in constant time).
 * - The Host header must be 127.0.0.1:<port> or localhost:<port>, so a page
 *   on another site that rebinds its DNS name to 127.0.0.1 is refused (421).
 *   A cross-site Origin or Sec-Fetch-Site is refused too (403).
 * - GET and HEAD only. There is no endpoint that changes anything: the
 *   console is a read-only view of the state folder.
 * - The page carries a strict Content-Security-Policy with a fresh nonce per
 *   response; JSON and the event stream escape <, >, & and line separators.
 */
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { CapabilityRule } from '@exorcist-98/core';
import { ConsoleModel } from './model.js';
import type { Liveness } from './model.js';
import { consolePage } from './page.js';

export const MAX_CLIENTS = 8;
const HEARTBEAT_MS = 15_000;

export type ConsoleOptions = {
  dir: string;
  /** 0 or absent: a random free port. */
  port?: number;
  /** How often to read the state folder (ms). */
  pollMs?: number;
  rules?: readonly CapabilityRule[];
  /** For tests. */
  token?: string;
  alive?: Liveness;
};

export type ConsoleServer = {
  url: string;
  port: number;
  token: string;
  close: () => Promise<void>;
};

/** JSON that is safe inside HTML and an event stream: no <, >, &, or JS line separators. */
export function safeJson(value: unknown): string {
  return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

export function pageCsp(nonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    `style-src 'nonce-${nonce}'`,
    "connect-src 'self'",
    "img-src 'self' data:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; ');
}

const DATA_CSP = "default-src 'none'; frame-ancestors 'none'";

function common(res: ServerResponse, csp: string): void {
  res.setHeader('Content-Security-Policy', csp);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store');
}

function plain(res: ServerResponse, status: number, text: string, extra: Record<string, string> = {}): void {
  common(res, DATA_CSP);
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', ...extra });
  res.end(`${text}\n`);
}

function sameToken(given: string, token: string): boolean {
  const a = Buffer.from(given, 'utf8');
  const b = Buffer.from(token, 'utf8');
  // Compare equal-length buffers so the time does not depend on where they differ.
  const padded = Buffer.alloc(b.length);
  a.copy(padded, 0, 0, Math.min(a.length, b.length));
  return timingSafeEqual(padded, b) && a.length === b.length;
}

export async function startConsole(o: ConsoleOptions): Promise<ConsoleServer> {
  const token = o.token ?? randomBytes(32).toString('base64url');
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(token)) throw new Error('The console token must be 32 to 128 URL-safe characters.');
  const model = new ConsoleModel(o.dir, { ...(o.rules ? { rules: o.rules } : {}), ...(o.alive ? { alive: o.alive } : {}) });
  model.poll();
  let stateJson = safeJson(model.state());

  const clients = new Set<ServerResponse>();
  let port = 0;
  const hosts = (): Set<string> => new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  const origins = (): Set<string> => new Set([`http://127.0.0.1:${port}`, `http://localhost:${port}`]);

  const send = (res: ServerResponse, event: string, data: string): void => {
    res.write(`event: ${event}\ndata: ${data}\n\n`);
  };

  const tick = (): void => {
    let fresh;
    try {
      fresh = model.poll();
    } catch {
      return; // A read that failed is tried again on the next tick.
    }
    const next = safeJson(model.state());
    if (fresh.length > 0) for (const c of clients) send(c, 'events', safeJson(fresh));
    if (next !== stateJson) {
      stateJson = next;
      for (const c of clients) send(c, 'state', stateJson);
    }
  };
  const poller = setInterval(tick, o.pollMs ?? 500);
  const beat = setInterval(() => { for (const c of clients) c.write(': keep-alive\n\n'); }, HEARTBEAT_MS);
  poller.unref();
  beat.unref();

  const handle = (req: IncomingMessage, res: ServerResponse): void => {
    // DNS rebinding: only our own host names, with our port.
    if (!hosts().has(String(req.headers.host ?? '').toLowerCase())) { plain(res, 421, 'Misdirected request.'); return; }
    const origin = req.headers.origin;
    if (origin !== undefined && !origins().has(origin)) { plain(res, 403, 'Cross-origin requests are refused.'); return; }
    const site = req.headers['sec-fetch-site'];
    if (site !== undefined && site !== 'same-origin' && site !== 'none') { plain(res, 403, 'Cross-site requests are refused.'); return; }
    if (req.method !== 'GET' && req.method !== 'HEAD') { plain(res, 405, 'This console is read-only.', { Allow: 'GET, HEAD' }); return; }

    let path: string;
    try {
      path = new URL(req.url ?? '/', 'http://127.0.0.1').pathname;
    } catch {
      plain(res, 400, 'Bad request.');
      return;
    }
    const parts = path.split('/');
    // ['', token, ...rest]
    if (parts.length < 2 || !sameToken(parts[1] ?? '', token)) { plain(res, 404, 'Not found.'); return; }
    const rest = parts.slice(2).join('/');

    if (rest === '') {
      if (!path.endsWith('/')) { common(res, DATA_CSP); res.writeHead(308, { Location: `/${token}/` }); res.end(); return; }
      const nonce = randomBytes(18).toString('base64');
      common(res, pageCsp(nonce));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(req.method === 'HEAD' ? undefined : consolePage(nonce));
      return;
    }
    if (rest === 'api/state') {
      common(res, DATA_CSP);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(req.method === 'HEAD' ? undefined : `{"state":${stateJson},"events":${safeJson(model.events())}}`);
      return;
    }
    if (rest === 'api/stream') {
      if (clients.size >= MAX_CLIENTS) { plain(res, 503, 'Too many open console pages.'); return; }
      common(res, DATA_CSP);
      res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', Connection: 'keep-alive' });
      if (req.method === 'HEAD') { res.end(); return; }
      res.write('retry: 2000\n\n');
      send(res, 'hello', `{"state":${stateJson},"events":${safeJson(model.events())}}`);
      clients.add(res);
      req.on('close', () => clients.delete(res));
      return;
    }
    plain(res, 404, 'Not found.');
  };

  const server = createServer((req, res) => {
    try { handle(req, res); } catch { if (!res.headersSent) plain(res, 500, 'Internal error.'); else res.end(); }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 0; // the event stream stays open
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(o.port ?? 0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  port = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${port}/${token}/`,
    port,
    token,
    close: async () => {
      clearInterval(poller);
      clearInterval(beat);
      for (const c of clients) c.end();
      clients.clear();
      const closed = new Promise<void>((r) => server.close(() => r()));
      server.closeAllConnections();
      await closed;
    },
  };
}
