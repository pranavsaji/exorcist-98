import type { Readable, Writable } from 'node:stream';
import { errorResponse, LineSplitter } from './jsonrpc.js';
import type { JsonRpcId } from './jsonrpc.js';
import { prepareShield } from './proxy.js';
import type { ShieldSetupOptions } from './proxy.js';
import type { Action } from './engine.js';

/**
 * The Shield in front of a REMOTE MCP server (S-005).
 *
 * The agent's client starts `exorcist shield --url <remote>` like any local
 * server and talks stdio to it; the Shield talks MCP Streamable HTTP to the
 * remote server. Every message in both directions goes through the same
 * engine as for local servers: pins and rug-pull detection, secrets and hosts
 * in calls, attacks in results, server-initiated requests, approval prompts.
 */
export type RemoteProxyOptions = ShieldSetupOptions & {
  url: string;
  /** Extra request headers (for example Authorization). Values are never logged. */
  headers?: Record<string, string>;
  stdin?: Readable;
  stdout?: Writable;
  fetchFn?: typeof fetch;
  /** Per-request time limit (ms). */
  timeoutMs?: number;
  /** Allow plain http to a host that is not this machine (tokens would travel unencrypted). */
  allowInsecure?: boolean;
  /** Wait before reopening a dropped server stream, per attempt (ms). Default 1 s, 2 s, 4 s ... up to 30 s. */
  reconnectBaseMs?: number;
};

const MAX_RECONNECTS = 8;

const MAX_EVENT_BYTES = 16 * 1024 * 1024;
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

export type UrlCheck = { ok: true; url: URL } | { ok: false; error: string };

export function checkRemoteUrl(raw: string, allowInsecure = false): UrlCheck {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, error: `"${raw}" is not a URL.` };
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return { ok: false, error: `Only http and https MCP servers are supported, not ${url.protocol}` };
  if (url.username || url.password) return { ok: false, error: 'Put credentials in a header (--header-env), not in the URL.' };
  if (url.protocol === 'http:' && !LOOPBACK.has(url.hostname) && !allowInsecure) {
    return { ok: false, error: `Refusing plain http to ${url.hostname}: anything sent, including tokens, would be readable on the network. Use https, or --allow-insecure if you must.` };
  }
  return { ok: true, url };
}

/** Split an SSE stream into the `data` of each event. */
export class SseParser {
  private buf = '';
  private data: string[] = [];
  private size = 0;

  push(chunk: string): string[] {
    this.buf += chunk;
    const out: string[] = [];
    let nl = this.buf.search(/\r\n|\n|\r/);
    while (nl !== -1) {
      const sep = this.buf.startsWith('\r\n', nl) ? 2 : 1;
      const line = this.buf.slice(0, nl);
      this.buf = this.buf.slice(nl + sep);
      if (line === '') {
        if (this.data.length > 0) out.push(this.data.join('\n'));
        this.data = [];
        this.size = 0;
      } else if (line.startsWith('data:')) {
        const v = line.slice(5).replace(/^ /, '');
        this.size += v.length;
        if (this.size <= MAX_EVENT_BYTES) this.data.push(v);
      }
      // `event:`, `id:`, `retry:` and comments (`:`) carry nothing the Shield needs.
      nl = this.buf.search(/\r\n|\n|\r/);
    }
    if (this.buf.length > MAX_EVENT_BYTES) this.buf = '';
    return out;
  }
}

type Message = Record<string, unknown>;

export async function runRemoteProxy(o: RemoteProxyOptions): Promise<number> {
  const stdin = o.stdin ?? process.stdin;
  const stdout = o.stdout ?? process.stdout;
  const stderr = o.stderr ?? process.stderr;
  const fetchFn = o.fetchFn ?? fetch;
  const timeoutMs = o.timeoutMs ?? 120_000;

  const checked = checkRemoteUrl(o.url, o.allowInsecure);
  if (!checked.ok) {
    stderr.write(`[exorcist] ${checked.error}\n`);
    return 2;
  }
  const url = checked.url.href;

  const prepared = await prepareShield({ ...o, stderr });
  if (typeof prepared === 'number') return prepared;
  const { engine, log, handle } = prepared;
  log(`Remote server: ${checked.url.origin}${checked.url.pathname}`);

  let sessionId: string | null = null;
  let protocolVersion: string | null = null;
  let initializeId: JsonRpcId | null = null;
  let getStreamOpen = false;
  let closing = false;
  const getCtl = new AbortController();
  const inFlight = new Set<Promise<void>>();

  const headers = (extra: Record<string, string> = {}): Record<string, string> => ({
    ...(o.headers ?? {}),
    ...(sessionId ? { 'mcp-session-id': sessionId } : {}),
    ...(protocolVersion ? { 'mcp-protocol-version': protocolVersion } : {}),
    ...extra,
  });

  const toClient = (m: unknown): void => void stdout.write(`${JSON.stringify(m)}\n`);

  /** Handle one message from the remote server. */
  const fromServer = (raw: string): void => {
    // Learn the negotiated protocol version from the initialize response.
    if (initializeId !== null) {
      try {
        const m = JSON.parse(raw) as Message;
        if (m['id'] === initializeId && m['result'] && typeof m['result'] === 'object') {
          const v = (m['result'] as { protocolVersion?: unknown }).protocolVersion;
          if (typeof v === 'string') protocolVersion = v;
          initializeId = null;
        }
      } catch { /* the engine reports bad lines */ }
    }
    deliver(engine.onServerLine(raw));
  };

  const readBody = async (res: Response): Promise<void> => {
    const type = res.headers.get('content-type') ?? '';
    if (res.body && type.includes('text/event-stream')) {
      const parser = new SseParser();
      const decoder = new TextDecoder();
      const reader = res.body.getReader();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        for (const ev of parser.push(decoder.decode(value, { stream: true }))) fromServer(ev);
      }
      return;
    }
    const text = await res.text();
    if (!text.trim()) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      log('The remote server sent a reply that was not JSON; it was dropped.');
      return;
    }
    for (const m of Array.isArray(parsed) ? parsed : [parsed]) fromServer(JSON.stringify(m));
  };

  /**
   * Open the stream for messages the server sends on its own, once a session
   * exists. If it drops, reopen it with a growing wait (a few times), so
   * server notifications and requests do not silently stop.
   */
  const openGetStream = (): void => {
    if (getStreamOpen || closing) return;
    getStreamOpen = true;
    const base = o.reconnectBaseMs ?? 1_000;
    const p = (async () => {
      try {
        for (let attempt = 0; attempt <= MAX_RECONNECTS && !closing; attempt++) {
          let delivered = false;
          try {
            const res = await fetchFn(url, { method: 'GET', headers: headers({ accept: 'text/event-stream' }), signal: getCtl.signal });
            if (res.status === 405 || res.status === 404 || !res.ok) return; // optional for servers
            delivered = true;
            await readBody(res);
          } catch {
            if (closing) return;
          }
          if (closing) return;
          if (delivered) attempt = 0; // a stream that connected resets the count
          if (attempt === MAX_RECONNECTS) {
            log('The remote server stream dropped and could not be reopened; server-initiated messages will not arrive until the next request.');
            return;
          }
          await new Promise((r) => setTimeout(r, Math.min(30_000, base * 2 ** attempt)));
        }
      } finally {
        getStreamOpen = false;
      }
    })();
    inFlight.add(p);
    void p.finally(() => inFlight.delete(p));
  };

  const post = (message: unknown): void => {
    const m = message as Message;
    const isRequest = typeof m['method'] === 'string' && m['id'] !== undefined;
    if (m['method'] === 'initialize' && m['id'] !== undefined) initializeId = m['id'] as JsonRpcId;
    const p = (async () => {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), timeoutMs);
      try {
        const res = await fetchFn(url, {
          method: 'POST',
          headers: headers({ 'content-type': 'application/json', accept: 'application/json, text/event-stream' }),
          body: JSON.stringify(message),
          signal: ctl.signal,
        });
        const sid = res.headers.get('mcp-session-id');
        if (sid && /^[\x21-\x7e]{1,256}$/.test(sid)) sessionId = sid;
        // A notification is usually answered with 202 and no body. After initialized, open the server stream.
        if (res.status === 202) {
          if (m['method'] === 'notifications/initialized') openGetStream();
          return;
        }
        if (!res.ok) {
          const why = res.status === 404 && sessionId ? 'the remote session expired' : `HTTP ${res.status}`;
          log(`The remote server refused a message (${why}).`);
          if (isRequest) fromServer(JSON.stringify(errorResponse(m['id'] as JsonRpcId, -32000, `Exorcist 98: the remote MCP server refused the request (${why}).`)));
          return;
        }
        await readBody(res);
        if (m['method'] === 'notifications/initialized') openGetStream();
      } catch (err) {
        const why = ctl.signal.aborted ? `no answer within ${Math.round(timeoutMs / 1000)} s` : String(err).split('\n')[0]?.slice(0, 160);
        log(`Could not reach the remote server: ${why}`);
        // Through the engine like any server reply: the request may be the Shield's own (a check before a call).
        if (isRequest) fromServer(JSON.stringify(errorResponse(m['id'] as JsonRpcId, -32000, `Exorcist 98: could not reach the remote MCP server (${why}).`)));
      } finally {
        clearTimeout(timer);
      }
    })();
    inFlight.add(p);
    void p.finally(() => inFlight.delete(p));
  };

  const deliver = (actions: Action[]): void => {
    for (const f of handle(actions)) {
      if (f.to === 'client') toClient(f.message);
      else post(f.message);
    }
  };

  const fromClient = new LineSplitter();
  const stopWatch = prepared.watch(deliver);

  return await new Promise<number>((resolve) => {
    stdin.on('data', (chunk: Buffer) => { for (const l of fromClient.push(chunk)) deliver(engine.onClientLine(l)); });
    stdin.on('end', () => {
      for (const l of fromClient.flush()) deliver(engine.onClientLine(l));
      closing = true;
      stopWatch();
      void (async () => {
        // Let requests already sent finish, but not the open-ended GET stream.
        const deadline = Date.now() + 5_000;
        while ([...inFlight].length > (getStreamOpen ? 1 : 0) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
        getCtl.abort();
        if (sessionId) {
          try { await fetchFn(url, { method: 'DELETE', headers: headers(), signal: AbortSignal.timeout(5_000) }); } catch { /* best effort */ }
        }
        resolve(0);
      })();
    });
  });
}
