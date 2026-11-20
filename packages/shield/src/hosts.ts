/**
 * Every network host a tool-call argument could send data to (S-007).
 *
 * Covers: any `scheme://host` (http, https, ftp, ssh, ws, wss, git, ...),
 * protocol-relative `//host/...`, `user@host:path` (scp and git), bare IPv4
 * and bracketed IPv6 addresses, percent- and backslash-escaped forms, and a
 * string that is entirely a hostname (`collect.example.invalid`) when its
 * last label is a known top-level domain. File names such as `readme.md` are
 * not hosts: a bare name must have a host-shaped last label and no path-like
 * neighbours.
 */
const SCHEME_URL = /\b[a-z][a-z0-9+.-]{1,15}:\/\/(?:[^\s/?#@"'<>\\]*@)?(\[[0-9a-f:.]+\]|[^\s/?#:"'<>\\]+)/gi;
const PROTOCOL_RELATIVE = /(?:^|[\s"'(=])\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?=[/:?#\s"']|$)/gi;
const SCP_STYLE = /(?:^|[\s"'])[a-z0-9._-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+):(?!\/\/)/gi;
const IPV4 = /(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])/g;
const WHOLE_HOST = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})(?::\d{1,5})?$/i;

/**
 * Top-level domains that mark a bare string as a host. Deliberately excludes
 * short TLDs that are also common file extensions (md, sh, py, rs, ts, js, pl,
 * so, co is kept because file extensions never use it).
 */
const HOST_TLDS = new Set([
  'com', 'net', 'org', 'io', 'dev', 'app', 'ai', 'co', 'xyz', 'info', 'biz', 'me', 'us', 'uk', 'de', 'fr', 'ru',
  'cn', 'jp', 'in', 'br', 'top', 'site', 'online', 'cloud', 'tech', 'store', 'live', 'gg', 'tk', 'ml', 'ga', 'cf',
  'cc', 'tv', 'ws', 'su', 'pw', 'link', 'click', 'zip', 'mov', 'invalid', 'example', 'test', 'local', 'internal',
  'onion', 'ngrok', 'fun', 'space', 'website', 'host', 'run', 'page', 'pages', 'workers', 'edu', 'gov', 'mil', 'int',
]);

const MAX_DECODE_ROUNDS = 3;

/** Undo percent- and backslash-escaping, a few rounds deep, so encoded URLs are seen. */
export function decodeEscapes(text: string): string {
  let cur = text;
  for (let i = 0; i < MAX_DECODE_ROUNDS; i++) {
    let next = cur
      .replace(/\\u([0-9a-f]{4})/gi, (_m, h: string) => String.fromCharCode(parseInt(h, 16)))
      .replace(/\\x([0-9a-f]{2})/gi, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
    try {
      next = decodeURIComponent(next);
    } catch {
      next = next.replace(/%([0-9a-f]{2})/gi, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
    }
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

function normaliseHost(raw: string): string {
  let h = raw.toLowerCase().replace(/\.+$/, '');
  if (!h.startsWith('[')) h = h.replace(/:\d+$/, '');
  return h;
}

export function hostsIn(text: string): string[] {
  const found = new Set<string>();
  const views = new Set([text, decodeEscapes(text)]);
  for (const view of views) {
    for (const re of [SCHEME_URL, PROTOCOL_RELATIVE, SCP_STYLE]) {
      re.lastIndex = 0;
      for (const m of view.matchAll(re)) {
        const h = normaliseHost(m[1] ?? '');
        if (h && /[a-z0-9]/.test(h)) found.add(h);
      }
    }
    IPV4.lastIndex = 0;
    for (const m of view.matchAll(IPV4)) found.add(m[1] ?? '');
    const whole = view.trim();
    const w = WHOLE_HOST.exec(whole);
    if (w && HOST_TLDS.has((w[1] ?? '').toLowerCase())) found.add(normaliseHost(whole));
  }
  found.delete('');
  return [...found];
}
