import { resolve } from 'node:path';
import { desktopNotifier, runProxy, runRemoteProxy } from '@exorcist-98/shield';
import { DEFAULT_DIR, stateDir, findDefinitionsDir, parse, str, strs } from '../util.js';
import type { Io } from '../util.js';

export const SHIELD_HELP = `Usage: exorcist shield --server <name> [options] -- <command> [args...]
       exorcist shield --server <name> --url <https://...> [options]

Run one MCP server behind the Real-Time Shield. Put this in your MCP config
(or use "exorcist wrap" to do it for you). With --url, the Shield protects a
remote server: your client starts this command as a local server, and the
Shield talks to the remote one over MCP Streamable HTTP.

Options:
  --server <name>          Name of the server (used for pins and alerts)
  --url <url>              A remote MCP server (https; http only for this machine)
  --header "Name: value"   Send this header to the remote server (repeatable)
  --header-env Name=VAR    Send header Name with the value of environment variable
                           VAR, so tokens stay out of the command line (repeatable)
  --allow-insecure         Allow plain http to another machine (not recommended)
  --config <file>          MCP config that holds the server, so it can be quarantined
  --dir <folder>           State folder (default: ${DEFAULT_DIR})
  --definitions <dir>      Folder of virus definitions
`;

const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/;
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'content-type', 'accept', 'mcp-session-id', 'mcp-protocol-version', 'connection', 'transfer-encoding']);

export type HeaderResult = { ok: true; headers: Record<string, string> } | { ok: false; error: string };

/** Build the remote headers. Values are never echoed in errors. */
export function parseHeaders(literal: readonly string[], fromEnv: readonly string[], env: NodeJS.ProcessEnv): HeaderResult {
  const headers: Record<string, string> = {};
  const add = (name: string, value: string): string | null => {
    const n = name.trim();
    if (!HEADER_NAME.test(n)) return `"${n}" is not a valid header name.`;
    if (FORBIDDEN_HEADERS.has(n.toLowerCase())) return `The Shield sets "${n}" itself.`;
    if (/[\r\n\0]/.test(value)) return `The value for "${n}" contains a line break.`;
    headers[n.toLowerCase()] = value.trim();
    return null;
  };
  for (const h of literal) {
    const i = h.indexOf(':');
    if (i <= 0) return { ok: false, error: `--header needs "Name: value".` };
    const e = add(h.slice(0, i), h.slice(i + 1));
    if (e) return { ok: false, error: e };
  }
  for (const h of fromEnv) {
    const i = h.indexOf('=');
    if (i <= 0) return { ok: false, error: '--header-env needs "Name=VARIABLE".' };
    const name = h.slice(0, i);
    const variable = h.slice(i + 1);
    const value = env[variable];
    if (value === undefined || value === '') return { ok: false, error: `The environment variable ${variable} (for header ${name.trim()}) is not set.` };
    const e = add(name, value);
    if (e) return { ok: false, error: e };
  }
  return { ok: true, headers };
}

export async function shieldCommand(argv: string[], io: Io): Promise<number> {
  const sep = argv.indexOf('--');
  const flags = sep === -1 ? argv : argv.slice(0, sep);
  const rest = sep === -1 ? [] : argv.slice(sep + 1);

  const p = parse(flags, {
    server: { type: 'string' }, config: { type: 'string' }, dir: { type: 'string' },
    definitions: { type: 'string' }, url: { type: 'string' },
    header: { type: 'string', multiple: true }, 'header-env': { type: 'string', multiple: true },
    'allow-insecure': { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
    // Written by `exorcist wrap` so `unwrap` can restore a remote entry exactly; not used here.
    'remote-type': { type: 'string' }, 'remote-headers': { type: 'string' }, 'remote-env': { type: 'string' }, 'remote-keys': { type: 'string' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${SHIELD_HELP}`); return 2; }
  if (p.values['help']) { io.out(SHIELD_HELP); return 0; }

  const server = str(p.values['server']);
  const url = str(p.values['url']);
  const command = rest[0];
  if (!server || (!command && !url)) { io.err(`Give --server and either --url or the server command after "--".\n\n${SHIELD_HELP}`); return 2; }
  if (url && command) { io.err(`Give either --url or a command after "--", not both.\n\n${SHIELD_HELP}`); return 2; }

  const defs = findDefinitionsDir(str(p.values['definitions']));
  if (!defs) { io.err('Could not find the virus definitions. Pass --definitions <dir> or set EXORCIST_DEFINITIONS.'); return 78; }

  const config = str(p.values['config']);
  const common = {
    server,
    dir: stateDir(str(p.values['dir'])),
    definitionsDir: defs,
    ...(config ? { configPath: resolve(config) } : {}),
    // Desktop notifications for critical and high alerts; EXORCIST_NOTIFY=0 or policy notify:false turns them off.
    ...(process.env['EXORCIST_NOTIFY'] === '0' ? {} : { notify: desktopNotifier() }),
  };

  if (url) {
    const h = parseHeaders(strs(p.values['header']), strs(p.values['header-env']), process.env);
    if (!h.ok) { io.err(h.error); return 2; }
    return await runRemoteProxy({ ...common, url, headers: h.headers, allowInsecure: p.values['allow-insecure'] === true });
  }
  return await runProxy({ ...common, command: command as string, args: rest.slice(1) });
}
