export type McpServerEntry = Record<string, unknown>;
export type McpConfig = { mcpServers?: Record<string, McpServerEntry> } & Record<string, unknown>;

export type WrapOptions = {
  /** Executable that runs the shield, e.g. "exorcist" or "npx". */
  bin: string;
  /** Arguments before `shield`, e.g. ["-y", "@exorcist-98/cli@0.1.0"] when bin is npx. */
  binArgs?: string[];
  /** State folder passed to the shield (--dir). */
  dir?: string;
  /** Path of this config file, so the shield can quarantine the server. */
  configPath?: string;
};

function strArray(v: unknown): string[] | null {
  return Array.isArray(v) && v.every((x) => typeof x === 'string') ? (v as string[]) : null;
}

/** Index of the `--` that separates shield flags from the original command, or -1. */
function separatorIndex(args: string[]): number {
  const s = args.indexOf('shield');
  if (s === -1 || args[s + 1] !== '--server') return -1;
  let i = s + 1;
  while (i < args.length && args[i] !== undefined && args[i]!.startsWith('--') && args[i] !== '--') i += 2;
  return args[i] === '--' ? i : -1;
}

/** The `shield --server ... --url` form that wraps a remote server: the parsed flags, or null. */
function remoteFlags(args: string[]): Map<string, string[]> | null {
  const s = args.indexOf('shield');
  if (s === -1 || args[s + 1] !== '--server' || args.includes('--')) return null;
  const flags = new Map<string, string[]>();
  for (let i = s + 1; i < args.length; i += 2) {
    const k = args[i];
    const v = args[i + 1];
    if (k === undefined || !k.startsWith('--') || v === undefined) return null;
    flags.set(k, [...(flags.get(k) ?? []), v]);
  }
  return flags.has('--url') ? flags : null;
}

export function isWrapped(entry: McpServerEntry): boolean {
  const args = strArray(entry['args']);
  return args !== null && (separatorIndex(args) !== -1 || remoteFlags(args) !== null);
}

const HEADER_ENV_PREFIX = 'EXORCIST_REMOTE_HEADER_';

/**
 * A remote server (`url`) becomes a local `exorcist shield --url` command
 * (S-005). Header values move into the entry's `env` and are passed with
 * --header-env, so tokens never appear in the process list. Enough is kept in
 * the arguments for `unwrapConfig` to restore the entry exactly.
 */
function wrapRemote(name: string, entry: McpServerEntry, opts: WrapOptions): boolean {
  const url = entry['url'];
  if (typeof url !== 'string') return false;
  const rawHeaders = entry['headers'];
  if (rawHeaders !== undefined && (typeof rawHeaders !== 'object' || rawHeaders === null || Array.isArray(rawHeaders))) return false;
  const headers = Object.entries((rawHeaders ?? {}) as Record<string, unknown>);
  if (headers.some(([, v]) => typeof v !== 'string')) return false;
  const hadEnv = entry['env'] !== undefined;
  const env: Record<string, string> = { ...((entry['env'] as Record<string, string> | undefined) ?? {}) };
  const headerArgs: string[] = [];
  headers.forEach(([h, v], i) => {
    const variable = `${HEADER_ENV_PREFIX}${i + 1}`;
    env[variable] = v as string;
    headerArgs.push('--header-env', `${h}=${variable}`);
  });
  const type = entry['type'];
  // The original key order, so `unwrap` gives back the same JSON text.
  const keys = JSON.stringify(Object.keys(entry));
  entry['command'] = opts.bin;
  entry['args'] = [
    ...(opts.binArgs ?? []),
    'shield',
    '--server', name,
    ...(opts.configPath ? ['--config', opts.configPath] : []),
    ...(opts.dir ? ['--dir', opts.dir] : []),
    '--url', url,
    ...headerArgs,
    ...(typeof type === 'string' ? ['--remote-type', type] : []),
    ...(rawHeaders !== undefined ? ['--remote-headers', 'yes'] : []),
    ...(hadEnv ? [] : ['--remote-env', 'none']),
    '--remote-keys', keys,
  ];
  if (Object.keys(env).length > 0 || hadEnv) entry['env'] = env;
  delete entry['url'];
  delete entry['headers'];
  delete entry['type'];
  return true;
}

function unwrapRemote(entry: McpServerEntry, flags: Map<string, string[]>): void {
  const url = flags.get('--url')?.[0] ?? '';
  const env = { ...((entry['env'] as Record<string, string> | undefined) ?? {}) };
  const headers: Record<string, string> = {};
  for (const pair of flags.get('--header-env') ?? []) {
    const i = pair.indexOf('=');
    const name = pair.slice(0, i);
    const variable = pair.slice(i + 1);
    headers[name] = env[variable] ?? '';
    if (variable.startsWith(HEADER_ENV_PREFIX)) delete env[variable];
  }
  delete entry['command'];
  delete entry['args'];
  const type = flags.get('--remote-type')?.[0];
  if (type !== undefined) entry['type'] = type;
  entry['url'] = url;
  if (flags.has('--remote-headers')) entry['headers'] = headers;
  if (flags.get('--remote-env')?.[0] === 'none') delete entry['env'];
  else entry['env'] = env;
  // Put the keys back in their original order.
  let order: unknown;
  try { order = JSON.parse(flags.get('--remote-keys')?.[0] ?? '[]'); } catch { order = []; }
  if (Array.isArray(order)) {
    const copy: Record<string, unknown> = { ...entry };
    for (const k of Object.keys(entry)) delete entry[k];
    for (const k of order) if (typeof k === 'string' && k in copy) entry[k] = copy[k];
    for (const [k, v] of Object.entries(copy)) if (!(k in entry)) entry[k] = v;
  }
}

/** Run every server in the config through the shield: stdio servers directly, remote ones through --url. */
export function wrapConfig(config: McpConfig, opts: WrapOptions): { config: McpConfig; wrapped: string[] } {
  const out = structuredClone(config);
  const wrapped: string[] = [];
  for (const [name, entry] of Object.entries(out.mcpServers ?? {})) {
    if (typeof entry['command'] !== 'string' && !isWrapped(entry) && wrapRemote(name, entry, opts)) {
      wrapped.push(name);
      continue;
    }
    const command = entry['command'];
    if (typeof command !== 'string' || isWrapped(entry)) continue;
    const args = strArray(entry['args']) ?? [];
    entry['command'] = opts.bin;
    entry['args'] = [
      ...(opts.binArgs ?? []),
      'shield',
      '--server', name,
      ...(opts.configPath ? ['--config', opts.configPath] : []),
      ...(opts.dir ? ['--dir', opts.dir] : []),
      '--',
      command,
      ...args,
    ];
    wrapped.push(name);
  }
  return { config: out, wrapped };
}

/** Exactly undo `wrapConfig`. Entries that are not wrapped are left alone. */
export function unwrapConfig(config: McpConfig): { config: McpConfig; unwrapped: string[] } {
  const out = structuredClone(config);
  const unwrapped: string[] = [];
  for (const [name, entry] of Object.entries(out.mcpServers ?? {})) {
    const args = strArray(entry['args']);
    if (!args) continue;
    const remote = remoteFlags(args);
    if (remote) {
      unwrapRemote(entry, remote);
      unwrapped.push(name);
      continue;
    }
    const sep = separatorIndex(args);
    const original = args[sep + 1];
    if (sep === -1 || original === undefined) continue;
    entry['command'] = original;
    const rest = args.slice(sep + 2);
    // An entry that had no arguments (or an empty list) goes back without an
    // `args` key; the two mean the same thing to an MCP client.
    if (rest.length > 0) entry['args'] = rest;
    else delete entry['args'];
    unwrapped.push(name);
  }
  return { config: out, unwrapped };
}
