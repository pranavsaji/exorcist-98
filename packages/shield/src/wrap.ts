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

export function isWrapped(entry: McpServerEntry): boolean {
  const args = strArray(entry['args']);
  return args !== null && separatorIndex(args) !== -1;
}

/** Run every stdio server in the config through the shield. Remote servers are left alone. */
export function wrapConfig(config: McpConfig, opts: WrapOptions): { config: McpConfig; wrapped: string[] } {
  const out = structuredClone(config);
  const wrapped: string[] = [];
  for (const [name, entry] of Object.entries(out.mcpServers ?? {})) {
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
