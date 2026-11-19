import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { unwrapConfig, wrapConfig } from '@exorcist-98/shield';
import type { McpConfig } from '@exorcist-98/shield';
import { DEFAULT_DIR, parse, str, strs } from '../util.js';
import type { Io } from '../util.js';

export const WRAP_HELP = `Usage: exorcist wrap <mcp.json> [options]
       exorcist unwrap <mcp.json>

wrap   Run every local MCP server in the file through the shield.
unwrap Put the original commands back, exactly.

Options (wrap):
  --bin <command>       Command that runs the shield (default: exorcist)
  --bin-arg <arg>       Argument before "shield" (repeatable), e.g. --bin npx --bin-arg -y --bin-arg exorcist@0.1.0
  --dir <folder>        State folder (default: ${resolve(DEFAULT_DIR)})
  --dry-run             Show the result without writing the file
`;

function readConfig(path: string, io: Io): McpConfig | null {
  if (!existsSync(path)) { io.err(`File not found: ${path}`); return null; }
  try {
    const json = JSON.parse(readFileSync(path, 'utf8')) as unknown;
    if (!json || typeof json !== 'object' || Array.isArray(json)) throw new Error('not an object');
    return json as McpConfig;
  } catch {
    io.err(`${path} is not a valid JSON object.`);
    return null;
  }
}

export async function wrapCommand(argv: string[], io: Io, mode: 'wrap' | 'unwrap'): Promise<number> {
  const p = parse(argv, {
    bin: { type: 'string' }, 'bin-arg': { type: 'string', multiple: true }, dir: { type: 'string' },
    'dry-run': { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${WRAP_HELP}`); return 2; }
  if (p.values['help']) { io.out(WRAP_HELP); return 0; }
  const file = p.positionals[0];
  if (!file || p.positionals.length > 1) { io.err(`Give exactly one MCP config file.\n\n${WRAP_HELP}`); return 2; }

  const path = resolve(file);
  const cfg = readConfig(path, io);
  if (!cfg) return 2;

  let next: McpConfig;
  let names: string[];
  if (mode === 'wrap') {
    const r = wrapConfig(cfg, {
      bin: str(p.values['bin']) ?? 'exorcist',
      binArgs: strs(p.values['bin-arg']),
      dir: resolve(str(p.values['dir']) ?? DEFAULT_DIR),
      configPath: path,
    });
    next = r.config;
    names = r.wrapped;
  } else {
    const r = unwrapConfig(cfg);
    next = r.config;
    names = r.unwrapped;
  }

  if (p.values['dry-run']) io.out(JSON.stringify(next, null, 2));
  else if (names.length > 0) writeFileSync(path, `${JSON.stringify(next, null, 2)}\n`, 'utf8');
  io.err(names.length === 0 ? `Nothing to ${mode}.` : `${mode === 'wrap' ? 'Wrapped' : 'Unwrapped'}: ${names.join(', ')}.`);
  return 0;
}
