import { resolve } from 'node:path';
import { runProxy } from '@exorcist-98/shield';
import { DEFAULT_DIR, findDefinitionsDir, parse, str } from '../util.js';
import type { Io } from '../util.js';

export const SHIELD_HELP = `Usage: exorcist shield --server <name> [options] -- <command> [args...]

Run one MCP server behind the Real-Time Shield. Put this in your MCP config
(or use "exorcist wrap" to do it for you).

Options:
  --server <name>        Name of the server (used for pins and alerts)
  --config <file>        MCP config that holds the server, so it can be quarantined
  --dir <folder>         State folder (default: ${DEFAULT_DIR})
  --definitions <dir>    Folder of virus definitions
`;

export async function shieldCommand(argv: string[], io: Io): Promise<number> {
  const sep = argv.indexOf('--');
  const flags = sep === -1 ? argv : argv.slice(0, sep);
  const rest = sep === -1 ? [] : argv.slice(sep + 1);

  const p = parse(flags, {
    server: { type: 'string' }, config: { type: 'string' }, dir: { type: 'string' },
    definitions: { type: 'string' }, help: { type: 'boolean', short: 'h' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${SHIELD_HELP}`); return 2; }
  if (p.values['help']) { io.out(SHIELD_HELP); return 0; }

  const server = str(p.values['server']);
  const command = rest[0];
  if (!server || !command) { io.err(`Give --server and the server command after "--".\n\n${SHIELD_HELP}`); return 2; }

  const defs = findDefinitionsDir(str(p.values['definitions']));
  if (!defs) { io.err('Could not find the virus definitions. Pass --definitions <dir> or set EXORCIST_DEFINITIONS.'); return 78; }

  const config = str(p.values['config']);
  return await runProxy({
    server,
    command,
    args: rest.slice(1),
    dir: resolve(str(p.values['dir']) ?? DEFAULT_DIR),
    definitionsDir: defs,
    ...(config ? { configPath: resolve(config) } : {}),
  });
}
