import { resolve } from 'node:path';
import { loadCanaries, plantCanaries, removeCanaries } from '@exorcist-98/shield';
import { parse } from '../util.js';
import type { Io } from '../util.js';

export const CANARY_HELP = `Usage: exorcist canary plant [dir]   Plant canary traps (3 by default)
       exorcist canary [dir] --list    Show the planted traps
       exorcist canary [dir] --remove  Remove the trap files and records

Canary traps are harmless, unique tokens planted in files an attacker would
want your AI to read (a fake .env, private-looking notes, an internal config).
No honest workflow ever sends one anywhere, so if one turns up in an MCP tool
call the Real-Time Shield blocks the call (EX-022), and a scan reports a token
copied out of its trap.

The traps go to <dir>/.exorcist/canary/ and the records to
<dir>/.exorcist/canaries.json, which the Shield reads automatically.
`;

/** Plant, list or remove canary traps in a project. */
export async function canaryCommand(argv: string[], io: Io): Promise<number> {
  // `--list` and `--remove` work as flags on the canary command itself, so
  // they are pulled out before parseArgs (which treats them as unknown
  // options next to a positional subcommand).
  const flags = new Set<string>();
  const rest: string[] = [];
  for (const a of argv) {
    if (a === '--list' || a === '--remove') flags.add(a);
    else rest.push(a);
  }
  const p = parse(rest, { help: { type: 'boolean', short: 'h' } });
  if (!p.ok) { io.err(`${p.error}\n\n${CANARY_HELP}`); return 2; }
  if (p.values['help']) { io.out(CANARY_HELP); return 0; }

  const [sub, maybeDir] = p.positionals;
  const dir = resolve(sub === 'plant' || sub === 'list' || sub === 'remove' ? (maybeDir ?? '.') : (sub ?? '.'));

  if (flags.has('--list')) return list(io, dir);
  if (flags.has('--remove')) return remove(io, dir);
  if (sub === 'list') return list(io, dir);
  if (sub === 'remove') return remove(io, dir);
  if (sub === undefined || sub === 'plant') return plant(io, dir);

  io.err(`Unknown subcommand "${sub}".\n\n${CANARY_HELP}`);
  return 2;
}

function list(io: Io, dir: string): number {
  const r = loadCanaries(dir);
  if (!r.ok) { io.err(`Exorcist 98: ${r.error}`); return 2; }
  if (r.canaries.length === 0) {
    io.out(`No canary traps in ${dir}. Plant some with: exorcist canary plant ${dir}`);
    return 0;
  }
  io.out(`Canary traps in ${dir} (${r.canaries.length}):`);
  for (const c of r.canaries) {
    io.out(`  ${c.file}  ${c.token.slice(0, 5)}${'*'.repeat(24)}  planted ${c.created}`);
  }
  io.out('The Shield blocks any tool call that contains one (EX-022).');
  return 0;
}

function plant(io: Io, dir: string): number {
  const r = plantCanaries(dir);
  if (!r.ok) { io.err(`Exorcist 98: ${r.error}`); return 2; }
  const fresh = r.records.slice(-3);
  io.out(`Planted ${fresh.length} canary trap${fresh.length === 1 ? '' : 's'} in ${r.dir}:`);
  for (const c of fresh) io.out(`  ${c.file}  ${c.token.slice(0, 5)}${'*'.repeat(24)}`);
  io.out('Records: .exorcist/canaries.json (the Shield reads them at start).');
  io.out('The Real-Time Shield now blocks any tool call that contains one (EX-022).');
  return 0;
}

function remove(io: Io, dir: string): number {
  const r = removeCanaries(dir);
  if (!r.ok) { io.err(`Exorcist 98: ${r.error}`); return 2; }
  if (r.removed.length === 0) {
    io.out(`No canary traps to remove in ${dir}.`);
    return 0;
  }
  io.out(`Removed ${r.removed.length} file${r.removed.length === 1 ? '' : 's'}:`);
  for (const f of r.removed) io.out(`  ${f}`);
  return 0;
}
