import { resolve } from 'node:path';
import { maskToken } from '@exorcist-98/core';
import { loadCanaries, plantCanaries, removeCanaries } from '@exorcist-98/shield';
import { DEFAULT_DIR, parse, stateDir, str } from '../util.js';
import type { Io } from '../util.js';

export const CANARY_HELP = `Usage: exorcist canary plant [dir]    Plant canary traps in a project (3 by default)
       exorcist canary --list [dir]   Show the planted traps
       exorcist canary --remove [dir] Remove the trap files and their records

Options:
  --count <n>   How many traps to plant, 1 to 3 (default 3)
  --dir <path>  The Shield's state folder (default: ${DEFAULT_DIR})
  -h, --help    Show this help

Canary traps are harmless, unique tokens (x98c_ + 24 random characters)
planted in files an attacker would want your AI to read: a fake .env, notes
that look private, an internal config. No honest task ever sends one
anywhere. If one turns up in an MCP tool call, the Real-Time Shield blocks the
call in every mode and raises a critical alert (EX-022). "exorcist scan" and
the pre-commit hook report a token copied out of its trap.

The traps go to <dir>/.exorcist/canary/ and the records to
<dir>/.exorcist/canaries.json, where the Shield reads them at start. Restart
running Shields after planting. Tokens are printed masked; keep the trap
files out of shared commits if you do not want others to see them.
`;

/** Plant, list or remove canary traps in a project. */
export async function canaryCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, {
    help:   { type: 'boolean', short: 'h' },
    list:   { type: 'boolean' },
    remove: { type: 'boolean' },
    count:  { type: 'string' },
    dir:    { type: 'string' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${CANARY_HELP}`); return 2; }
  if (p.values['help']) { io.out(CANARY_HELP); return 0; }

  const positionals = [...p.positionals];
  const sub = positionals[0] === 'plant' || positionals[0] === 'list' || positionals[0] === 'remove' ? positionals.shift() : undefined;
  if (positionals.length > 1) { io.err(`Too many arguments.\n\n${CANARY_HELP}`); return 2; }
  const dir = resolve(positionals[0] ?? '.');
  const wantList = p.values['list'] === true || sub === 'list';
  const wantRemove = p.values['remove'] === true || sub === 'remove';
  const wantPlant = sub === 'plant';
  if ([wantList, wantRemove, wantPlant].filter(Boolean).length !== 1) {
    io.err(`Choose one of: plant, --list or --remove.\n\n${CANARY_HELP}`);
    return 2;
  }
  // The Shield's state folder only matters when it is set explicitly (--dir
  // or EXORCIST_DIR): by default it is <dir>/.exorcist, where the records go.
  const explicitDir = str(p.values['dir']);
  const state = explicitDir !== undefined || process.env['EXORCIST_DIR'] ? stateDir(explicitDir) : undefined;

  if (wantList) return list(io, dir);
  if (wantRemove) return remove(io, dir, state);

  const countRaw = str(p.values['count']);
  const count = countRaw === undefined ? 3 : Number(countRaw);
  return plant(io, dir, state, count);
}

function list(io: Io, dir: string): number {
  const r = loadCanaries(dir);
  if (!r.ok) { io.err(`Exorcist 98: ${r.error}`); return 2; }
  if (r.canaries.length === 0) {
    io.out(`No canary traps in ${dir}. Plant some with: exorcist canary plant ${dir}`);
    return 0;
  }
  io.out(`Canary traps in ${dir} (${r.canaries.length}):`);
  for (const c of r.canaries) io.out(`  ${c.file}  ${maskToken(c.token)}  planted ${c.created}`);
  io.out('The Real-Time Shield blocks any tool call that carries one of these tokens (EX-022).');
  return 0;
}

function plant(io: Io, dir: string, state: string | undefined, count: number): number {
  const r = plantCanaries(dir, { count, ...(state ? { stateDir: state } : {}) });
  if (!r.ok) { io.err(`Exorcist 98: ${r.error}`); return 2; }
  io.out(`Planted ${r.records.length} canary trap${r.records.length === 1 ? '' : 's'} in ${dir}:`);
  for (const c of r.records) io.out(`  ${c.file}  ${maskToken(c.token)}`);
  io.out(`Records: ${r.recordsFile}`);
  if (r.policyUpdated) io.out(`The Shield's policy (${r.policyUpdated}) now points at these records.`);
  io.out('The Real-Time Shield blocks any tool call that carries one of these tokens, in every mode (EX-022). Restart running Shields to load them.');
  return 0;
}

function remove(io: Io, dir: string, state: string | undefined): number {
  const r = removeCanaries(dir, state ? { stateDir: state } : {});
  if (!r.ok) { io.err(`Exorcist 98: ${r.error}`); return 2; }
  if (r.removed.length === 0) {
    io.out(`No canary traps to remove in ${dir}.`);
    return 0;
  }
  io.out(`Removed ${r.removed.length} file${r.removed.length === 1 ? '' : 's'}:`);
  for (const f of r.removed) io.out(`  ${f}`);
  return 0;
}
