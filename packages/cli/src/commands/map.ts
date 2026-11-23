import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { mapRepo } from '@exorcist-98/core';
import type { Capability, ConfigMap, HauntedMap, SignatureFinding } from '@exorcist-98/core';
import { findDefinitionsDir, parse, str } from '../util.js';
import type { Io } from '../util.js';

export const MAP_HELP = `Usage: exorcist map [dir] [options]

The Haunted House Map: for every MCP config in a folder (default: the current
one), which servers sit in each room of the "lethal trifecta":

  Vault of Secrets   private data (files outside the project, email,
                     databases, password managers, cloud consoles)
  Open Door          untrusted input (web pages, search, issues, chat, inbox)
  Escape Tunnel      a way out (web requests to any host, sending messages,
                     creating issues or gists, uploads)

When one config fills all three rooms, one prompt injection can steal what
the agent can read (EX-023). Auto-approved tools on any of them make it critical.

Options:
  --format <text|json>   Output format (default: text)
  --definitions <dir>    Folder with capabilities.yaml and the virus definitions

Exit code: 1 when a config forms the trifecta, 0 when none does, 2 on bad usage.
`;

export const ROOMS: ReadonlyArray<{ cap: Capability; room: string; power: string }> = [
  { cap: 'private-data',    room: 'Vault of Secrets', power: 'private data' },
  { cap: 'untrusted-input', room: 'Open Door',        power: 'untrusted input' },
  { cap: 'exfiltration',    room: 'Escape Tunnel',    power: 'a way out' },
];

function renderConfig(c: ConfigMap, finding: SignatureFinding | undefined): string[] {
  const lines = [c.file];
  if (c.ghosts.length === 0) return [...lines, '  (no enabled servers)', ''];
  const width = Math.max(...ROOMS.map((r) => `${r.room} (${r.power})`.length), 'Quiet ghosts (no risky powers)'.length) + 2;
  for (const r of ROOMS) {
    const names = c.legs[r.cap];
    lines.push(`  ${`${r.room} (${r.power})`.padEnd(width)}${names.length > 0 ? names.join(', ') : '(empty)'}`);
  }
  const quiet = c.ghosts.filter((g) => g.capabilities.length === 0).map((g) => g.name);
  if (quiet.length > 0) lines.push(`  ${'Quiet ghosts (no risky powers)'.padEnd(width)}${quiet.join(', ')}`);
  if (c.ghosts.some((g) => g.reasons.length > 0)) lines.push('  Why:');
  for (const g of c.ghosts) {
    if (g.reasons.length === 0) continue;
    const auto = g.autoApproved ? ' [auto-approved]' : '';
    const kind = g.kind === 'ability' ? ' (built-in)' : '';
    lines.push(`    ${g.name}${kind}${auto}: ${g.reasons.map((r) => `${r.label} (${r.ruleId}: ${r.evidence})`).join('; ')}`);
  }
  if (c.trifecta) {
    const sev = (c.severity ?? 'high').toUpperCase();
    lines.push(`  ${sev}  LETHAL TRIFECTA (EX-023): all three rooms are haunted${finding ? ` (${finding.file}:${finding.line})` : ''}.`);
    lines.push('        One poisoned page, issue or message could make the agent read your secrets and send them out.');
  } else {
    const empty = ROOMS.filter((r) => c.legs[r.cap].length === 0).map((r) => r.room);
    const list = empty.length === 1 ? empty[0] : `${empty.slice(0, -1).join(', ')} and ${empty[empty.length - 1]}`;
    lines.push(`  OK  No trifecta: the ${list} ${empty.length === 1 ? 'room is' : 'rooms are'} empty.`);
  }
  return [...lines, ''];
}

/** The map as plain text, one block per config. */
export function renderMap(map: HauntedMap, findings: readonly SignatureFinding[]): string {
  if (map.configs.length === 0) return 'No MCP configs found, so there is no house to map.\n';
  const out = ['The Haunted House Map', ''];
  for (const c of map.configs) out.push(...renderConfig(c, findings.find((f) => f.file === c.file)));
  const n = map.configs.filter((c) => c.trifecta).length;
  out.push(n === 0
    ? `${map.configs.length} MCP config${map.configs.length === 1 ? '' : 's'} mapped; none forms the lethal trifecta.`
    : `${n} of ${map.configs.length} MCP config${map.configs.length === 1 ? '' : 's'} form${n === 1 ? 's' : ''} the lethal trifecta.`);
  return `${out.join('\n')}\n`;
}

export async function mapCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, { format: { type: 'string' }, definitions: { type: 'string' }, help: { type: 'boolean', short: 'h' } });
  if (!p.ok) { io.err(`${p.error}\n\n${MAP_HELP}`); return 2; }
  if (p.values['help']) { io.out(MAP_HELP); return 0; }
  if (p.positionals.length > 1) { io.err(`Give at most one folder.\n\n${MAP_HELP}`); return 2; }
  const format = str(p.values['format']) ?? 'text';
  if (format !== 'text' && format !== 'json') { io.err(`Unknown format "${format}". Use text or json.`); return 2; }

  const target = p.positionals[0] ?? '.';
  const root = resolve(target);
  if (!existsSync(root) || !statSync(root).isDirectory()) { io.err(`Folder not found: ${target}`); return 2; }
  const defsDir = findDefinitionsDir(str(p.values['definitions']));
  if (!defsDir) { io.err('Could not find the virus definitions. Pass --definitions <dir> or set EXORCIST_DEFINITIONS.'); return 2; }

  const r = await mapRepo(root, { definitionsDir: defsDir });
  if (!r.ok) { io.err(`Could not map ${target}: ${r.error}`); return 2; }
  if (format === 'json') io.out(JSON.stringify({ version: '1', map: r.map, findings: r.findings }, null, 2));
  else io.out(renderMap(r.map, r.findings));
  return r.map.configs.some((c) => c.trifecta) ? 1 : 0;
}
