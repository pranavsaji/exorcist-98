import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { alertsPath, approveHost, approveServer, approveTool, loadState, saveState, statePath } from '@exorcist-98/shield';
import { DEFAULT_DIR, stateDir, parse, str } from '../util.js';
import type { Io } from '../util.js';

export const APPROVE_HELP = `Usage: exorcist approve tool <server> <tool> [--dir <folder>]
       exorcist approve host <server> <host> [--dir <folder>]
       exorcist approve server <server> [--dir <folder>]
       exorcist alerts [--dir <folder>] [--last <n>]

approve tool   Accept the changed version of a tool the shield hid (re-pins it).
approve host   Let a server send data to a host (a name like api.example.com, or *.example.com).
approve server Accept a changed program behind a server (new code or arguments) and pin it.
alerts         Show recent shield alerts.

The running shield picks the change up on the next request. Your AI client may
need to refresh its tool list (reconnect the MCP server) to see a restored tool.
`;

export async function approveCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, { dir: { type: 'string' }, help: { type: 'boolean', short: 'h' } });
  if (!p.ok) { io.err(`${p.error}\n\n${APPROVE_HELP}`); return 2; }
  if (p.values['help']) { io.out(APPROVE_HELP); return 0; }
  const [kind, server, name] = p.positionals;
  const known = kind === 'server' ? Boolean(server) : (kind === 'tool' || kind === 'host') && Boolean(server && name);
  if (!kind || !server || !known) {
    io.err(`Say what to approve.\n\n${APPROVE_HELP}`);
    return 2;
  }
  const path = statePath(stateDir(str(p.values['dir'])));
  const loaded = loadState(path);
  if (!loaded.ok) { io.err(loaded.error); return 1; }
  const r = kind === 'server' ? approveServer(loaded.state, server)
    : kind === 'tool' ? approveTool(loaded.state, server, name as string) : approveHost(loaded.state, server, name as string);
  if (!r.ok) { io.err(r.error); return 1; }
  saveState(path, loaded.state);
  io.out(r.message);
  return 0;
}

export async function alertsCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, { dir: { type: 'string' }, last: { type: 'string' }, help: { type: 'boolean', short: 'h' } });
  if (!p.ok) { io.err(p.error); return 2; }
  const file = alertsPath(stateDir(str(p.values['dir'])));
  if (!existsSync(file)) { io.out('No alerts.'); return 0; }
  const n = Math.max(1, Number.parseInt(str(p.values['last']) ?? '20', 10) || 20);
  const lines = readFileSync(file, 'utf8').split('\n').filter(Boolean).slice(-n);
  for (const l of lines) {
    try {
      const a = JSON.parse(l) as { time: string; severity: string; ruleId: string; server: string; tool?: string; message: string };
      io.out(`${a.time}  ${a.severity.toUpperCase().padEnd(8)} ${a.ruleId}  ${a.server}${a.tool ? `/${a.tool}` : ''}: ${a.message}`);
    } catch { /* skip a damaged line */ }
  }
  return 0;
}
