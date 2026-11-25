import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { alertsPath, loadPolicy, macOsAuth, policyPath, resolveRelease, approveHost, approveServer, approveTool, grantSession, liveSessions, sessionSummary, loadState, saveState, statePath } from '@exorcist-98/shield';
import { DEFAULT_DIR, stateDir, parse, str } from '../util.js';
import type { Io } from '../util.js';
import { personConfirms, processTerminal } from './on-access.js';
import type { Terminal } from './on-access.js';
import type { OsAuth } from '@exorcist-98/shield';

export const APPROVE_HELP = `Usage: exorcist approve tool <server> <tool> [--dir <folder>]
       exorcist approve host <server> <host> [--dir <folder>]
       exorcist approve server <server> [--dir <folder>]
       exorcist approve session <key> [--dir <folder>]
       exorcist alerts [--dir <folder>] [--last <n>]

approve tool    Accept the changed version of a tool the shield hid (re-pins it).
approve host    Let a server send data to a host (a name like api.example.com, or *.example.com).
approve server  Accept a changed program behind a server (new code or arguments) and pin it.
approve session Let an agent session the Session Guard (EX-027) is holding send data out again.
                The key is in the alert. It asks again after new untrusted text or private data.
                On macOS the Shield releases it itself, in a system prompt (Touch ID or your
                login password), so this command writes nothing then. If the policy sets
                "sessionRelease": "terminal", or the system prompt is unavailable, a person
                runs it in an interactive terminal, then clicks a native dialog (macOS).
                Elsewhere it falls back to a typed one-time code, which an agent driving a
                real terminal could read: weaker.
alerts          Show recent shield alerts.

The running shield picks the change up on the next request. Your AI client may
need to refresh its tool list (reconnect the MCP server) to see a restored tool.
`;

export async function approveCommand(argv: string[], io: Io, term: Terminal = processTerminal(), osAuth: OsAuth = macOsAuth()): Promise<number> {
  const p = parse(argv, { dir: { type: 'string' }, help: { type: 'boolean', short: 'h' } });
  if (!p.ok) { io.err(`${p.error}\n\n${APPROVE_HELP}`); return 2; }
  if (p.values['help']) { io.out(APPROVE_HELP); return 0; }
  const [kind, server, name] = p.positionals;
  if (kind === 'session') {
    const dir = stateDir(str(p.values['dir']));
    if (!server) {
      const live = liveSessions(dir);
      io.err(live.length > 0
        ? `Say which session. Sessions with facts in ${dir}: ${live.join(', ')}\n`
        : `There is no live session in ${dir}.\n`);
      return 2;
    }
    // With OS release the Shield asks the system itself. A file written here
    // could be forged by any program, so nothing is written.
    const policy = loadPolicy(policyPath(dir));
    if (!policy.ok) { io.err(policy.error); return 1; }
    const release = await resolveRelease(policy.policy.sessionRelease, osAuth);
    if (release.mode === 'os') {
      io.out("This session is released in the system prompt (Touch ID or your login password) that the Shield shows when the agent's call is held. Nothing was written here.");
      return 1;
    }
    // The agent the guard is holding has a shell tool too, and the refusal it
    // got names this command, so only a person may complete it.
    if (!term.interactive) {
      io.err('exorcist approve session only runs in an interactive terminal: the user must run it themselves. Nothing was released.');
      return 1;
    }
    const asOf = new Date();
    const what = sessionSummary(dir, server, asOf);
    for (const w of what) io.out(`  - ${w}`);
    const msg = `Let this AI agent session send data out again?\n\nSession ${server}\n${what.map((w) => `- ${w}`).join('\n')}\n\nOnly release it if you asked for what it is trying to send.`;
    if (!term.dialog || process.platform !== 'darwin') {
      io.err('Note: there is no native dialog here, so this uses a typed code. An agent that drives a real terminal could read it; only type it yourself.');
    }
    if (!(await personConfirms(term, io, msg))) return 1;
    const g = grantSession(dir, server, new Date(), asOf);
    if (!g.ok) { io.err(g.error); return 1; }
    io.out(g.message);
    return 0;
  }
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
