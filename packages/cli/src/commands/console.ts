import { execFile } from 'node:child_process';
import { loadCapabilityRules } from '@exorcist-98/core';
import type { CapabilityRule } from '@exorcist-98/core';
import { startConsole } from '../console/server.js';
import type { ConsoleServer } from '../console/server.js';
import { DEFAULT_DIR, findDefinitionsDir, parse, stateDir, str } from '../util.js';
import type { Io } from '../util.js';

export const CONSOLE_HELP = `Usage: exorcist console [--dir <folder>] [--port <n>] [--no-open]

Open the live Shield console in your browser: every tool call the Real-Time
Shield allowed, held or blocked (and why), the servers it protects, its alerts,
and what the Session Guard (EX-027) has seen in each agent session.

It reads the state folder's event log (events.jsonl) and session records. It
is read-only: nothing on the page can approve or release anything. A held
call is answered in your agent's approval prompt. A held session is released
in the system prompt (Touch ID or your login password) when the Shield uses
sessionRelease "os" (macOS only), and otherwise with "exorcist approve
session <key>" in your own terminal.

The page is served on 127.0.0.1 only, at a URL with a secret token. Stop with
Ctrl+C.

Options:
  --dir <folder>   State folder the Shields use (default: ${DEFAULT_DIR})
  --port <n>       Port to listen on (default: a random free port)
  --no-open        Print the URL instead of opening a browser
`;

/** Open a URL in the default browser, without a shell. */
export function openCommand(platform: NodeJS.Platform, url: string): { file: string; args: string[] } | null {
  if (!/^http:\/\/127\.0\.0\.1:\d+\/[A-Za-z0-9_-]+\/$/.test(url)) return null;
  if (platform === 'darwin') return { file: 'open', args: [url] };
  if (platform === 'win32') return { file: 'rundll32', args: ['url.dll,FileProtocolHandler', url] };
  return { file: 'xdg-open', args: [url] };
}

export type ConsoleDeps = {
  /** Resolves when the console should stop (Ctrl+C by default). */
  until?: (server: ConsoleServer) => Promise<void>;
  open?: (url: string) => void;
};

const untilSignal = (): Promise<void> =>
  new Promise((resolve) => {
    const stop = (): void => { process.off('SIGINT', stop); process.off('SIGTERM', stop); resolve(); };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  });

export async function consoleCommand(argv: string[], io: Io, deps: ConsoleDeps = {}): Promise<number> {
  const p = parse(argv, { dir: { type: 'string' }, port: { type: 'string' }, 'no-open': { type: 'boolean' }, help: { type: 'boolean', short: 'h' } });
  if (!p.ok) { io.err(`${p.error}\n\n${CONSOLE_HELP}`); return 2; }
  if (p.values['help']) { io.out(CONSOLE_HELP); return 0; }
  const portText = str(p.values['port']);
  const port = portText === undefined ? 0 : Number(portText);
  if (!Number.isInteger(port) || port < 0 || port > 65535) { io.err(`"${portText}" is not a port number.`); return 2; }

  const dir = stateDir(str(p.values['dir']));
  // Capability labels make the Session Guard's facts read better; optional.
  let rules: CapabilityRule[] = [];
  const defs = findDefinitionsDir();
  if (defs) {
    const r = await loadCapabilityRules(defs);
    if (r.ok) rules = r.rules;
  }

  let server: ConsoleServer;
  try {
    server = await startConsole({ dir, port, rules });
  } catch (err) {
    io.err(`Could not start the console: ${String((err as Error).message ?? err)}`);
    return 1;
  }
  io.out(`Exorcist 98 Shield console (read-only) for ${dir}`);
  io.out(`  ${server.url}`);
  io.out('Only this machine can open it, and only with the token in the URL. Press Ctrl+C to stop.');
  io.out('Read-only. A held session is released in the system prompt when the Shield uses OS release (macOS), otherwise with "exorcist approve session <key>" in your own terminal.');
  if (p.values['no-open'] !== true) {
    const opener = deps.open ?? ((url: string) => {
      const c = openCommand(process.platform, url);
      if (c) execFile(c.file, c.args, () => { /* the URL is printed above */ });
    });
    opener(server.url);
  }
  await (deps.until ?? untilSignal)(server);
  await server.close();
  return 0;
}
