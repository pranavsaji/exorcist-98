import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { addAllowedRead, decideRead, loadDefinitions, readAllowedReads, realPath, sha256File, shownName } from '@exorcist-98/core';
import type { VirusDefinition } from '@exorcist-98/core';
import { findDefinitionsDir, parse } from '../util.js';
import type { Io } from '../util.js';

export const ON_ACCESS_HELP = `Usage: exorcist on-access   (Kiro hook helper)

Reads a Kiro PreToolUse hook event from stdin and decides whether the agent
may read the file the tool names. Exit code 2 blocks the read and the reason
is written to stderr. Used by the on-access hook written by "exorcist init";
run it yourself only to try it out.

Exit codes: 0 allow the read, 2 block it. Anything it cannot read or
understand is allowed: the hook must never stop the agent from working.
`;

export const ALLOW_READ_HELP = `Usage: exorcist allow-read <file>

Allow one file for on-access scanning: its real path and current SHA-256 are
recorded, and the next read of exactly these bytes at that path passes
without a scan. Edit the file and it is checked again.

The list is kept outside the project, per user:
  $EXORCIST_DIR/allowed-reads/<project id>.json  (default ~/.exorcist/...)
A list inside the project folder is never used: the project could plant it.

Only a person can allow a file: the command runs only in an interactive
terminal and asks you to type the first 6 characters of the file's SHA-256,
which it shows there. An agent's shell tool cannot approve its own read.
`;

/** The terminal allow-read talks to. Production uses the process's own (see processTerminal). */
export type Terminal = {
  /** True only when both stdin and stdout are a TTY. */
  interactive: boolean;
  /** Show `prompt` on the terminal and read one line typed there. */
  ask: (prompt: string) => Promise<string>;
};

export const processTerminal = (): Terminal => ({
  interactive: process.stdin.isTTY === true && process.stdout.isTTY === true,
  ask: (prompt) => new Promise((done) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl.question(prompt, (answer) => { rl.close(); done(answer); });
  }),
});

/** The confirmation allow-read asks for: the first 6 hex characters of the file's SHA-256. */
export const confirmationCode = (sha256: string): string => sha256.slice(0, 6);
export const confirms = (answer: string, sha256: string): boolean =>
  answer.trim().toLowerCase() === confirmationCode(sha256);

/** The event's `cwd`, so the state folder is the project the agent works in, not the hook's own cwd. */
function eventCwd(stdin: string): string {
  try {
    const parsed = JSON.parse(stdin) as { cwd?: unknown };
    if (typeof parsed?.cwd === 'string' && parsed.cwd) return parsed.cwd;
  } catch { /* not JSON: fall back to the process cwd */ }
  return process.cwd();
}

/**
 * The on-access hook helper. Fail-open everywhere (REQ-01.6): no definitions,
 * an unreadable state folder or a broken event all allow the read.
 */
export async function onAccessCommand(stdin: string, io: Io): Promise<number> {
  const cwd = eventCwd(stdin);
  let defs: VirusDefinition[] = [];
  const defsDir = findDefinitionsDir();
  if (defsDir) {
    try {
      defs = await loadDefinitions(defsDir);
    } catch (err) {
      io.err(`Exorcist 98 on-access: the virus definitions could not be loaded, so the read was allowed. ${String(err).split('\n')[0]}`);
      return 0;
    }
  } else {
    io.err('Exorcist 98 on-access: no virus definitions were found, so the read was allowed.');
    return 0;
  }

  let allowed: ReadonlySet<string> = new Set();
  try {
    allowed = readAllowedReads(cwd);
  } catch {
    allowed = new Set();
  }

  const decision = decideRead(stdin, defs, { cwd, allowed });
  if (decision.message) io.err(decision.message);
  return decision.exitCode;
}

export async function allowReadCommand(argv: string[], io: Io, term: Terminal = processTerminal()): Promise<number> {
  const p = parse(argv, { help: { type: 'boolean', short: 'h' } });
  if (!p.ok) { io.err(`${p.error}\n\n${ALLOW_READ_HELP}`); return 2; }
  if (p.values['help']) { io.out(ALLOW_READ_HELP); return 0; }
  const target = p.positionals[0];
  if (!target || p.positionals.length > 1) { io.err(`Give exactly one file to allow.\n\n${ALLOW_READ_HELP}`); return 2; }
  // Before anything else: an agent's shell tool or a script never gets here.
  if (!term.interactive) {
    io.err('exorcist allow-read only runs in an interactive terminal: the user must review the file and run it themselves. Nothing was allowed.');
    return 1;
  }
  const file = resolve(target);
  if (!existsSync(file) || !statSync(file).isFile()) { io.err(`Not a readable file: ${shownName(target)}`); return 1; }
  const hash = sha256File(file);
  if (hash === null) { io.err(`Cannot read ${shownName(target)}.`); return 1; }

  io.out(`File:    ${shownName(realPath(file))}`);
  io.out(`SHA-256: ${hash}`);
  io.out('Allow only a file you have reviewed: Exorcist 98 will let your agent read exactly these bytes at this path.');
  const answer = await term.ask(`Type the first 6 characters of the SHA-256 above to allow it: `);
  if (!confirms(answer, hash)) { io.err('That does not match. Nothing was allowed.'); return 1; }

  // Only the bytes the user confirmed: if the file changed meanwhile, nothing is written.
  const result = addAllowedRead(process.cwd(), file, process.env, hash);
  if (!result.ok) { io.err(result.error); return 1; }
  io.out(`Allowed. Recorded in ${result.store}`);
  io.out('The next read of exactly these bytes at this path passes; any edit checks the file again.');
  return 0;
}
