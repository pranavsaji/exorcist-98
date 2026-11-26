import { randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream, openSync, writeSync } from 'node:fs';
import { homedir } from 'node:os';
import { createInterface } from 'node:readline';
import { decideMcpWrite, shownName } from '@exorcist-98/core';
import { askOwner, macDialog, personConfirms } from './on-access.js';
import type { Terminal } from './on-access.js';
import type { Io } from '../util.js';

export const GUARD_MCP_WRITE_HELP = `Usage: exorcist guard-mcp-write   (Kiro hook helper)
Reads a Kiro PreToolUse hook event from stdin. When the tool would write to
.kiro/settings/mcp.json (in a project or in your home folder), adds a trusted
command to .vscode/settings.json, or creates, changes, moves or deletes a file
in .kiro/hooks/ or .kiro/agents/, a person must confirm it: on a Mac with the system verification (Touch ID or login password),
else in a native dialog you click (Deny is the default),
elsewhere by typing a code shown on your terminal (/dev/tty). The dialog names
the file and never shows what the agent wanted to write.
Exit codes: 0 allow, 2 block (denied, timed out, or nobody to ask; the reason
goes to stderr). Any other event, and any input it cannot understand, is
allowed: the hook must never stop the agent from working.
Shell commands are checked on a best-effort basis (>, >>, tee, sed -i, cp, mv).
`;

/** The dialog gives up after 120 s; this ends the wait a little later, under the hook's 150 s. */
export const PROMPT_TIMEOUT_MS = 125_000;

export type GuardDeps = {
  /** Where the person is asked. */
  term: Terminal;
  /** Where the typed code is shown: the person's terminal, never the hook's stdout (an agent may read that). */
  promptIo: Io;
  home: string;
  timeoutMs: number;
};

/**
 * The real terminal for a hook. The hook's stdin carries the event, so the
 * keyboard is /dev/tty, opened separately; without a controlling terminal
 * (a GUI-launched Kiro) `interactive` is false and only a native dialog can
 * ask. The code goes to the same device, not to the hook's stdout.
 */
export function hookDeps(): GuardDeps {
  let fd: number | null = null;
  try { fd = openSync('/dev/tty', 'r+'); } catch { fd = null; }
  const tty = fd;
  const write = (s: string): void => { if (tty !== null) try { writeSync(tty, s.endsWith('\n') ? s : `${s}\n`); } catch { /* terminal gone */ } };
  const term: Terminal = {
    interactive: tty !== null,
    ask: (prompt) => new Promise((done) => {
      if (tty === null) { done(''); return; }
      const input = createReadStream('', { fd: tty, autoClose: false });
      const output = createWriteStream('', { fd: tty, autoClose: false });
      const rl = createInterface({ input, output, terminal: true });
      rl.question(prompt, (answer) => { rl.close(); input.destroy(); done(answer); });
    }),
    dialog: macDialog,
    nonce: () => randomBytes(4).toString('hex').slice(0, 6),
  };
  return { term, promptIo: { out: write, err: write }, home: homedir(), timeoutMs: PROMPT_TIMEOUT_MS };
}

type Guarded = 'mcp-config' | 'trusted-commands' | 'guard-file';

/** Plain-language text for the dialog. Names the file, never the content. */
function dialogMessage(kind: Guarded, path: string): string {
  if (kind === 'trusted-commands') return `Your AI agent wants to change which commands it may run without asking you:\n\n${shownName(path)}\n\nA wider list lets the agent run programs on your computer without your approval. Allow it only if you asked for this change.`;
  if (kind === 'guard-file') return `Your AI agent wants to change one of its own guard files (a hook or a custom agent):\n\n${shownName(path)}\n\nThese files decide what the agent is stopped from doing. Allow it only if you asked for this change.`;
  return `Your AI agent wants to change an MCP configuration file:\n\n${shownName(path)}\n\nA changed MCP config can start programs on your computer. Allow it only if you asked for this change.`;
}

function reasonText(kind: Guarded, path: string): string {
  if (kind === 'trusted-commands') return `Allow your AI agent to change its trusted commands in ${shownName(path)}`;
  if (kind === 'guard-file') return `Allow your AI agent to change its guard file ${shownName(path)}`;
  return `Allow your AI agent to change the MCP config ${shownName(path)}`;
}
function blockMessage(kind: Guarded, path: string, why: string): string {
  if (kind === 'trusted-commands') return `Exorcist 98 blocked the write to ${shownName(path)}: ${why} The trusted commands list decides which programs the agent may run without asking, so only you may change it. To make the change yourself, edit the file in your own editor, then ask the agent to continue.`;
  if (kind === 'guard-file') return `Exorcist 98 blocked the write to ${shownName(path)}: ${why} Hooks and custom agents decide what the agent is stopped from doing, so only you may change them. To make the change yourself, edit the file in your own editor, then ask the agent to continue.`;
  return `Exorcist 98 blocked the write to ${shownName(path)}: ${why} An MCP config can start programs on your computer, so only you may change it. To make the change yourself, edit the file in your own editor, then ask the agent to continue.`;
}

/** Ask once; a timeout counts as no. */
async function askPerson(deps: GuardDeps, kind: Guarded, path: string): Promise<'yes' | 'no' | 'nobody' | 'timeout'> {
  const { term, promptIo } = deps;
  const run = async (): Promise<'yes' | 'no' | 'nobody'> => {
    if (term.interactive) return (await personConfirms(term, promptIo, dialogMessage(kind, path), reasonText(kind, path))) ? 'yes' : 'no';
    // No terminal to type in: only the OS verification or a native dialog can ask.
    const answer = await askOwner(term, dialogMessage(kind, path), reasonText(kind, path));
    return answer === 'allow' ? 'yes' : answer === 'deny' ? 'no' : 'nobody';
  };
  let timer: NodeJS.Timeout | undefined;
  const limit = new Promise<'timeout'>((done) => { timer = setTimeout(() => done('timeout'), deps.timeoutMs); });
  try {
    return await Promise.race([run(), limit]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * The MCP config write hook. Fail-open on anything that is not a recognisable
 * write to an MCP config; fail-closed when it is one and nobody can be asked.
 */
export async function guardMcpWriteCommand(stdin: string, io: Io, deps: GuardDeps = hookDeps()): Promise<number> {
  let event: unknown;
  try { event = JSON.parse(stdin); } catch { return 0; }
  const decision = decideMcpWrite(event, deps.home, process.cwd());
  if (decision.target === 'other') return 0;
  const answer = await askPerson(deps, decision.target, decision.path);
  if (answer === 'yes') return 0;
  const why = answer === 'no' ? 'you did not confirm it.'
    : answer === 'timeout' ? 'nobody confirmed it in time.'
    : 'there is no dialog or terminal where a person can be asked.';
  io.err(blockMessage(decision.target, decision.path, why));
  return 2;
}
