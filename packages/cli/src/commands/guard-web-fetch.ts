import { isAbsolute } from 'node:path';
import { canariesPath, decideWebFetch, loadCanariesFile, loadEnvValues, webFetchBlockMessage } from '@exorcist-98/core';
import type { Io } from '../util.js';

export const GUARD_WEB_FETCH_HELP = `Usage: exorcist guard-web-fetch   (Kiro hook helper)
Reads a Kiro PreToolUse hook event for the web_fetch tool from stdin. When the
address holds a secret (a key or token), a canary token, or a value from a .env
file of this project, in plain form, percent-encoded, base64 or split up, the
fetch is blocked: a fetch sends its address to another computer.
Exit codes: 0 allow, 2 block (one line on stderr naming the kind of value and the
host, never the value or the address). Any other event, and any input it cannot
understand, is allowed: the hook must never stop the agent from working.
`;

/** The project folder: the event's own `cwd` when it is an absolute path, else the process folder. */
function projectDir(event: unknown): string {
  const cwd = typeof event === 'object' && event !== null ? (event as Record<string, unknown>)['cwd'] : undefined;
  return typeof cwd === 'string' && cwd !== '' && isAbsolute(cwd) ? cwd : process.cwd();
}

/** Thin wrapper: parse stdin, load the project's secrets, ask the pure decision. Fails open. */
export function guardWebFetchCommand(stdin: string, io: Io): number {
  let event: unknown;
  try { event = JSON.parse(stdin); } catch { return 0; }
  const cwd = projectDir(event);
  const records = loadCanariesFile(canariesPath(cwd));
  const decision = decideWebFetch(event, {
    envValues: loadEnvValues(cwd),
    canaries: records.ok ? records.canaries : [],
  });
  if (!decision.block) return 0;
  io.err(webFetchBlockMessage(decision));
  return 2;
}
