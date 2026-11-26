import { isAbsolute } from 'node:path';
import { decideEnvWrite, envWriteBlockMessage, loadEnvValues } from '@exorcist-98/core';
import type { Io } from '../util.js';
export const GUARD_ENV_WRITE_HELP = `Usage: exorcist guard-env-write   (Kiro hook helper)
Reads a Kiro PreToolUse hook event for a file write (fs_write, str_replace) from
stdin. When the text to be written holds a value from a .env file of this project
and the destination is not itself a .env file, the write is blocked: the value
would end up in a file that gets committed or shared.
Exit codes: 0 allow, 2 block (one line on stderr naming the file, never the
value). Any other event, a project without a .env file, and any input it cannot
understand, is allowed: the hook must never stop the agent from working.
`;
function projectDir(event: unknown): string {
  const cwd = typeof event === 'object' && event !== null ? (event as Record<string, unknown>)['cwd'] : undefined;
  return typeof cwd === 'string' && cwd !== '' && isAbsolute(cwd) ? cwd : process.cwd();
}
/** Thin wrapper: parse stdin, load the project's .env values, ask the pure decision. Fails open. */
export function guardEnvWriteCommand(stdin: string, io: Io): number {
  let event: unknown;
  try { event = JSON.parse(stdin); } catch { return 0; }
  const envValues = loadEnvValues(projectDir(event));
  const decision = decideEnvWrite(event, envValues);
  if (!decision.block) return 0;
  io.err(envWriteBlockMessage(decision, envValues));
  return 2;
}
