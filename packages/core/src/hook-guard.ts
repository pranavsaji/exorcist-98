/**
 * Decision logic for the Kiro PreToolUse hook that blocks `git commit` while
 * staged files contain secrets. The thin script in scripts/ reads stdin and
 * calls `decide`; keeping the logic here makes it testable.
 *
 * Kiro sends the event as JSON ({ hook_event_name, cwd, tool_name,
 * tool_input }). Exit 0 lets the command run; a non-zero exit blocks it.
 */
import { findStagedSecrets } from './secrets-check.js';

export type HookDecision = { exitCode: 0 | 2; message: string };

function strings(value: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 6) return out;
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const v of value) strings(v, out, depth + 1);
  else if (value && typeof value === 'object') for (const v of Object.values(value)) strings(v, out, depth + 1);
  return out;
}

/** True for `git commit`, `git -C dir commit -m x`, `git commit -am` and the like. */
export function isGitCommit(command: string): boolean {
  return /(^|[\s;&|(])git\s+(?:-[^\s]+\s+(?:[^\s-][^\s]*\s+)?)*commit(\s|$)/.test(command);
}

export function decide(stdin: string, fallbackCwd: string = process.cwd()): HookDecision {
  let event: { cwd?: unknown; tool_input?: unknown };
  try {
    event = JSON.parse(stdin) as typeof event;
  } catch {
    return { exitCode: 0, message: '' }; // not a hook event we understand: do not block
  }
  if (!strings(event.tool_input).some(isGitCommit)) return { exitCode: 0, message: '' };

  const cwd = typeof event.cwd === 'string' && event.cwd ? event.cwd : fallbackCwd;
  const result = findStagedSecrets(cwd);
  if (!result.ok) return { exitCode: 0, message: result.error };
  if (result.hits.length === 0) return { exitCode: 0, message: '' };

  const lines = result.hits.map((h) => `  ${h.file}:${h.line}  ${h.pattern}  ${h.redacted}`);
  return {
    exitCode: 2,
    message:
      `Exorcist 98 blocked this commit: ${result.hits.length} possible secret(s) are staged.\n` +
      `${lines.join('\n')}\n` +
      'Remove them (use an environment variable or a secrets manager), unstage the file, then commit again.',
  };
}
