/**
 * sandbox-policy.ts (EX-035, CT-18)
 *
 * Reports, as information only, a committed `.kiro/settings/sandbox.json`
 * that turns MCP sandboxing, or the whole command sandbox, off.
 *
 * Field names come from https://kiro.dev/docs/sandbox: `enabled` (required,
 * boolean), `networkAccess` (string) and `mcpSandboxing` (boolean, off by
 * default). Per that page a project file can only tighten the global policy,
 * so an "off" here may be overridden by an active global policy.
 *
 * Pure function: no file or network access.
 */
import { lineColOf } from './canary.js';
import { parseJsonLoose } from './json-loose.js';
import type { Finding } from './types.js';

export const SANDBOX_RULE_ID = 'EX-035';
const SANDBOX_FILE = /(?:^|\/)\.kiro\/settings\/sandbox\.json$/;
const OWASP = ['ASI05 Unexpected Code Execution', 'LLM06:2025 Excessive Agency'];
const FIX =
  'A project file can only tighten the global sandbox policy, so if your global policy turns the sandbox and MCP wrapping on, it still applies here. ' +
  'To be covered in every project, set "enabled": true and "mcpSandboxing": true in your global ~/.kiro/settings/sandbox.json (or in this file).';

/** Index of `"key": false` at the start of a line that is not inside a // comment. */
function indexOfFalse(text: string, key: string): number {
  const re = new RegExp(`"${key}"\\s*:\\s*false`, 'g');
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const lineStart = text.lastIndexOf('\n', m.index) + 1;
    if (!text.slice(lineStart, m.index).includes('//')) return m.index;
  }
  return -1;
}

/** The info finding for a sandbox file that turns MCP sandboxing (or everything) off, or []. */
export function sandboxFindings(text: string, rel: string): Finding[] {
  if (!SANDBOX_FILE.test(rel.replace(/\\/g, '/'))) return [];
  const doc = parseJsonLoose(text);
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return [];
  const obj = doc as Record<string, unknown>;
  const mcpOff = obj['mcpSandboxing'] === false;
  const allOff = obj['enabled'] === false;
  if (!mcpOff && !allOff) return [];
  const key = mcpOff ? 'mcpSandboxing' : 'enabled';
  const at = indexOfFalse(text, key);
  if (at < 0) return [];
  const m = new RegExp(`^"${key}"\\s*:\\s*false`).exec(text.slice(at));
  const { line, col } = lineColOf(text, at);
  return [{
    source: 'signature',
    ruleId: SANDBOX_RULE_ID,
    title: mcpOff ? 'Info: MCP sandboxing is off in this project' : 'Info: the command sandbox is off in this project',
    severity: 'low',
    file: rel,
    line,
    col,
    span: m ? m[0] : `"${key}": false`,
    owasp: OWASP,
    fix: FIX,
  }];
}
