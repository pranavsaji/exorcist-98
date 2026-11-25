import type { FileRole } from './types.js';
// Pure and browser-safe: no Node imports.
/** Roles whose files an agent takes instructions or settings from. A generic config or code file is not one. */
const NEVER_LOWERED_ROLES: ReadonlySet<FileRole> = new Set<FileRole>(['instruction', 'memory', 'hook', 'mcp-config', 'tool-result', 'power']);
/** Folders and names of agent tools, at any depth: `.kiro/**`, `.claude/**`, `.cursor/**`, `.github/*instructions*`. */
const AGENT_PATH = /(^|\/)(\.kiro|\.claude|\.cursor)\/|(^|\/)\.github\/(?:[^/]*instructions[^/]*|instructions|prompts)(\/|$)/i;
/**
 * True for a file whose findings must keep their full severity even in a test
 * or eval folder: instructions, hooks, MCP configs and anything under an agent
 * tool folder (m7-exemption-bypasses).
 */
export function keepsFullSeverity(rel: string, role: FileRole): boolean {
  const norm = rel.replace(/\\/g, '/');
  return NEVER_LOWERED_ROLES.has(role) || AGENT_PATH.test(norm);
}
/** True when `def` lowers findings in `rel` to low severity. */
export function lowersSeverity(def: { low_severity_paths?: readonly string[] | undefined }, rel: string, role: FileRole): boolean {
  if (!def.low_severity_paths || keepsFullSeverity(rel, role)) return false;
  return def.low_severity_paths.some((p) => new RegExp(p, 'i').test(rel));
}
