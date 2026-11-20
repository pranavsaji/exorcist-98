import { plainFor, scanText } from '@exorcist-98/core';
import type { VirusDefinition } from '@exorcist-98/core';
import { hostAllowed } from './policy.js';
import { hostsIn } from './hosts.js';
import { describeCredential, findCredentials } from './secrets.js';

export { hostsIn };
import type { ToolDef } from './hash.js';

export type Reason = { ruleId: string; message: string };

const MAX_DEPTH = 32;
const MAX_STRINGS = 5_000;
const MAX_SCAN_CHARS = 1_000_000;

/** All string values and keys in a JSON-like value, within depth and count limits. */
export function collectStrings(value: unknown): string[] {
  return collectStringsChecked(value).strings;
}

/**
 * Like `collectStrings`, and also says whether anything was left unread
 * because of the depth or count limits. A caller deciding whether data may
 * leave the machine must refuse what it could not read (fail closed).
 */
export function collectStringsChecked(value: unknown): { strings: string[]; truncated: boolean } {
  const out: string[] = [];
  let truncated = false;
  const walk = (v: unknown, depth: number): void => {
    if (out.length >= MAX_STRINGS || depth > MAX_DEPTH) {
      if (v !== null && v !== undefined) truncated = true;
      return;
    }
    if (typeof v === 'string') out.push(v);
    else if (Array.isArray(v)) for (const x of v) walk(x, depth + 1);
    else if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
        out.push(k);
        walk(x, depth + 1);
      }
    }
  };
  walk(value, 0);
  return { strings: out, truncated };
}

// ── tool calls (agent to server) ──────────────────────────────────────────────

export type CallVerdict =
  | { action: 'allow'; reasons: [] }
  | { action: 'block'; reasons: Reason[] }
  | { action: 'ask'; reasons: Reason[]; hosts: string[] };

export function inspectCall(
  args: unknown,
  ctx: { allowedHosts: readonly string[]; approvedHosts: readonly string[] },
): CallVerdict {
  const { strings, truncated } = collectStringsChecked(args);
  if (truncated) {
    return {
      action: 'block',
      reasons: [{ ruleId: 'EX-016', message: `The arguments of this call are too deeply nested or too large to inspect (over ${MAX_DEPTH} levels or ${MAX_STRINGS} strings), so they were not sent.` }],
    };
  }

  const secretReasons: Reason[] = [];
  for (const s of strings) {
    for (const hit of findCredentials(s)) {
      secretReasons.push({
        ruleId: 'EX-017',
        message: `A secret (${describeCredential(hit)}) is in the arguments of this call. ${plainFor('EX-017', '').headline}.`,
      });
    }
  }
  if (secretReasons.length > 0) return { action: 'block', reasons: secretReasons.slice(0, 3) };

  const unknown = new Set<string>();
  for (const s of strings) {
    for (const h of hostsIn(s)) {
      if (!hostAllowed(h, ctx.allowedHosts) && !hostAllowed(h, ctx.approvedHosts)) unknown.add(h);
    }
  }
  if (unknown.size > 0) {
    const hosts = [...unknown].sort();
    return {
      action: 'ask',
      hosts,
      reasons: hosts.map((h) => ({ ruleId: 'EX-016', message: `This call would send data to ${h}, which is not on your allowed list.` })),
    };
  }
  return { action: 'allow', reasons: [] };
}

// ── tool results (server to agent) ────────────────────────────────────────────

export type ResultVerdict = { action: 'allow' | 'block'; reasons: Reason[] };

/** The text parts of an MCP tool result. */
export function extractResultText(result: unknown): string {
  if (!result || typeof result !== 'object') return '';
  const r = result as { content?: unknown; structuredContent?: unknown };
  const parts: string[] = [];
  if (Array.isArray(r.content)) {
    for (const c of r.content) {
      if (c && typeof c === 'object') {
        const item = c as { text?: unknown; resource?: { text?: unknown } };
        if (typeof item.text === 'string') parts.push(item.text);
        if (item.resource && typeof item.resource.text === 'string') parts.push(item.resource.text);
      }
    }
  }
  if (r.structuredContent !== undefined) parts.push(...collectStrings(r.structuredContent));
  return parts.join('\n').slice(0, MAX_SCAN_CHARS);
}

const BLOCKING = new Set(['critical', 'high']);

function reasonsFrom(findings: ReturnType<typeof scanText>): Reason[] {
  const seen = new Set<string>();
  const reasons: Reason[] = [];
  for (const f of findings) {
    if (!BLOCKING.has(f.severity) || seen.has(f.ruleId)) continue;
    seen.add(f.ruleId);
    reasons.push({ ruleId: f.ruleId, message: plainFor(f.ruleId, f.title).headline });
  }
  return reasons;
}

export function inspectResult(result: unknown, defs: VirusDefinition[]): ResultVerdict {
  const text = extractResultText(result);
  if (!text) return { action: 'allow', reasons: [] };
  const reasons = reasonsFrom(scanText(text, 'tool-result', defs, '(tool result)'));
  return reasons.length > 0 ? { action: 'block', reasons } : { action: 'allow', reasons: [] };
}

// ── tool definitions (server to agent, in tools/list) ─────────────────────────

const TOOL_TEXT_RULES = new Set(['EX-005', 'EX-006']);

/** Every description in a tool, including those nested in its input schema. */
export function toolText(tool: ToolDef): string {
  return [tool.name, tool.description ?? '', ...collectStrings(tool.inputSchema)].join('\n').slice(0, MAX_SCAN_CHARS);
}

/**
 * Static check of a tool the first time it is seen. Poisoning rules run on the
 * tool text as an MCP config; the injection rules run as for a tool result.
 */
export function inspectTool(tool: ToolDef, defs: VirusDefinition[]): Reason[] {
  const text = toolText(tool);
  const poisoning = scanText(text, 'mcp-config', defs.filter((d) => TOOL_TEXT_RULES.has(d.id)), tool.name);
  const injection = scanText(text, 'tool-result', defs, tool.name);
  return reasonsFrom([...poisoning, ...injection]);
}

// ── requests and notifications the server starts (S-010) ──────────────────────

/** Methods with no text worth checking (they only carry ids, counts or URIs). */
const QUIET = new Set(['notifications/cancelled', 'notifications/tools/list_changed', 'notifications/resources/list_changed', 'notifications/prompts/list_changed', 'notifications/roots/list_changed', 'roots/list', 'ping']);

/** Every string in the params of a server request or notification, checked like a tool result. */
export function inspectServerText(params: unknown, defs: VirusDefinition[]): ResultVerdict {
  const text = collectStrings(params).join('\n').slice(0, MAX_SCAN_CHARS);
  if (!text) return { action: 'allow', reasons: [] };
  const reasons = reasonsFrom(scanText(text, 'tool-result', defs, '(server request)'));
  return reasons.length > 0 ? { action: 'block', reasons } : { action: 'allow', reasons: [] };
}

export function isQuietMethod(method: string): boolean {
  return QUIET.has(method);
}

/** Redacted descriptions of the credentials anywhere in a value. */
export function secretsIn(value: unknown): string[] {
  const out: string[] = [];
  for (const s of collectStrings(value)) for (const h of findCredentials(s)) out.push(describeCredential(h));
  return out;
}
