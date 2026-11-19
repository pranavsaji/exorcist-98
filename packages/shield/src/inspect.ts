import { findSecrets, plainFor, redact, scanText } from '@exorcist-98/core';
import type { VirusDefinition } from '@exorcist-98/core';
import { hostAllowed } from './policy.js';
import type { ToolDef } from './hash.js';

export type Reason = { ruleId: string; message: string };

const MAX_DEPTH = 8;
const MAX_STRINGS = 5_000;
const MAX_SCAN_CHARS = 1_000_000;

/** All string values and keys in a JSON-like value, within depth and count limits. */
export function collectStrings(value: unknown): string[] {
  const out: string[] = [];
  const walk = (v: unknown, depth: number): void => {
    if (out.length >= MAX_STRINGS || depth > MAX_DEPTH) return;
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
  return out;
}

// ── tool calls (agent to server) ──────────────────────────────────────────────

export type CallVerdict =
  | { action: 'allow'; reasons: [] }
  | { action: 'block'; reasons: Reason[] }
  | { action: 'ask'; reasons: Reason[]; hosts: string[] };

const URL_HOST = /https?:\/\/([^\s/?#"'<>\\]+)/gi;

export function hostsIn(text: string): string[] {
  const hosts: string[] = [];
  URL_HOST.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = URL_HOST.exec(text)) !== null) {
    let h = (m[1] ?? '').toLowerCase();
    h = h.slice(h.lastIndexOf('@') + 1); // drop user:password@
    if (!h.startsWith('[')) h = h.replace(/:\d+$/, ''); // drop the port
    if (h) hosts.push(h);
  }
  return hosts;
}

export function inspectCall(
  args: unknown,
  ctx: { allowedHosts: readonly string[]; approvedHosts: readonly string[] },
): CallVerdict {
  const strings = collectStrings(args);

  const secretReasons: Reason[] = [];
  for (const s of strings) {
    for (const hit of findSecrets(s)) {
      secretReasons.push({
        ruleId: 'EX-017',
        message: `A secret (${hit.pattern}, ${redact(hit.match)}) is in the arguments of this call. ${plainFor('EX-017', '').headline}.`,
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
