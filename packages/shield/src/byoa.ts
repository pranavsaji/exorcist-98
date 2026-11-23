/**
 * Bring Your Own Attack (m5-byoa): a visitor pastes text, says where an agent
 * would meet it, and gets the real scanner's findings plus what the real
 * ShieldEngine does with it.
 *
 * Like the Possession Lab simulator, everything runs in memory: the MCP server
 * is a stub that answers from the pasted text, the Shield's pin file is an
 * object, and nothing touches a network, a process or a file. The pasted text
 * is never stored or logged, and the result quotes at most MAX_QUOTE
 * consecutive characters of it (enforced at the end by `capQuotes`).
 */
import { scanText } from '@exorcist-98/core';
import type { FileRole, Severity, SignatureFinding, VirusDefinition } from '@exorcist-98/core';
import { ShieldEngine } from './engine.js';
import type { Action } from './engine.js';
import type { ToolDef } from './hash.js';
import type { JsonRpcMessage } from './jsonrpc.js';
import { DEFAULT_POLICY } from './policy.js';
import { emptyState } from './state.js';
import type { State } from './state.js';
import { BYOA_MAX_CHARS } from './byoa-samples.js';
import type { ByoaPlacement } from './byoa-samples.js';

export { BYOA_MAX_CHARS, BYOA_PLACEMENTS, PLACEMENT_LABELS, byoaSamples, toTagCharacters } from './byoa-samples.js';
export type { ByoaPlacement, ByoaSample } from './byoa-samples.js';

/** Most consecutive characters of the pasted text any part of a result may repeat (REQ-02.2). */
export const MAX_QUOTE = 200;
const MAX_FINDINGS = 50;
const MAX_ALERTS = 10;

export type ByoaFinding = {
  ruleId: string;
  severity: Severity;
  title: string;
  line: number;
  col: number;
  /** The engine's exact quoted span (at most 120 characters). */
  span: string;
  fix: string;
};

export type ByoaAlert = { ruleId: string; severity: 'critical' | 'high' | 'medium'; message: string };

export type ShieldAction =
  /** Tool description: checked, pinned and shown to the agent. */
  | 'pinned'
  /** Tool description or tool result: kept away from the agent. */
  | 'withheld'
  /** Tool result or call: went through. */
  | 'passed'
  /** Call: stopped before it reached the server. */
  | 'blocked'
  /** The simulation could not run on this input. */
  | 'unavailable';

export type ByoaShield =
  | { applies: false; note: string }
  | {
      applies: true;
      action: ShieldAction;
      summary: string;
      alerts: ByoaAlert[];
      /** What the agent got from the Shield instead of the pasted text, if anything. */
      agentReceived: string | null;
      /** Whether the stub MCP server received the call (call arguments only). */
      serverReceived: boolean | null;
    };

export type ByoaHidden = {
  count: number;
  kinds: string[];
  /** The message spelled by Unicode tag characters, if any (the Ouija decoder). */
  decoded: string | null;
};

export type ByoaVerdict = 'exorcised' | 'flagged' | 'clean';

export type ByoaResult = {
  placement: ByoaPlacement;
  verdict: ByoaVerdict;
  stamp: 'EXORCISED' | 'FLAGGED' | 'CLEAN';
  headline: string;
  explanation: string;
  /** Always shown: a clean result is not proof of safety. */
  caveat: string;
  findings: ByoaFinding[];
  shield: ByoaShield;
  hidden: ByoaHidden | null;
  notes: string[];
  checkedChars: number;
};

export const CAVEAT =
  'A clean result is not proof of safety. Exorcist 98 matches known attack patterns, and an attacker who rewords an attack can get past them. Treat text from strangers as untrusted either way.';

// ── hidden characters and the Ouija decoder ──────────────────────────────────

const isZeroWidth = (cp: number) => [0x200b, 0x200c, 0x200d, 0xfeff, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180e].includes(cp);
const isBidi = (cp: number) => (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
const isTag = (cp: number) => cp >= 0xe0000 && cp <= 0xe007f;

/**
 * Count invisible characters and read back any message spelled in Unicode tag
 * characters (U+E0020 to U+E007E map to ASCII; a run needs two or more).
 * Linear time. The message is attacker text: it is displayed, never obeyed.
 */
export function findHidden(text: string): ByoaHidden | null {
  let zw = 0;
  let bidi = 0;
  let tags = 0;
  const runs: string[] = [];
  let run = '';
  const endRun = () => {
    if (run.length >= 2 && runs.length < 100) runs.push(run);
    run = '';
  };
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (isTag(cp)) {
      tags++;
      if (cp >= 0xe0020 && cp <= 0xe007e) run += String.fromCharCode(cp - 0xe0000);
      continue;
    }
    endRun();
    if (isZeroWidth(cp)) zw++;
    else if (isBidi(cp)) bidi++;
  }
  endRun();
  const count = zw + bidi + tags;
  if (count === 0) return null;
  const kinds = [
    ...(tags ? [`${tags} Unicode tag character${tags === 1 ? '' : 's'}`] : []),
    ...(zw ? [`${zw} zero-width character${zw === 1 ? '' : 's'}`] : []),
    ...(bidi ? [`${bidi} direction-changing character${bidi === 1 ? '' : 's'}`] : []),
  ];
  const message = runs.join(' / ').trim();
  return { count, kinds, decoded: message ? clip(message, MAX_QUOTE) : null };
}

// ── quoting limit ────────────────────────────────────────────────────────────

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/**
 * Return `value` with every string shortened so that none contains more than
 * `max` consecutive characters of `input`. Applied to the whole result as a
 * last line of defence (alerts can repeat hosts, decoded messages repeat
 * text, and a visitor may paste a rule's own fix text).
 */
export function capQuotes<T>(value: T, input: string, max = MAX_QUOTE): T {
  if (input.length <= max) return value;
  const windows = new Set<string>();
  for (let i = 0; i + max + 1 <= input.length; i++) windows.add(input.slice(i, i + max + 1));
  const cut = (s: string): string => {
    let out = s;
    for (;;) {
      let hit = -1;
      for (let i = 0; i + max + 1 <= out.length; i++) {
        if (windows.has(out.slice(i, i + max + 1))) { hit = i; break; }
      }
      if (hit === -1) return out;
      // Keeps max - 1 characters from the hit, so the new window cannot match again.
      out = `${out.slice(0, hit + max - 1)}…`;
    }
  };
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return v.length > max ? cut(v) : v;
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return walk(value) as T;
}

// ── the scanner ──────────────────────────────────────────────────────────────

/** The file role(s) and label each placement is scanned as. A tool description is read both ways, as the Shield reads it. */
const SCAN_AS: Record<ByoaPlacement, { roles: FileRole[]; label: string }> = {
  'rules-file': { roles: ['instruction'], label: 'README.md' },
  'tool-description': { roles: ['mcp-config', 'tool-result'], label: '(tool description)' },
  'tool-result': { roles: ['tool-result'], label: '(tool result)' },
  'call-arguments': { roles: ['config'], label: 'arguments.json' },
};

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

function scan(placement: ByoaPlacement, text: string, defs: VirusDefinition[]): ByoaFinding[] {
  const { roles, label } = SCAN_AS[placement];
  const seen = new Set<string>();
  const out: SignatureFinding[] = [];
  for (const role of roles) {
    for (const f of scanText(text, role, defs, label)) {
      const key = `${f.ruleId}:${f.line}:${f.col}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(f);
    }
  }
  out.sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.line - b.line || a.col - b.col);
  return out.slice(0, MAX_FINDINGS).map((f) => ({
    ruleId: f.ruleId, severity: f.severity, title: f.title, line: f.line, col: f.col, span: f.span, fix: f.fix,
  }));
}

// ── the Shield, in memory ────────────────────────────────────────────────────

const SERVER = 'your-mcp-server';
const stringSchema = (name: string) => ({ type: 'object', properties: { [name]: { type: 'string', description: 'Input' } } });

/** A stub MCP server: answers tools/list and tools/call from fixed data. */
class StubServer {
  readonly received: unknown[] = [];
  constructor(private readonly tools: ToolDef[], private readonly resultText: string) {}
  handle(msg: Record<string, unknown>): Record<string, unknown> | null {
    const id = msg['id'];
    const method = msg['method'];
    if (id === undefined || typeof method !== 'string') return null;
    if (method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: this.tools } };
    if (method === 'tools/call') {
      this.received.push((msg['params'] as { arguments?: unknown } | undefined)?.arguments);
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: this.resultText }] } };
    }
    return { jsonrpc: '2.0', id, result: {} };
  }
}

type Run = { alerts: ByoaAlert[]; toAgent: Array<Record<string, unknown>> };

/** A real ShieldEngine with the default policy, its pin file kept in memory. */
function makeShield(defs: VirusDefinition[]): ShieldEngine {
  let state: State = emptyState();
  return new ShieldEngine({
    server: SERVER,
    io: { load: () => structuredClone(state), save: (s: State) => { state = structuredClone(s); } },
    policy: { ...DEFAULT_POLICY, notify: false, allowedHosts: [] },
    defs,
    now: () => new Date('2026-11-20T10:00:00Z'),
  });
}

/** Run the engine's actions to completion, with the stub server answering. */
function pump(engine: ShieldEngine, server: StubServer, first: Action[], run: Run): void {
  const queue = [...first];
  let guard = 0;
  while (queue.length > 0 && guard++ < 200) {
    const a = queue.shift()!;
    if (a.type === 'alert') {
      if (run.alerts.length < MAX_ALERTS) run.alerts.push({ ruleId: a.alert.ruleId, severity: a.alert.severity, message: a.alert.message });
    } else if (a.type === 'forward' && a.to === 'server') {
      const reply = server.handle(a.message as Record<string, unknown>);
      if (reply) queue.push(...engine.onServerLine(JSON.stringify(reply)));
    } else if (a.type === 'forward' && a.to === 'client') {
      run.toAgent.push(a.message as Record<string, unknown>);
    }
  }
}

const textOf = (msg: Record<string, unknown> | undefined): string => {
  const r = msg?.['result'] as { content?: Array<{ text?: unknown }> } | undefined;
  return (r?.content ?? []).map((c) => (typeof c.text === 'string' ? c.text : '')).join('\n');
};

function listTools(engine: ShieldEngine, server: StubServer, run: Run): ToolDef[] {
  const id = 1;
  pump(engine, server, engine.onClient({ jsonrpc: '2.0', id, method: 'tools/list' }), run);
  const listed = run.toAgent.find((m) => m['id'] === id);
  return ((listed?.['result'] as { tools?: ToolDef[] } | undefined)?.tools ?? []);
}

function callTool(engine: ShieldEngine, server: StubServer, name: string, args: unknown, run: Run): { reply: Record<string, unknown> | undefined; reached: boolean } {
  const id = 2;
  const before = server.received.length;
  const msg: JsonRpcMessage = { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } };
  pump(engine, server, engine.onClient(msg), run);
  return { reply: run.toAgent.find((m) => m['id'] === id), reached: server.received.length > before };
}

/** Deepest nesting of a parsed JSON value, without recursion. */
function depthOf(value: unknown, limit: number): number {
  let max = 0;
  const stack: Array<[unknown, number]> = [[value, 1]];
  while (stack.length > 0) {
    const [v, d] = stack.pop()!;
    if (d > max) max = d;
    if (max > limit) return max;
    if (v && typeof v === 'object') for (const x of Object.values(v as Record<string, unknown>)) stack.push([x, d + 1]);
  }
  return max;
}

function shieldFor(placement: ByoaPlacement, text: string, defs: VirusDefinition[], notes: string[]): ByoaShield {
  if (placement === 'rules-file') {
    return {
      applies: false,
      note: 'The Shield guards MCP traffic: tool descriptions, tool results and tool calls. A README or rules file is checked by the scanner instead (a scan, the CI action or the Kiro hook), before your agent reads it.',
    };
  }
  const run: Run = { alerts: [], toAgent: [] };

  if (placement === 'tool-description') {
    const server = new StubServer([{ name: 'pasted_tool', description: text, inputSchema: stringSchema('input') }], 'ok');
    const shield = makeShield(defs);
    const tools = listTools(shield, server, run);
    const kept = tools.some((t) => t.name === 'pasted_tool');
    return {
      applies: true,
      action: kept ? 'pinned' : 'withheld',
      summary: kept
        ? 'Checked the tool and pinned it (SHA-256 of its name, description and inputs). Your AI would read this description. If it ever changes, the Shield hides the tool until you approve the change.'
        : 'Withheld the tool from your AI the first time it was seen. Your AI never reads this description, and any call to the tool is refused.',
      alerts: run.alerts,
      agentReceived: null,
      serverReceived: null,
    };
  }

  if (placement === 'tool-result') {
    const server = new StubServer([{ name: 'search_docs', description: 'Search the documentation.', inputSchema: stringSchema('query') }], text);
    const shield = makeShield(defs);
    listTools(shield, server, run);
    const { reply } = callTool(shield, server, 'search_docs', { query: 'how do I install this?' }, run);
    const refused = (reply?.['result'] as { isError?: boolean } | undefined)?.isError === true;
    return {
      applies: true,
      action: refused ? 'withheld' : 'passed',
      summary: refused
        ? 'Withheld the result. Your AI got a short refusal from the Shield instead of this text.'
        : 'Passed the result to your AI unchanged.',
      alerts: run.alerts,
      agentReceived: refused ? textOf(reply) : null,
      serverReceived: null,
    };
  }

  // call-arguments
  let args: unknown;
  let parsed: unknown;
  let isJson = false;
  try { parsed = JSON.parse(text) as unknown; isJson = true; } catch { isJson = false; }
  if (isJson && parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
    args = parsed;
  } else {
    args = { input: text };
    notes.push(isJson
      ? 'Tool call arguments are a JSON object; this is other JSON, so it was sent as one string argument named "input".'
      : 'This is not valid JSON, so it was sent as one string argument named "input".');
  }
  if (depthOf(args, 200) > 200) {
    // Deeper than the Shield ever reads (it refuses anything past 32 levels), and too deep to copy safely here.
    notes.push('The JSON is nested more than 200 levels deep. The real Shield refuses any call nested past 32 levels without reading it.');
    return {
      applies: true,
      action: 'blocked',
      summary: 'Stopped the call before it left your machine: the arguments are nested too deeply to inspect.',
      alerts: [{ ruleId: 'EX-016', severity: 'critical', message: 'The arguments of this call are too deeply nested or too large to inspect, so they were not sent.' }],
      agentReceived: null,
      serverReceived: false,
    };
  }
  const server = new StubServer([{ name: 'send_data', description: 'Send data to a service.', inputSchema: { type: 'object' } }], 'Sent.');
  const shield = makeShield(defs);
  listTools(shield, server, run);
  const { reply, reached } = callTool(shield, server, 'send_data', args, run);
  return {
    applies: true,
    action: reached ? 'passed' : 'blocked',
    summary: reached
      ? 'Let the call through to the MCP server.'
      : 'Stopped the call before it left your machine. The MCP server never received it.',
    alerts: run.alerts,
    agentReceived: reached ? null : textOf(reply),
    serverReceived: reached,
  };
}

const CHECKED_AS: Record<ByoaPlacement, string> = {
  'rules-file': 'a README or rules file your agent reads',
  'tool-description': 'the description of an MCP tool',
  'tool-result': 'the result of an MCP tool',
  'call-arguments': 'the arguments of a tool call your agent makes',
};

// ── verdict ──────────────────────────────────────────────────────────────────

const STOPPED_EXPLAIN: Partial<Record<ByoaPlacement, string>> = {
  'tool-description': 'The Shield hid this tool the first time it saw it, so your AI never reads the description and any call to the tool is refused.',
  'tool-result': 'The Shield kept this result away from your AI and gave it a refusal instead.',
  'call-arguments': 'The Shield stopped this call before it left your machine. The MCP server never received it.',
};

/** What "clean" covered, per placement, so a visitor knows what was and was not checked. */
const CLEAN_EXPLAIN: Record<ByoaPlacement, string> = {
  'rules-file': 'The scanner found nothing. It looked for hidden characters, orders aimed at your AI, encoded blobs, hidden comments, secrets and risky commands.',
  'tool-description': 'The scanner found nothing and the Shield pinned the tool. If its description ever changes, the Shield hides it until you approve the change.',
  'tool-result': 'The scanner found nothing and the Shield passed the result to your AI.',
  'call-arguments': 'The Shield let the call through. In call arguments it looks for secrets and for hosts you have not allowed; it does not judge what the text says.',
};

function decide(placement: ByoaPlacement, findings: ByoaFinding[], shield: ByoaShield, hidden: ByoaHidden | null): Pick<ByoaResult, 'verdict' | 'stamp' | 'headline' | 'explanation'> {
  const stopped = shield.applies && (shield.action === 'withheld' || shield.action === 'blocked');
  const serious = findings.some((f) => f.severity === 'critical' || f.severity === 'high');
  if (stopped) {
    return { verdict: 'exorcised', stamp: 'EXORCISED', headline: 'EXORCISED: the Shield would stop this.', explanation: STOPPED_EXPLAIN[placement] ?? '' };
  }
  if (placement === 'rules-file' && serious) {
    return {
      verdict: 'exorcised',
      stamp: 'EXORCISED',
      headline: 'EXORCISED: the scanner flags this file before your agent reads it.',
      explanation: 'A scan reports it with the line and the exact text, so you can remove it before an agent ever opens the file.',
    };
  }
  const alerts = shield.applies ? shield.alerts.length : 0;
  if (findings.length > 0 || alerts > 0 || hidden !== null) {
    const why: string[] = [];
    if (findings.length > 0) why.push(`the scanner reports ${findings.length} finding${findings.length === 1 ? '' : 's'}`);
    if (alerts > 0) why.push(`the Shield raised ${alerts} alert${alerts === 1 ? '' : 's'}`);
    if (hidden !== null && !findings.some((f) => f.ruleId === 'EX-001')) why.push('the text hides invisible characters that no rule flags in this place');
    const passed = shield.applies && (shield.action === 'passed' || shield.action === 'pinned');
    return {
      verdict: 'flagged',
      stamp: 'FLAGGED',
      headline: 'FLAGGED: something here looks wrong.',
      explanation: `${why.join(', and ').replace(/^./, (c) => c.toUpperCase())}.${passed ? ' The Shield would still let it through, so read the details below and decide.' : ' Read the details below and decide.'}`,
    };
  }
  return { verdict: 'clean', stamp: 'CLEAN', headline: 'CLEAN: nothing found.', explanation: CLEAN_EXPLAIN[placement] };
}

/**
 * Judge pasted text as if an agent met it at `placement`. Deterministic and
 * pure apart from CPU: same input, same output. Text longer than
 * BYOA_MAX_CHARS is cut to that length (the API refuses it before this).
 */
export function judgeText(placement: ByoaPlacement, input: string, defs: VirusDefinition[]): ByoaResult {
  const text = input.length > BYOA_MAX_CHARS ? input.slice(0, BYOA_MAX_CHARS) : input;
  const notes: string[] = [];
  if (text.length < input.length) notes.push(`Only the first ${BYOA_MAX_CHARS.toLocaleString('en-US')} characters were checked.`);

  const findings = scan(placement, text, defs);
  let shield: ByoaShield;
  try {
    shield = shieldFor(placement, text, defs, notes);
  } catch {
    shield = { applies: true, action: 'unavailable', summary: 'The Shield simulation could not run on this text.', alerts: [], agentReceived: null, serverReceived: null };
  }
  const hidden = findHidden(text);
  const result: ByoaResult = {
    placement,
    ...decide(placement, findings, shield, hidden),
    caveat: CAVEAT,
    findings,
    shield,
    hidden,
    notes: [`Checked as ${CHECKED_AS[placement]}.`, ...notes],
    checkedChars: text.length,
  };
  return capQuotes(result, text);
}
