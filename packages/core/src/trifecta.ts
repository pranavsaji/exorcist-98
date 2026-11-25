// The lethal trifecta (EX-023) and the Haunted House Map.
//
// One MCP server rarely does harm alone. A config whose enabled servers,
// together, can read private data, take in untrusted text and send data out
// lets a single prompt injection steal whatever the agent can read. This
// module reads MCP config files, labels each server with the capability
// rules (capabilities.ts), and reports EX-023 once per config.
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { CAPABILITIES, classifyCapabilities } from './capabilities.js';
import type { CapabilityRule, ServerSpec } from './capabilities.js';
import type { Capability, ConfigMap, FileRole, MapGhost, SignatureFinding } from './types.js';
import type { VirusDefinition } from './definitions/schema.js';

export const TRIFECTA_RULE_ID = 'EX-023';
// No caps on servers, abilities or tools: padding a config with filler
// entries must never hide the dangerous ones (a truncated config would read
// as clean). Classifying an entry is a few regex tests, so every entry is
// analysed; the walker's file-size limit bounds the total.
/** Largest Shield pin file read, in bytes. */
export const MAX_PINS_BYTES = 4_000_000;

/** One entry of an MCP config: a server, or a built-in ability the config allows. */
export type ConfigEntry = ServerSpec & {
  name:         string;
  kind:         'server' | 'ability';
  disabled:     boolean;
  /** Tool names that run without asking ('*' for all). */
  autoApprove:  string[];
};

export type ParsedMcpConfig = {
  file:    string;
  entries: ConfigEntry[];
  /** Where EX-023 is reported: the `mcpServers` (or `servers`, `allow`) key. */
  anchor:  { line: number; col: number; span: string };
};

// ── Parsing ───────────────────────────────────────────────────────────────────

/** Remove // and /* comments and trailing commas outside strings (JSONC, as in VS Code mcp.json). */
export function stripJsonc(text: string): string {
  let out = '';
  let i = 0;
  let inStr = false;
  while (i < text.length) {
    const c = text[i] as string;
    if (inStr) {
      out += c;
      if (c === '\\') { out += text[i + 1] ?? ''; i += 2; continue; }
      if (c === '"') inStr = false;
      i++;
      continue;
    }
    if (c === '"') { inStr = true; out += c; i++; continue; }
    if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (c === '/' && text[i + 1] === '*') { const e = text.indexOf('*/', i + 2); i = e === -1 ? text.length : e + 2; continue; }
    out += c;
    i++;
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

function parseJsonLoose(text: string): unknown {
  try { return JSON.parse(text); } catch { /* try JSONC */ }
  try { return JSON.parse(stripJsonc(text)); } catch { return undefined; }
}

const Obj = z.record(z.unknown());
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);

function position(text: string, offset: number): { line: number; col: number } {
  const before = text.slice(0, offset);
  const line = (before.match(/\n/g) ?? []).length + 1;
  const nl = before.lastIndexOf('\n');
  return { line, col: nl === -1 ? offset + 1 : offset - nl };
}

function anchorFor(text: string, keys: string[]): ParsedMcpConfig['anchor'] {
  for (const k of keys) {
    const span = JSON.stringify(k);
    const at = text.indexOf(span);
    if (at !== -1) return { ...position(text, at), span };
  }
  const firstLine = text.split('\n').find((l) => l.trim() !== '') ?? '';
  const at = text.indexOf(firstLine.trim());
  return { ...position(text, Math.max(0, at)), span: firstLine.trim().slice(0, 120) || '(empty file)' };
}

function serverEntries(servers: Record<string, unknown>): ConfigEntry[] {
  const out: ConfigEntry[] = [];
  for (const [name, raw] of Object.entries(servers)) {
    const e = Obj.safeParse(raw);
    if (!e.success) continue;
    const v = e.data;
    const command = str(v['command']);
    const url = str(v['url']) ?? str(v['serverUrl']) ?? str(v['httpUrl']);
    if (command === undefined && url === undefined) continue;
    const autoApprove = [...strings(v['autoApprove']), ...strings(v['alwaysAllow'])];
    if (v['trust'] === true) autoApprove.push('*');
    out.push({
      name,
      kind: 'server',
      disabled: v['disabled'] === true || v['enabled'] === false,
      autoApprove,
      ...(command !== undefined ? { command, args: strings(v['args']) } : {}),
      ...(url !== undefined ? { url } : {}),
    });
  }
  return out;
}

/**
 * Read an MCP config: Kiro, Cursor, Claude Code (`.mcp.json`, settings with
 * `permissions.allow`), VS Code (`servers`), Gemini (`trust`), Cline
 * (`alwaysAllow`). Generic JSON config files count only when they have an
 * `mcpServers` object with at least one server. Null when the file is not an
 * MCP config.
 */
export function parseMcpConfig(rel: string, role: FileRole, text: string): ParsedMcpConfig | null {
  if (role !== 'mcp-config' && !(role === 'config' && /\.jsonc?$/i.test(rel))) return null;
  if (role === 'config' && !text.includes('mcpServers')) return null;
  const top = Obj.safeParse(parseJsonLoose(text));
  if (!top.success) return null;
  const doc = top.data;
  const entries: ConfigEntry[] = [];
  let hasServersKey = false;
  for (const key of role === 'mcp-config' ? ['mcpServers', 'servers'] : ['mcpServers']) {
    const s = Obj.safeParse(doc[key]);
    if (!s.success) continue;
    hasServersKey = true;
    entries.push(...serverEntries(s.data));
  }
  if (role === 'config' && entries.length === 0) return null;

  // Claude Code: permissions.allow auto-approves MCP tools (mcp__server__tool)
  // and built-in abilities (WebFetch, Bash(...), Read(...)).
  const perms = Obj.safeParse(doc['permissions']);
  const allow = role === 'mcp-config' && perms.success ? strings(perms.data['allow']) : [];
  for (const a of allow) {
    const m = /^mcp__([^_](?:[^_]|_(?!_))*)(?:__(.+))?$/.exec(a);
    if (m) {
      const server = entries.find((e) => e.kind === 'server' && e.name === m[1]);
      server?.autoApprove.push(m[2] && m[2] !== '*' ? m[2] : '*');
      continue;
    }
    if (entries.some((e) => e.kind === 'ability' && e.name === a)) continue;
    entries.push({ name: a, kind: 'ability', ability: a, disabled: false, autoApprove: ['*'] });
  }
  if (!hasServersKey && entries.length === 0) return null;
  return { file: rel, entries, anchor: anchorFor(text, ['mcpServers', 'servers', 'allow', 'permissions']) };
}

// ── Pins (the Shield's record of each server's tools) ─────────────────────────

const PinsSchema = z.object({
  servers: z.record(z.object({
    tools: z.record(z.object({ description: z.string() }).passthrough()).default({}),
  }).passthrough()).default({}),
}).passthrough();

export type ToolPins = Map<string, Array<{ name: string; description: string }>>;

/** Tools per server from a Shield pin file's JSON. An invalid file gives no tools. */
export function parsePins(json: unknown): ToolPins {
  const out: ToolPins = new Map();
  const p = PinsSchema.safeParse(json);
  if (!p.success) return out;
  for (const [server, s] of Object.entries(p.data.servers)) {
    out.set(server, Object.entries(s.tools).map(([name, t]) => ({ name, description: t.description })));
  }
  return out;
}

export type PinsRead = { pins: ToolPins; note: string | null };

/**
 * The pin file at `<root>/.exorcist/pins.json`. It comes from the scanned
 * repository, so it is untrusted: only a regular file (never a symlink, which
 * could point anywhere on the machine) no larger than `maxBytes` is read, and
 * it is opened with O_NOFOLLOW so it cannot be swapped for a link in between.
 * Anything else is ignored, with a note saying why. A missing file is no note.
 */
export async function readPins(root: string, maxBytes: number = MAX_PINS_BYTES): Promise<PinsRead> {
  const path = join(root, '.exorcist', 'pins.json');
  const none = (note: string | null): PinsRead => ({ pins: new Map(), note });
  let info;
  try {
    info = await lstat(path);
  } catch {
    return none(null);
  }
  if (info.isSymbolicLink()) return none('The Shield pin file .exorcist/pins.json is a symbolic link, so it was ignored.');
  if (!info.isFile()) return none('.exorcist/pins.json is not a regular file, so it was ignored.');
  if (info.size > maxBytes) return none(`The Shield pin file .exorcist/pins.json is larger than ${maxBytes} bytes, so it was ignored.`);
  let fh;
  try {
    fh = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch {
    return none('The Shield pin file .exorcist/pins.json could not be opened, so it was ignored.');
  }
  try {
    const st = await fh.stat();
    if (!st.isFile() || st.size > maxBytes) return none(`The Shield pin file .exorcist/pins.json changed while it was read, so it was ignored.`);
    const buf = Buffer.alloc(st.size);
    const { bytesRead } = await fh.read(buf, 0, st.size, 0);
    let json: unknown;
    try {
      json = JSON.parse(buf.subarray(0, bytesRead).toString('utf8'));
    } catch {
      return none('The Shield pin file .exorcist/pins.json is not valid JSON, so it was ignored.');
    }
    return { pins: parsePins(json), note: null };
  } finally {
    await fh.close();
  }
}

// ── Detection ─────────────────────────────────────────────────────────────────

export type TrifectaResult = {
  legs:     Record<Capability, string[]>;
  trifecta: boolean;
  severity: 'critical' | 'high' | null;
};

/**
 * The legs of the trifecta covered by these ghosts (REQ-02). Pure and
 * order-independent: legs are sorted name lists. Critical when a ghost on a
 * leg has auto-approved tools.
 */
export function detectTrifecta(ghosts: readonly MapGhost[]): TrifectaResult {
  const legs = Object.fromEntries(CAPABILITIES.map((c) => [
    c,
    [...new Set(ghosts.filter((g) => g.capabilities.includes(c)).map((g) => g.name))].sort(),
  ])) as Record<Capability, string[]>;
  const trifecta = CAPABILITIES.every((c) => legs[c].length > 0);
  const autoOnLeg = ghosts.some((g) => g.autoApproved && g.capabilities.length > 0);
  return { legs, trifecta, severity: trifecta ? (autoOnLeg ? 'critical' : 'high') : null };
}

const byKindThenName = (a: MapGhost, b: MapGhost): number =>
  a.kind !== b.kind ? (a.kind === 'server' ? -1 : 1) : a.name < b.name ? -1 : a.name > b.name ? 1 : 0;

/** Label every enabled entry of a config and work out its map. */
export function analyzeConfig(config: ParsedMcpConfig, rules: readonly CapabilityRule[], pins: ToolPins = new Map()): ConfigMap {
  const ghosts: MapGhost[] = config.entries
    .filter((e) => !e.disabled)
    .map((e) => {
      const tools = [
        ...(e.kind === 'server' ? pins.get(e.name) ?? [] : []),
        ...e.autoApprove.filter((t) => t !== '*').map((name) => ({ name })),
      ];
      const spec: ServerSpec = e.kind === 'ability'
        ? { ability: e.ability ?? e.name }
        : { ...(e.command !== undefined ? { command: e.command, args: e.args ?? [] } : {}), ...(e.url !== undefined ? { url: e.url } : {}), tools };
      const c = classifyCapabilities(spec, rules);
      return { name: e.name, kind: e.kind, capabilities: c.capabilities, reasons: c.reasons, autoApproved: e.autoApprove.length > 0 };
    })
    .sort(byKindThenName);
  return { file: config.file, ghosts, ...detectTrifecta(ghosts) };
}

const LEG_WORDS: Record<Capability, string> = {
  'private-data':    'private data from',
  'untrusted-input': 'untrusted text from',
  exfiltration:      'a way out through',
};

/** The EX-023 finding for a config map, or null when there is no trifecta or the rule is disabled. */
export function trifectaFinding(config: ParsedMcpConfig, map: ConfigMap, defs: readonly VirusDefinition[]): SignatureFinding | null {
  if (!map.trifecta || map.severity === null) return null;
  const def = defs.find((d) => d.id === TRIFECTA_RULE_ID && d.enabled !== false && d.match.analysis === 'trifecta');
  if (!def) return null;
  // Test and eval fixtures are not a user's agent setup (skip_paths, as for the text rules).
  if (def.skip_paths?.some((p) => new RegExp(p, 'i').test(config.file))) return null;
  const legs = CAPABILITIES.map((c) => `${LEG_WORDS[c]} ${map.legs[c].join(', ')}`).join('; ');
  const auto = map.ghosts.filter((g) => g.autoApproved && g.capabilities.length > 0).map((g) => g.name);
  const autoText = auto.length > 0 ? ` Tools on ${auto.join(', ')} are auto-approved, so nothing asks you first.` : '';
  return {
    source: 'signature',
    ruleId: def.id,
    title: def.title,
    severity: map.severity,
    file: config.file,
    line: config.anchor.line,
    col: config.anchor.col,
    span: config.anchor.span,
    owasp: def.owasp,
    fix: `This config gives one agent session ${legs}.${autoText} ${def.fix.trim()}`,
  };
}
