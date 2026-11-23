// Capability classification for the lethal-trifecta check (EX-023).
//
// The rules are data (definitions/capabilities.yaml). This module loads and
// validates them, works out every name an MCP server is known by (the package
// a runner starts, a docker image, a script, a remote URL), and labels a
// server or a built-in agent ability with the capabilities whose rules match.
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import yaml from 'js-yaml';
import { z } from 'zod';
import { packageArg } from './scanner/signature-engine.js';
import type { Capability, CapabilityReason } from './types.js';

export const CAPABILITIES: readonly Capability[] = ['private-data', 'untrusted-input', 'exfiltration'];
export const CAPABILITIES_FILE = 'capabilities.yaml';

// ── Rule file schema ──────────────────────────────────────────────────────────

function compiles(pattern: string): boolean {
  try { new RegExp(pattern, 'i'); return true; } catch { return false; }
}
const Pattern = z.string().min(1).refine(compiles, 'not a valid regular expression');

const ToolSchema = z.object({ name: z.string(), description: z.string().optional() }).strict();

const ExampleSchema = z.object({
  command: z.string().optional(),
  args:    z.array(z.string()).optional(),
  url:     z.string().optional(),
  tools:   z.array(ToolSchema).optional(),
  ability: z.string().optional(),
  expect:  z.boolean(),
  note:    z.string().optional(),
}).strict();

const RuleSchema = z.object({
  id:         z.string().regex(/^CAP-\d{3}$/, 'id must match CAP-NNN'),
  capability: z.enum(['private-data', 'untrusted-input', 'exfiltration']),
  label:      z.string().min(1),
  match: z.object({
    package:     Pattern.optional(),
    exclude:     Pattern.optional(),
    path_scope:  z.literal('outside-project').optional(),
    tool:        Pattern.optional(),
    description: Pattern.optional(),
    ability:     Pattern.optional(),
  }).strict().refine((m) => m.package || m.tool || m.description || m.ability, 'match needs package, tool, description or ability'),
  examples: z.array(ExampleSchema).min(1, 'every rule needs at least one example')
    .refine((ex) => ex.some((e) => e.expect), 'every rule needs an example it matches (expect: true)'),
}).strict();

const RuleFileSchema = z.object({
  version: z.literal(1),
  rules:   z.array(RuleSchema).min(1),
}).strict().superRefine((f, ctx) => {
  const seen = new Set<string>();
  for (const r of f.rules) {
    if (seen.has(r.id)) ctx.addIssue({ code: z.ZodIssueCode.custom, message: `duplicate rule id ${r.id}` });
    seen.add(r.id);
  }
});

export type CapabilityRuleSpec = z.infer<typeof RuleSchema>;
export type CapabilityExample = z.infer<typeof ExampleSchema>;

export type CapabilityRule = {
  id:         string;
  capability: Capability;
  label:      string;
  package:     RegExp | null;
  exclude:     RegExp | null;
  outsideOnly: boolean;
  tool:        RegExp | null;
  description: RegExp | null;
  ability:     RegExp | null;
  examples:    CapabilityExample[];
};

export type CapabilityRulesResult =
  | { ok: true; rules: CapabilityRule[] }
  | { ok: false; error: string; missing: boolean };

const re = (p: string | undefined): RegExp | null => (p === undefined ? null : new RegExp(p, 'i'));

/** Validate parsed YAML (or any value) as a capability rule file. */
export function parseCapabilityRules(data: unknown): CapabilityRulesResult {
  const parsed = RuleFileSchema.safeParse(data);
  if (!parsed.success) {
    const i = parsed.error.issues[0];
    return { ok: false, missing: false, error: `${CAPABILITIES_FILE} is invalid: ${i ? `${i.path.join('.')} ${i.message}` : 'unknown problem'}` };
  }
  return {
    ok: true,
    rules: parsed.data.rules.map((r) => ({
      id: r.id,
      capability: r.capability,
      label: r.label,
      package: re(r.match.package),
      exclude: re(r.match.exclude),
      outsideOnly: r.match.path_scope === 'outside-project',
      tool: re(r.match.tool),
      description: re(r.match.description),
      ability: re(r.match.ability),
      examples: r.examples,
    })),
  };
}

/** Load `capabilities.yaml` from a definitions folder. A missing file is `missing: true`. */
export async function loadCapabilityRules(definitionsDir: string): Promise<CapabilityRulesResult> {
  let raw: string;
  try {
    raw = await readFile(join(definitionsDir, CAPABILITIES_FILE), 'utf8');
  } catch {
    return { ok: false, missing: true, error: `${CAPABILITIES_FILE} was not found in ${definitionsDir}` };
  }
  let data: unknown;
  try {
    data = yaml.load(raw);
  } catch (err) {
    return { ok: false, missing: false, error: `${CAPABILITIES_FILE} is not valid YAML: ${String(err).split('\n')[0]}` };
  }
  return parseCapabilityRules(data);
}

// ── Servers ───────────────────────────────────────────────────────────────────

/** What is known about one MCP server, or one built-in agent ability (`ability`). */
export type ServerSpec = {
  command?: string;
  args?:    string[];
  url?:     string;
  /** Tools seen by the Shield (pin file) or named in an auto-approve list. */
  tools?:   Array<{ name: string; description?: string }>;
  /** A built-in ability such as a Claude Code `permissions.allow` entry. */
  ability?: string;
};

const PACKAGE_RUNNERS = new Set(['npx', 'bunx', 'pnpx', 'uvx']);
const SCRIPT_RUNNERS = new Set(['node', 'nodejs', 'python', 'python3', 'py', 'bun', 'deno', 'tsx', 'ts-node']);
const CONTAINERS = new Set(['docker', 'podman']);
const SHELLS = new Set(['bash', 'sh', 'zsh', 'cmd', 'powershell', 'pwsh']);
const LAUNCHERS = new Set([...PACKAGE_RUNNERS, ...SCRIPT_RUNNERS, ...CONTAINERS, ...SHELLS, 'npm', 'pnpm', 'yarn', 'uv', 'pipx', 'env', 'exorcist']);
/** docker/podman run flags that take a value. */
const DOCKER_VALUE_FLAGS = new Set([
  '-e', '--env', '--env-file', '-v', '--volume', '--mount', '--name', '--network', '--net', '-p', '--publish',
  '-w', '--workdir', '-u', '--user', '--entrypoint', '-l', '--label', '--add-host', '--platform', '--pull',
  '--restart', '-m', '--memory', '--cpus', '-h', '--hostname', '--device', '--cap-add', '--cap-drop',
  '--security-opt', '--tmpfs', '--ulimit', '--log-driver', '--log-opt', '--dns', '--runtime', '--gpus',
]);
const UV_VALUE_FLAGS = new Set(['--directory', '--with', '--from', '--python', '-p', '--project', '--index', '--index-url']);

function basenameOf(cmd: string): string {
  const b = cmd.replace(/\\/g, '/').split('/').pop() ?? cmd;
  return b.toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, '');
}

/** A package or image name without its version, tag or registry prefix. Lowercase. */
export function stripVersion(spec: string): string {
  let t = spec.trim().toLowerCase().replace(/^(?:npm|jsr|pypi):/, '');
  const at = t.indexOf('@', t.startsWith('@') ? 1 : 0);
  if (at > 0) t = t.slice(0, at);
  t = t.replace(/\[[^\]]*\]$/, '');                // python extras
  t = t.replace(/(?:===?|>=|<=|~=|!=|>|<).*$/, ''); // python version specifiers
  return t;
}

function dockerImage(spec: string): string {
  let t = spec.trim().toLowerCase().replace(/@sha256:.*$/, '');
  const slash = t.lastIndexOf('/');
  const colon = t.lastIndexOf(':');
  if (colon > slash) t = t.slice(0, colon);
  return t;
}

type Launch = { command: string; args: string[]; url: string | null };

/**
 * The real program behind a server entry: a Shield-wrapped server
 * (`exorcist shield --server x -- npx pkg`, or `--url` for a remote one) and a
 * shell wrapper (`bash -c "npx pkg"`) are unwrapped first.
 */
export function unwrapLaunch(command: string, args: string[], depth = 0): Launch {
  const s = args.indexOf('shield');
  if (s !== -1 && args[s + 1] === '--server') {
    const dd = args.indexOf('--', s);
    if (dd !== -1 && args[dd + 1] !== undefined) return unwrapLaunch(args[dd + 1] as string, args.slice(dd + 2), depth + 1);
    const u = args.indexOf('--url', s);
    if (u !== -1 && args[u + 1] !== undefined) return { command: '', args: [], url: args[u + 1] as string };
  }
  const base = basenameOf(command);
  if (depth < 3 && SHELLS.has(base)) {
    const c = args.findIndex((a) => /^(?:-c|\/c|-command)$/i.test(a));
    const inner = c === -1 ? undefined : args[c + 1];
    if (inner !== undefined) {
      const parts = inner.trim().split(/\s+/).filter(Boolean).map((p) => p.replace(/^["']|["']$/g, ''));
      if (parts[0] !== undefined) return unwrapLaunch(parts[0], parts.slice(1), depth + 1);
    }
  }
  if (depth < 3 && base === 'env') {
    // env VAR=1 npx pkg
    const i = args.findIndex((a) => !a.includes('=') && !a.startsWith('-'));
    if (i !== -1) return unwrapLaunch(args[i] as string, args.slice(i + 1), depth + 1);
  }
  return { command, args, url: null };
}

function firstPositional(args: string[], valueFlags: Set<string>): number {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a === '--') continue;
    if (a.startsWith('-')) {
      if (!a.includes('=') && valueFlags.has(a)) i++;
      continue;
    }
    return i;
  }
  return -1;
}

/** Index of the package (or image, or script) argument in `args`, and the names it gives. */
function packageNames(l: Launch): { names: string[]; at: number } {
  const base = basenameOf(l.command);
  const a = l.args;
  const names: string[] = [];
  let at = -1;
  const pkgAt = (offset: number): void => {
    const rest = a.slice(offset).filter((x) => x !== '--');
    const p = packageArg(rest);
    if (p !== null) { names.push(stripVersion(p)); at = a.indexOf(p, offset); }
  };
  if (PACKAGE_RUNNERS.has(base)) pkgAt(0);
  else if ((base === 'pnpm' || base === 'yarn') && a[0] === 'dlx') pkgAt(1);
  else if (base === 'npm' && (a[0] === 'exec' || a[0] === 'x')) pkgAt(1);
  else if (base === 'pipx' && a[0] === 'run') pkgAt(1);
  else if (base === 'uv') {
    for (let i = 0; i < a.length; i++) if ((a[i] === '--with' || a[i] === '--from' || a[i] === '--directory') && a[i + 1]) names.push((a[i + 1] as string).toLowerCase());
    const run = a.findIndex((x) => x === 'run');
    if (run !== -1) {
      const rest = a.slice(run + 1);
      const j = firstPositional(rest, UV_VALUE_FLAGS);
      if (j !== -1) { names.push(stripVersion(rest[j] as string)); at = run + 1 + j; }
    }
  } else if (CONTAINERS.has(base)) {
    const run = a.findIndex((x) => x === 'run');
    if (run !== -1) {
      const rest = a.slice(run + 1);
      const j = firstPositional(rest, DOCKER_VALUE_FLAGS);
      if (j !== -1) { names.push(dockerImage(rest[j] as string)); at = run + 1 + j; }
    }
  } else if (SCRIPT_RUNNERS.has(base)) {
    const m = a.indexOf('-m');
    if (m !== -1 && a[m + 1]) { names.push((a[m + 1] as string).toLowerCase()); at = m + 1; }
    else {
      const j = firstPositional(a.filter((x) => x !== 'run'), new Set(['--allow-read', '--config']));
      const script = j === -1 ? undefined : a.filter((x) => x !== 'run')[j];
      if (script !== undefined) { names.push(stripVersion(script.replace(/\\/g, '/'))); at = a.indexOf(script); }
    }
  }
  if (!LAUNCHERS.has(base) && base !== '') names.push(base);
  return { names, at };
}

/** Every name a server is known by, lowercase: package, image, script, command, URL host and path. */
export function serverIdentities(server: ServerSpec): string[] {
  if (server.ability !== undefined) return [];
  const out: string[] = [];
  const l = unwrapLaunch(server.command ?? '', server.args ?? []);
  const url = l.url ?? server.url;
  if (url) {
    try {
      const u = new URL(url);
      out.push(`${u.hostname}${u.pathname}`.toLowerCase());
    } catch {
      out.push(url.toLowerCase());
    }
  }
  if (l.command) out.push(...packageNames(l).names);
  return [...new Set(out.filter((n) => n.length > 0))];
}

// ── Paths outside the project ─────────────────────────────────────────────────

/** Credential folders and files: private wherever they are. */
const CREDENTIALS = /^(?:\.ssh|\.aws|\.gnupg|\.gpg|\.kube|\.docker|\.azure|\.gcloud|\.password-store|\.netrc|\.npmrc|\.pypirc|\.git-credentials|keychains?)$/i;
/** Personal folders directly inside a home folder. */
const PERSONAL = /^(?:\.config|\.local|library|documents|desktop|downloads|pictures|mail|appdata|onedrive|dropbox|icloud drive)$/i;
/** System folders under the root that hold other people's or the machine's data. */
const SYSTEM = /^(?:etc|var|private|proc|sys|boot|root|srv)$/i;
const HOME = /^(?:~|\$home|\$\{home\}|%userprofile%|%homepath%)$/i;
const PROJECT = /^(?:\$\{(?:workspacefolder|workspaceroot|pwd|projectroot|project_dir|cwd)\}|\$pwd|%cd%)$/i;

/** A home folder (given as the segments after it) or a personal folder inside one. */
const homeOrPersonal = (rest: string[]): boolean => rest.length === 0 || PERSONAL.test(rest[0] as string);

/**
 * True when a path argument reaches outside the project: the filesystem
 * root, a drive, a home folder or a personal folder in it (~/Documents), a
 * system folder (/etc), a credentials folder anywhere (.ssh, .aws), or a
 * relative path that climbs out with `..`. Relative paths,
 * `${workspaceFolder}` and deeper absolute paths (most likely the project
 * itself, such as /home/me/code/app) are not.
 */
export function isOutsideProject(raw: string): boolean {
  let p = raw.trim().replace(/^["']|["']$/g, '').replace(/\\/g, '/');
  const absolute = p.startsWith('/');
  p = p.replace(/(?:\/\*\*?)+$/, '');
  if (p === '' && absolute) return true; // "/**": the whole disk
  if (p === '' || p === '**' || p === '*') return false;
  const segs = p.split('/').filter((x) => x !== '');
  if (segs.some((x) => CREDENTIALS.test(x))) return true;
  const first = segs[0] ?? '';
  if (/^[a-z]:$/i.test(first)) {
    if ((segs[1] ?? '').toLowerCase() === 'users') return segs.length <= 3 || PERSONAL.test(segs[3] as string);
    return segs.length === 1;
  }
  if (p.startsWith('/')) {
    if (segs.length === 0) return true;
    const top = first.toLowerCase();
    if (top === 'home' || top === 'users') return segs.length <= 2 || PERSONAL.test(segs[2] as string);
    if (top === 'volumes' || top === 'mnt' || top === 'media') return segs.length <= 2;
    return SYSTEM.test(top);
  }
  if (HOME.test(first)) return homeOrPersonal(segs.slice(1));
  let depth = 0;
  for (const x of PROJECT.test(first) ? segs.slice(1) : segs) {
    if (x === '..') depth--;
    else if (x !== '.') depth++;
    if (depth < 0) return true;
  }
  return false;
}

/** Path-like arguments of a server: positional paths, `--flag=path` values, docker mount sources. */
export function pathArguments(server: ServerSpec): string[] {
  const l = unwrapLaunch(server.command ?? '', server.args ?? []);
  const { at } = packageNames(l);
  const out: string[] = [];
  l.args.forEach((a, i) => {
    if (i === at) return;
    let v = a;
    const eq = /^--?[A-Za-z][\w-]*=(.*)$/.exec(a);
    if (eq) v = eq[1] ?? '';
    const src = /(?:^|,)(?:src|source)=([^,]+)/.exec(v);
    if (src) v = src[1] ?? '';
    else {
      const bind = /^([~/][^:]*):\/.*/.exec(v); // docker -v /host:/container
      if (bind) v = bind[1] ?? '';
    }
    if (v.startsWith('-') || v.includes('://')) return;
    if (/^(?:[/~.]|\$|%|[A-Za-z]:[\\/]?$|[A-Za-z]:[\\/])/.test(v)) out.push(v);
  });
  return out;
}

/** Claude Code permission paths: `//abs` is absolute, `~/` is home, `/x` and `x` are in the project. */
function claudePath(p: string): string {
  if (p.startsWith('//')) return p.slice(1);
  if (p.startsWith('/')) return `.${p}`;
  return p;
}

// ── Classification ────────────────────────────────────────────────────────────

/** What a rule matched on this server, or null. */
export function ruleEvidence(rule: CapabilityRule, server: ServerSpec): string | null {
  if (server.ability !== undefined) {
    if (!rule.ability) return null;
    const m = rule.ability.exec(server.ability);
    if (!m) return null;
    if (rule.outsideOnly && !isOutsideProject(claudePath(m[1] ?? ''))) return null;
    return server.ability;
  }
  if (rule.package) {
    for (const id of serverIdentities(server)) {
      if (!rule.package.test(id) || (rule.exclude && rule.exclude.test(id))) continue;
      if (rule.outsideOnly) {
        const outside = pathArguments(server).find(isOutsideProject);
        if (outside !== undefined) return `${id} ${outside}`;
        continue;
      }
      return id;
    }
  }
  for (const t of server.tools ?? []) {
    if (rule.tool && rule.tool.test(t.name)) return `tool ${t.name}`;
    if (rule.description && t.description && rule.description.test(t.description)) return `tool ${t.name} (description)`;
  }
  return null;
}

export type Classification = { capabilities: Capability[]; reasons: CapabilityReason[] };

/**
 * Label a server or built-in ability with any of private-data,
 * untrusted-input and exfiltration (REQ-01). Capabilities come out in the
 * fixed order of CAPABILITIES; reasons in rule order.
 */
export function classifyCapabilities(server: ServerSpec, rules: readonly CapabilityRule[]): Classification {
  const reasons: CapabilityReason[] = [];
  for (const rule of rules) {
    const evidence = ruleEvidence(rule, server);
    if (evidence !== null) reasons.push({ capability: rule.capability, ruleId: rule.id, label: rule.label, evidence: evidence.slice(0, 120) });
  }
  const has = new Set(reasons.map((r) => r.capability));
  return { capabilities: CAPABILITIES.filter((c) => has.has(c)), reasons };
}

/** An example from the rule file as a server spec. */
export function exampleServer(e: CapabilityExample): ServerSpec {
  return {
    ...(e.command !== undefined ? { command: e.command } : {}),
    ...(e.args !== undefined ? { args: e.args } : {}),
    ...(e.url !== undefined ? { url: e.url } : {}),
    ...(e.tools !== undefined ? { tools: e.tools } : {}),
    ...(e.ability !== undefined ? { ability: e.ability } : {}),
  };
}
