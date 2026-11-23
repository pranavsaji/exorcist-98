/**
 * exorcist.lock (m5): a committed, reviewable list of the MCP tools a team has
 * approved, like a package lockfile for tool descriptions. Written
 * deterministically (sorted keys, 2-space indent, trailing newline) so a diff
 * in code review means a real change, never formatting or ordering.
 *
 * The lock is untrusted input: it comes from the project folder, so it is
 * validated with zod and every field is treated as data only. Pins seeded
 * from it are still inspected by the signature checks the first time the
 * Shield sees the tool (see engine.ts), so a lock cannot pre-approve a tool
 * whose description hides instructions.
 */
import { existsSync } from 'node:fs';
import { dirname, join, parse as parsePath, resolve } from 'node:path';
import { createTwoFilesPatch } from 'diff';
import { z } from 'zod';
import { canonicalJson, toolFingerprint } from './hash.js';
import type { ToolDef } from './hash.js';
import type { ServerState, State } from './state.js';

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);

export const LockToolSchema = z.object({
  sha256:      Sha256,
  /** The first 200 characters of the tool description, for review. */
  description: z.string(),
}).strict();

export const LockServerSchema = z.object({
  /** launchFingerprint of the program behind a local server. Absent for remote and unpinned servers. */
  launch: Sha256.optional(),
  tools:  z.record(LockToolSchema).default({}),
  /** A remote (http/sse) server: listed with its URL (no query or credentials), tools not pinned. */
  url:    z.string().optional(),
  /** Why a server's tools are not pinned. */
  note:   z.string().optional(),
}).strict();

export const LockSchema = z.object({
  version: z.literal(1),
  servers: z.record(LockServerSchema),
}).strict();

export type Lock = z.infer<typeof LockSchema>;
export type LockServer = z.infer<typeof LockServerSchema>;
export type LockTool = z.infer<typeof LockToolSchema>;

/** Descriptions are kept to this many characters (code points) in the lock. */
export const DESCRIPTION_CHARS = 200;

export const LOCK_FILE = 'exorcist.lock';

/** The first DESCRIPTION_CHARS code points, so a surrogate pair is never cut in half. */
export function lockDescription(description: string | undefined): string {
  const d = description ?? '';
  if (d.length <= DESCRIPTION_CHARS) return d;
  return Array.from(d).slice(0, DESCRIPTION_CHARS).join('');
}

/** A remote server's URL as the lock records it: no credentials, query or fragment (they can hold tokens). */
export function lockUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return '(not a valid URL)';
  }
}

/** What one server contributed to the lock. */
export type ServerListing = {
  name: string;
  /** launchFingerprint(...).hash of a local server. */
  launch?: string;
  tools: ToolDef[];
  url?: string;
  note?: string;
};

/** A record built with defineProperty-like semantics, so a key such as "__proto__" stays an ordinary key. */
const record = <T>(entries: Array<[string, T]>): Record<string, T> => Object.fromEntries(entries) as Record<string, T>;

function lockServer(l: ServerListing): LockServer {
  // A server that lists the same name twice: keep the smallest fingerprint, so
  // the order the server sent them in never changes the lock (PBT-LCK-03).
  const byName = new Map<string, LockTool>();
  for (const t of l.tools) {
    if (typeof t.name !== 'string' || t.name.length === 0) continue;
    const entry = { sha256: toolFingerprint(t), description: lockDescription(t.description) };
    const prev = byName.get(t.name);
    if (!prev || entry.sha256 < prev.sha256) byName.set(t.name, entry);
  }
  return {
    ...(l.launch !== undefined ? { launch: l.launch } : {}),
    tools: record([...byName.entries()]),
    ...(l.url !== undefined ? { url: l.url } : {}),
    ...(l.note !== undefined ? { note: l.note } : {}),
  };
}

/** Build a lock from server listings. The same tools always give the same lock, in any order. */
export function buildLock(listings: ServerListing[]): Lock {
  const servers = new Map<string, LockServer>();
  for (const l of listings) {
    const entry = lockServer(l);
    const prev = servers.get(l.name);
    // Server names are unique in an MCP config; if a caller repeats one, the
    // choice must still not depend on order.
    if (!prev || canonicalJson(entry) < canonicalJson(prev)) servers.set(l.name, entry);
  }
  return { version: 1, servers: record([...servers.entries()]) };
}

/** Build a lock from the local Shield pin file (`exorcist lock --from-shield`). Only approved pins count. */
export function pinsToLock(state: State): Lock {
  const servers: Array<[string, LockServer]> = [];
  for (const [name, s] of Object.entries(state.servers)) {
    const tools = Object.entries(s.tools).map(([tool, pin]): [string, LockTool] => [tool, { sha256: pin.hash, description: lockDescription(pin.description) }]);
    if (tools.length === 0 && !s.launch) continue;
    servers.push([name, {
      ...(s.launch ? { launch: s.launch.hash } : {}),
      tools: record(tools),
      ...(!s.launch ? { note: 'no program pin was recorded for this server (remote, or launch pinning is off)' } : {}),
    }]);
  }
  return { version: 1, servers: record(servers) };
}

/** Sort object keys recursively, so equal data gives equal bytes (REQ-01.2). */
function deepSorted(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(deepSorted);
  const obj = value as Record<string, unknown>;
  return record(Object.keys(obj).filter((k) => obj[k] !== undefined).sort().map((k) => [k, deepSorted(obj[k])]));
}

/** Deterministic text of a lock: sorted keys, 2-space indent, trailing newline. */
export function serializeLock(lock: Lock): string {
  return `${JSON.stringify(deepSorted(lock), null, 2)}\n`;
}

export type ParseLockResult = { ok: true; lock: Lock } | { ok: false; error: string };

/** Read and validate lock text. It is untrusted, so a bad file is an error, never a guess. */
export function parseLock(text: string): ParseLockResult {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { ok: false, error: `${LOCK_FILE} is not valid JSON.` };
  }
  const parsed = LockSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const where = issue && issue.path.length > 0 ? ` (at ${issue.path.join('.')})` : '';
    return { ok: false, error: `${LOCK_FILE} is invalid: ${issue?.message ?? 'unknown problem'}${where}` };
  }
  return { ok: true, lock: parsed.data };
}

// ── diff ─────────────────────────────────────────────────────────────────────

export type LockChangeKind =
  | 'server-added'
  | 'server-removed'
  | 'tool-added'
  | 'tool-removed'
  | 'tool-changed'
  | 'launch-changed'
  | 'url-changed';

export type LockChange = {
  server: string;
  tool?: string;
  kind: LockChangeKind;
  message: string;
  /** Unified diff of the locked description against the current one, when they differ. */
  detail?: string;
};

const MAX_PATCH_CHARS = 4_000;
const short = (h: string | undefined): string => (h ? h.slice(0, 8) : 'none');

/** Unified diff of two descriptions (approved = the lock, now = the server). */
export function descriptionPatch(oldD: string, newD: string): string {
  return createTwoFilesPatch('approved', 'now', oldD, newD, '', '', { context: 2 }).slice(0, MAX_PATCH_CHARS);
}

/** Compare the committed lock with the current one and describe every difference (REQ-03.1). */
export function diffLock(oldLock: Lock, newLock: Lock): LockChange[] {
  const out: LockChange[] = [];
  const names = [...new Set([...Object.keys(oldLock.servers), ...Object.keys(newLock.servers)])].sort();
  for (const name of names) {
    const a = Object.hasOwn(oldLock.servers, name) ? oldLock.servers[name] : undefined;
    const b = Object.hasOwn(newLock.servers, name) ? newLock.servers[name] : undefined;
    if (!a) {
      const tools = Object.keys(b?.tools ?? {}).sort();
      out.push({ server: name, kind: 'server-added', message: `The server "${name}" is not in the lock. Its tools: ${tools.join(', ') || '(none)'}.` });
      continue;
    }
    if (!b) {
      out.push({ server: name, kind: 'server-removed', message: `The server "${name}" is in the lock but no longer in the MCP config.` });
      continue;
    }
    if (a.launch !== b.launch) {
      out.push({ server: name, kind: 'launch-changed', message: `The program behind "${name}" changed (launch ${short(a.launch)} became ${short(b.launch)}).` });
    }
    if (a.url !== b.url) {
      out.push({ server: name, kind: 'url-changed', message: `The address of "${name}" changed (${a.url ?? 'none'} became ${b.url ?? 'none'}).` });
    }
    const tools = [...new Set([...Object.keys(a.tools), ...Object.keys(b.tools)])].sort();
    for (const t of tools) {
      const at = Object.hasOwn(a.tools, t) ? a.tools[t] : undefined;
      const bt = Object.hasOwn(b.tools, t) ? b.tools[t] : undefined;
      if (!bt) { out.push({ server: name, tool: t, kind: 'tool-removed', message: `The tool "${t}" on "${name}" is in the lock but the server no longer lists it.` }); continue; }
      if (!at) {
        out.push({ server: name, tool: t, kind: 'tool-added', message: `The tool "${t}" on "${name}" is new and not in the lock.`, detail: descriptionPatch('', bt.description) });
        continue;
      }
      if (at.sha256 === bt.sha256) continue;
      const sameText = at.description === bt.description;
      out.push({
        server: name, tool: t, kind: 'tool-changed',
        message: `The tool "${t}" on "${name}" changed since it was locked (${short(at.sha256)} became ${short(bt.sha256)})` +
          (sameText ? `: the first ${DESCRIPTION_CHARS} characters of the description are the same, so the input schema or the rest of the description changed.` : '.'),
        ...(sameText ? {} : { detail: descriptionPatch(at.description, bt.description) }),
      });
    }
  }
  return out;
}

// ── Shield seeding ───────────────────────────────────────────────────────────

/** The tool pins a lock grants one server, in Shield state form, marked as coming from the lock. */
export function lockToPins(ls: LockServer, now: Date = new Date()): ServerState['tools'] {
  const at = now.toISOString();
  return record(Object.entries(ls.tools).map(([name, t]) => [name, { hash: t.sha256, description: t.description, pinnedAt: at, source: 'lock' as const }]));
}

export type SeedResult = { seeded: number; disagreements: number };

/**
 * Seed a server's state from the lock (REQ-03.2): a machine that never pinned
 * a tool treats the locked fingerprint as approved, so anything else is a rug
 * pull (EX-006). The lock wins over a missing local pin; a local pin that
 * disagrees with the lock is kept and reported. The program pin is seeded
 * only for a local server (`withLaunch`).
 */
export function seedFromLock(
  s: ServerState,
  ls: LockServer,
  report: (line: string) => void,
  o: { withLaunch: boolean; server: string; now?: Date },
): SeedResult {
  const now = o.now ?? new Date();
  let seeded = 0;
  let disagreements = 0;
  for (const [name, pin] of Object.entries(lockToPins(ls, now))) {
    const local = Object.hasOwn(s.tools, name) ? s.tools[name] : undefined;
    if (!local) {
      s.tools[name] = pin;
      delete s.unreviewed[name]; // the team reviewed it: that is what the lock records
      seeded += 1;
    } else if (local.hash !== pin.hash) {
      disagreements += 1;
      report(`The local pin for "${name}" on "${o.server}" (${short(local.hash)}) disagrees with ${LOCK_FILE} (${short(pin.hash)}). ` +
        `The local pin is kept. If the lock is right, run: exorcist approve tool ${o.server} ${name}`);
    }
  }
  if (o.withLaunch && ls.launch) {
    if (!s.launch) {
      s.launch = { hash: ls.launch, parts: [`approved in ${LOCK_FILE} (launch ${short(ls.launch)})`], pinnedAt: now.toISOString() };
      seeded += 1;
    } else if (s.launch.hash !== ls.launch) {
      disagreements += 1;
      report(`The local program pin for "${o.server}" (${short(s.launch.hash)}) disagrees with ${LOCK_FILE} (${short(ls.launch)}). The local pin is kept.`);
    }
  }
  return { seeded, disagreements };
}

const PROJECT_MARKERS = ['.git', '.kiro', '.exorcist'];

/**
 * The project's exorcist.lock, if any: the nearest one at or above each start
 * folder, stopping at the first folder that looks like a project root.
 */
export function findLockFile(starts: string[]): string | null {
  for (const start of starts) {
    const { root } = parsePath(resolve(start));
    for (let dir = resolve(start); ; dir = dirname(dir)) {
      const candidate = join(dir, LOCK_FILE);
      if (existsSync(candidate)) return candidate;
      if (PROJECT_MARKERS.some((m) => existsSync(join(dir, m)))) break;
      if (dir === root || dirname(dir) === dir) break;
    }
  }
  return null;
}
