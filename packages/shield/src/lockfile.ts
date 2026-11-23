/**
 * exorcist.lock: a committed, reviewable list of the MCP tools a team has
 * approved, like a package lockfile for tool descriptions. Written
 * deterministically (sorted keys, 2-space indent, trailing newline) so a diff
 * in code review means a real change, never formatting.
 *
 * The lock is untrusted input: it is read from the project root, so it is
 * validated with zod and every field is treated as data only.
 */
import { createHash } from 'node:crypto';
import { createTwoFilesPatch } from 'diff';
import { z } from 'zod';
import { toolFingerprint } from './hash.js';
import type { ToolDef } from './hash.js';
import type { ServerState, State } from './state.js';

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);

export const LockToolSchema = z.object({
  sha256:      Sha256,
  /** The first 200 characters of the tool description, for review. */
  description: z.string(),
});

export const LockServerSchema = z.object({
  /** Fingerprint of the program behind the server (command, arguments, files). */
  launch: Sha256,
  tools:  z.record(LockToolSchema).default({}),
  /** Set for remote (http/sse) servers, which are listed but not pinned. */
  url:    z.string().optional(),
  /** Why a server was skipped (remote, disabled). */
  note:   z.string().optional(),
});

export const LockSchema = z.object({
  version: z.literal(1),
  servers: z.record(LockServerSchema),
});

export type Lock = z.infer<typeof LockSchema>;
export type LockServer = z.infer<typeof LockServerSchema>;
export type LockTool = z.infer<typeof LockToolSchema>;

/** Descriptions are truncated to this many characters in the lock. */
export const DESCRIPTION_CHARS = 200;

export const LOCK_FILE = 'exorcist.lock';

/** The launch entry of a remote server: no program, so the URL stands in. */
export function urlFingerprint(url: string): string {
  return createHash('sha256').update(`url:${url}`).digest('hex');
}

/** What one server contributed to the lock. */
export type ServerListing = {
  name: string;
  /** Launch fingerprint hash (or the URL fingerprint for a remote server). */
  launch: string;
  tools: ToolDef[];
  url?: string;
  note?: string;
};

/** Build a lock from live server listings. The same tools always give the same bytes. */
export function buildLock(listings: ServerListing[]): Lock {
  const servers: Record<string, LockServer> = {};
  for (const l of listings) {
    const tools: Record<string, LockTool> = {};
    for (const t of l.tools) {
      if (typeof t.name !== 'string' || t.name.length === 0) continue;
      tools[t.name] = {
        sha256:      toolFingerprint(t),
        description: (t.description ?? '').slice(0, DESCRIPTION_CHARS),
      };
    }
    servers[l.name] = {
      launch: l.launch,
      tools,
      ...(l.url !== undefined ? { url: l.url } : {}),
      ...(l.note !== undefined ? { note: l.note } : {}),
    };
  }
  return { version: 1, servers };
}

/** Build a lock from the local Shield pin file (`exorcist lock --from-shield`). */
export function pinsToLock(state: State): Lock {
  const servers: Record<string, LockServer> = {};
  for (const [name, s] of Object.entries(state.servers)) {
    const tools: Record<string, LockTool> = {};
    for (const [tool, pin] of Object.entries(s.tools)) {
      tools[tool] = { sha256: pin.hash, description: pin.description.slice(0, DESCRIPTION_CHARS) };
    }
    if (Object.keys(tools).length === 0 && !s.launch) continue;
    servers[name] = {
      launch: s.launch?.hash ?? createHash('sha256').update('launch-unpinned').digest('hex'),
      tools,
      ...(!s.launch ? { note: 'no launch pin was recorded for this server' } : {}),
    };
  }
  return { version: 1, servers };
}

/** Sort object keys recursively, so equal data gives equal bytes (REQ-01.2). */
function deepSorted(value: unknown): unknown {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return value;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(value as Record<string, unknown>).sort()) {
    const v = (value as Record<string, unknown>)[k];
    if (v !== undefined) out[k] = deepSorted(v);
  }
  return out;
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
    return { ok: false, error: 'exorcist.lock is not valid JSON.' };
  }
  const parsed = LockSchema.safeParse(json);
  if (!parsed.success) {
    return { ok: false, error: `exorcist.lock is invalid: ${parsed.error.issues[0]?.message ?? 'unknown problem'}` };
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
  | 'launch-changed';

export type LockChange = {
  server: string;
  tool?: string;
  kind: LockChangeKind;
  message: string;
  /** Unified diff of the description, when there is one. */
  detail?: string;
};

const descriptionPatch = (oldD: string, newD: string): string =>
  createTwoFilesPatch('approved', 'now', oldD, newD, '', '', { context: 2 }).slice(0, 4_000);

/** Compare two locks and describe every difference (REQ-03.1). */
export function diffLock(oldLock: Lock, newLock: Lock): LockChange[] {
  const out: LockChange[] = [];
  const names = [...new Set([...Object.keys(oldLock.servers), ...Object.keys(newLock.servers)])].sort();
  for (const name of names) {
    const a = oldLock.servers[name];
    const b = newLock.servers[name];
    if (!a) {
      out.push({ server: name, kind: 'server-added', message: `The server "${name}" is new. Its tools: ${Object.keys(b?.tools ?? {}).sort().join(', ') || '(none)'}.` });
      continue;
    }
    if (!b) {
      out.push({ server: name, kind: 'server-removed', message: `The server "${name}" is gone from the config, but the lock still pins its tools.` });
      continue;
    }
    if (a.launch !== b.launch) {
      out.push({
        server: name,
        kind: 'launch-changed',
        message: `The program behind "${name}" changed (launch ${a.launch.slice(0, 8)} became ${b.launch.slice(0, 8)}).`,
      });
    }
    const tools = [...new Set([...Object.keys(a.tools), ...Object.keys(b.tools)])].sort();
    for (const t of tools) {
      const at = a.tools[t];
      const bt = b.tools[t];
      if (!bt) { out.push({ server: name, tool: t, kind: 'tool-removed', message: `The tool "${t}" on "${name}" was removed.` }); continue; }
      if (!at) {
        out.push({
          server: name, tool: t, kind: 'tool-added',
          message: `The tool "${t}" on "${name}" is new and not in the lock. Description: ${bt.description.slice(0, 120)}`,
        });
        continue;
      }
      if (at.sha256 !== bt.sha256) {
        const sameText = at.description === bt.description;
        out.push({
          server: name, tool: t, kind: 'tool-changed',
          message: `The tool "${t}" on "${name}" changed (${at.sha256.slice(0, 8)} became ${bt.sha256.slice(0, 8)})${sameText ? ': the description reads the same, so the input schema changed.' : '.'}`,
          ...(sameText ? {} : { detail: descriptionPatch(at.description, bt.description) }),
        });
      }
    }
  }
  return out;
}

// ── Shield seeding ───────────────────────────────────────────────────────────

/** The pins a lock grants one server, in Shield state form. */
export function lockServerToPins(ls: LockServer, pinnedAt: string): Pick<ServerState, 'tools' | 'launch'> {
  const tools: ServerState['tools'] = {};
  for (const [name, t] of Object.entries(ls.tools)) {
    tools[name] = { hash: t.sha256, description: t.description, pinnedAt };
  }
  // The lock holds only the launch hash; the parts line is a marker, because
  // parts are only needed for the readable diff of a *changed* program, and
  // the changed program's own parts are available then.
  return { tools, launch: { hash: ls.launch, parts: ['lock exorcist.lock'], pinnedAt } };
}

/**
 * Seed a server's state from the lock: a machine that never pinned a tool
 * still treats the locked fingerprint as approved, and anything else as a
 * rug pull (REQ-03.2). A local pin that disagrees with the lock is reported.
 */
export function seedFromLock(
  s: ServerState,
  ls: LockServer,
  report: (line: string) => void,
  now: Date = new Date(),
): boolean {
  let seeded = false;
  const at = now.toISOString();
  for (const [name, t] of Object.entries(ls.tools)) {
    const local = s.tools[name];
    if (!local) {
      s.tools[name] = { hash: t.sha256, description: t.description, pinnedAt: at };
      seeded = true;
    } else if (local.hash !== t.sha256) {
      report(`The local pin for "${name}" (${local.hash.slice(0, 8)}) disagrees with exorcist.lock (${t.sha256.slice(0, 8)}). The local pin is kept; refresh the lock if the lock is right.`);
    }
  }
  if (!s.launch) {
    s.launch = { hash: ls.launch, parts: ['lock exorcist.lock'], pinnedAt: at };
    seeded = true;
  } else if (s.launch.hash !== ls.launch) {
    report(`The local program pin (${s.launch.hash.slice(0, 8)}) disagrees with exorcist.lock (${ls.launch.slice(0, 8)}). The local pin is kept.`);
  }
  return seeded;
}
