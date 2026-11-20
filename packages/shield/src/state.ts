import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { z } from 'zod';

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);

const PinSchema = z.object({
  hash:        Sha256,
  description: z.string(),
  pinnedAt:    z.string(),
});

const PendingSchema = z.object({
  hash:           Sha256,
  oldHash:        Sha256,
  oldDescription: z.string(),
  newDescription: z.string(),
  seenAt:         z.string(),
});

const UnreviewedSchema = z.object({
  hash:        Sha256,
  description: z.string(),
  seenAt:      z.string(),
});

const ServerStateSchema = z.object({
  tools:         z.record(PinSchema).default({}),
  pending:       z.record(PendingSchema).default({}),
  /** Tools seen for the first time under `firstUse: review`, not yet approved. */
  unreviewed:    z.record(UnreviewedSchema).default({}),
  approvedHosts: z.array(z.string()).default([]),
});

export const StateSchema = z.object({
  version: z.literal(1),
  servers: z.record(ServerStateSchema).default({}),
});

export type State = z.infer<typeof StateSchema>;
export type ServerState = z.infer<typeof ServerStateSchema>;
export type Pin = z.infer<typeof PinSchema>;

export type Alert = {
  time:     string;
  server:   string;
  ruleId:   string;
  severity: 'critical' | 'high' | 'medium';
  tool?:    string;
  message:  string;
  /** Extra text such as a unified diff. Never contains arguments or results. */
  detail?:  string;
};

export const emptyState = (): State => ({ version: 1, servers: {} });

export type LoadResult = { ok: true; state: State } | { ok: false; error: string };

export const statePath  = (dir: string): string => join(dir, 'pins.json');
export const policyPath = (dir: string): string => join(dir, 'policy.json');
export const alertsPath = (dir: string): string => join(dir, 'alerts.jsonl');
export const vaultPath  = (dir: string): string => join(dir, 'vault');

/** A missing file is an empty state. A corrupt or invalid file is an error: fail closed. */
export function loadState(path: string): LoadResult {
  if (!existsSync(path)) return { ok: true, state: emptyState() };
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return { ok: false, error: `The pin file ${path} is not valid JSON. Fix or delete it; the shield will not run without it.` };
  }
  const parsed = StateSchema.safeParse(json);
  if (!parsed.success) {
    return { ok: false, error: `The pin file ${path} is invalid: ${parsed.error.issues[0]?.message ?? 'unknown problem'}` };
  }
  return { ok: true, state: parsed.data };
}

/** Atomic write: temp file in the same folder, then rename. */
export function saveState(path: string, state: State): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`, 'utf8');
  renameSync(tmp, path);
}

export function serverState(state: State, name: string): ServerState {
  let s = state.servers[name];
  if (!s) {
    s = { tools: {}, pending: {}, unreviewed: {}, approvedHosts: [] };
    state.servers[name] = s;
  }
  return s;
}

export function appendAlert(path: string, alert: Alert): void {
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, `${JSON.stringify(alert)}\n`, 'utf8');
}

export type ApproveResult = { ok: true; message: string } | { ok: false; error: string };

/** Accept the pending (changed or never reviewed) version of a tool and pin it. */
export function approveTool(state: State, server: string, tool: string, now: Date = new Date()): ApproveResult {
  const s = state.servers[server];
  const fresh = s?.unreviewed[tool];
  if (s && fresh) {
    s.tools[tool] = { hash: fresh.hash, description: fresh.description, pinnedAt: now.toISOString() };
    delete s.unreviewed[tool];
    return { ok: true, message: `Approved "${tool}" on "${server}" after review. It is now pinned.` };
  }
  const pending = s?.pending[tool];
  if (!s || !pending) return { ok: false, error: `There is no pending change for "${tool}" on "${server}".` };
  s.tools[tool] = { hash: pending.hash, description: pending.newDescription, pinnedAt: now.toISOString() };
  delete s.pending[tool];
  return { ok: true, message: `Approved the new version of "${tool}" on "${server}".` };
}

export function approveHost(state: State, server: string, host: string): ApproveResult {
  const clean = host.trim().toLowerCase();
  if (!/^(\*\.)?[a-z0-9.-]+$/.test(clean) || clean.length > 253) return { ok: false, error: `"${host}" is not a valid host name.` };
  const s = serverState(state, server);
  if (!s.approvedHosts.includes(clean)) s.approvedHosts.push(clean);
  return { ok: true, message: `"${server}" may now send data to ${clean}.` };
}
