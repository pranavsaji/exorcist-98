import { createHash, randomBytes } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { createTwoFilesPatch } from 'diff';
import { z } from 'zod';

const EntrySchema = z.object({
  id:         z.string(),
  kind:       z.enum(['mcp-server', 'file']),
  target:     z.string(),
  serverName: z.string().optional(),
  reason:     z.string(),
  createdAt:  z.string(),
  sha256:     z.string(),
  status:     z.enum(['quarantined', 'restored']),
});

export type VaultEntry = z.infer<typeof EntrySchema>;
export type VaultResult<T> = { ok: true; value: T } | { ok: false; error: string };

const sha256 = (data: Buffer | string): string => createHash('sha256').update(data).digest('hex');
const fail = (error: string): { ok: false; error: string } => ({ ok: false, error });

function newId(label: string, now: Date): string {
  const stamp = now.toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 30) || 'item';
  return `${stamp}-${slug}-${randomBytes(2).toString('hex')}`;
}

function entryDir(vaultDir: string, id: string): string {
  return join(vaultDir, id);
}

function writeManifest(vaultDir: string, e: VaultEntry): void {
  writeFileSync(join(entryDir(vaultDir, e.id), 'manifest.json'), `${JSON.stringify(e, null, 2)}\n`, 'utf8');
}

export function listEntries(vaultDir: string): VaultEntry[] {
  if (!existsSync(vaultDir)) return [];
  const out: VaultEntry[] = [];
  for (const name of readdirSync(vaultDir)) {
    const file = join(vaultDir, name, 'manifest.json');
    if (!existsSync(file)) continue;
    try {
      const parsed = EntrySchema.safeParse(JSON.parse(readFileSync(file, 'utf8')));
      if (parsed.success) out.push(parsed.data);
    } catch {
      /* skip unreadable manifests */
    }
  }
  return out.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

export function getEntry(vaultDir: string, id: string): VaultEntry | null {
  return listEntries(vaultDir).find((e) => e.id === id) ?? null;
}

function activeFor(vaultDir: string, target: string, serverName?: string): VaultEntry | undefined {
  return listEntries(vaultDir).find(
    (e) => e.status === 'quarantined' && e.target === target && e.serverName === serverName,
  );
}

// ── MCP servers ───────────────────────────────────────────────────────────────

type McpConfig = { mcpServers?: Record<string, Record<string, unknown>> } & Record<string, unknown>;

function readConfig(path: string): VaultResult<McpConfig> {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return fail(`Could not read ${path}.`);
  }
  try {
    const json = JSON.parse(text) as unknown;
    if (!json || typeof json !== 'object' || Array.isArray(json)) return fail(`${path} is not a JSON object.`);
    return { ok: true, value: json as McpConfig };
  } catch {
    return fail(`${path} is not valid JSON.`);
  }
}

const writeConfig = (path: string, cfg: McpConfig): void => writeFileSync(path, `${JSON.stringify(cfg, null, 2)}\n`, 'utf8');

/**
 * Disable one MCP server in a config file (sets `disabled: true`) and keep a
 * backup of its original entry. Other servers and other settings are untouched.
 */
export function quarantineServer(o: {
  configPath: string;
  serverName: string;
  reason: string;
  vaultDir: string;
  now?: Date;
}): VaultResult<VaultEntry> {
  const configPath = resolve(o.configPath);
  const cfg = readConfig(configPath);
  if (!cfg.ok) return cfg;
  const entry = cfg.value.mcpServers?.[o.serverName];
  if (!entry) return fail(`There is no MCP server named "${o.serverName}" in ${configPath}.`);
  if (activeFor(o.vaultDir, configPath, o.serverName)) {
    return fail(`"${o.serverName}" is already in the vault. Restore it first or leave it quarantined.`);
  }

  const now = o.now ?? new Date();
  const id = newId(o.serverName, now);
  const dir = entryDir(o.vaultDir, id);
  mkdirSync(dir, { recursive: true });
  const backup = `${JSON.stringify(entry, null, 2)}\n`;
  writeFileSync(join(dir, 'entry.json'), backup, 'utf8');

  const e: VaultEntry = {
    id, kind: 'mcp-server', target: configPath, serverName: o.serverName,
    reason: o.reason, createdAt: now.toISOString(), sha256: sha256(backup), status: 'quarantined',
  };
  writeManifest(o.vaultDir, e);

  entry['disabled'] = true;
  writeConfig(configPath, cfg.value);
  return { ok: true, value: e };
}

// ── files (hooks, steering, anything) ─────────────────────────────────────────

/** Move a file into the vault. A copy is kept; the original path is emptied. */
export function quarantineFile(o: { filePath: string; reason: string; vaultDir: string; now?: Date }): VaultResult<VaultEntry> {
  const target = resolve(o.filePath);
  if (!existsSync(target) || !statSync(target).isFile()) return fail(`${target} is not a file.`);
  if (activeFor(o.vaultDir, target)) return fail(`${target} is already in the vault.`);

  const now = o.now ?? new Date();
  const id = newId(basename(target), now);
  const dir = entryDir(o.vaultDir, id);
  mkdirSync(join(dir, 'files'), { recursive: true });
  const stored = join(dir, 'files', basename(target));
  copyFileSync(target, stored);
  const digest = sha256(readFileSync(stored));
  if (digest !== sha256(readFileSync(target))) {
    rmSync(dir, { recursive: true, force: true });
    return fail('The backup did not match the original, so nothing was moved.');
  }
  const e: VaultEntry = { id, kind: 'file', target, reason: o.reason, createdAt: now.toISOString(), sha256: digest, status: 'quarantined' };
  writeManifest(o.vaultDir, e);
  rmSync(target);
  return { ok: true, value: e };
}

// ── diff and restore ──────────────────────────────────────────────────────────

function backupFile(vaultDir: string, e: VaultEntry): string {
  return e.kind === 'mcp-server' ? join(entryDir(vaultDir, e.id), 'entry.json') : join(entryDir(vaultDir, e.id), 'files', basename(e.target));
}

/** Unified diff of the backup against the current state of the target. */
export function diffEntry(vaultDir: string, id: string): VaultResult<string> {
  const e = getEntry(vaultDir, id);
  if (!e) return fail(`There is no vault entry "${id}".`);
  const before = readFileSync(backupFile(vaultDir, e), 'utf8');
  let after = '';
  if (e.kind === 'mcp-server') {
    const cfg = readConfig(e.target);
    const now = cfg.ok ? cfg.value.mcpServers?.[e.serverName ?? ''] : undefined;
    after = now ? `${JSON.stringify(now, null, 2)}\n` : '';
  } else if (existsSync(e.target)) {
    after = readFileSync(e.target, 'utf8');
  }
  const label = e.kind === 'mcp-server' ? `${e.serverName} in ${basename(e.target)}` : basename(e.target);
  return { ok: true, value: createTwoFilesPatch(`${label} (backup)`, `${label} (now)`, before, after, '', '', { context: 3 }) };
}

/**
 * Put the original back. For an MCP server only the `disabled` flag is
 * restored, so other edits to the config are kept. A file is restored to its
 * original path unless something different is there now (use `force`).
 */
export function restoreEntry(vaultDir: string, id: string, opts: { force?: boolean } = {}): VaultResult<VaultEntry> {
  const e = getEntry(vaultDir, id);
  if (!e) return fail(`There is no vault entry "${id}".`);
  if (e.status === 'restored') return fail(`"${id}" was already restored.`);

  if (e.kind === 'mcp-server') {
    const cfg = readConfig(e.target);
    if (!cfg.ok) return cfg;
    const original = JSON.parse(readFileSync(backupFile(vaultDir, e), 'utf8')) as Record<string, unknown>;
    const servers = (cfg.value.mcpServers ??= {});
    const current = servers[e.serverName ?? ''];
    if (!current) {
      servers[e.serverName ?? ''] = original;
    } else if ('disabled' in original) {
      current['disabled'] = original['disabled'];
    } else {
      delete current['disabled'];
    }
    writeConfig(e.target, cfg.value);
  } else {
    const stored = backupFile(vaultDir, e);
    if (existsSync(e.target) && sha256(readFileSync(e.target)) !== e.sha256 && !opts.force) {
      return fail(`${e.target} exists and is different from the quarantined file. Use --force to overwrite it.`);
    }
    mkdirSync(resolve(e.target, '..'), { recursive: true });
    copyFileSync(stored, e.target);
  }

  const done: VaultEntry = { ...e, status: 'restored' };
  writeManifest(vaultDir, done);
  return { ok: true, value: done };
}
