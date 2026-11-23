/**
 * `exorcist lock`: create, update and verify exorcist.lock, the committed
 * list of approved MCP tools (m5).
 *
 * The lock command starts every local MCP server in the config to list its
 * tools over MCP stdio (a 20 s timeout bounds a server that never answers),
 * never starts a server marked disabled, and skips remote (http/sse) servers
 * with a note. With --from-shield it builds the lock from the local pin file
 * instead, without starting anything. With --check it re-lists and exits 1
 * on any difference.
 */
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, resolve, dirname } from 'node:path';
import { createInterface } from 'node:readline';
import {
  buildLock, diffLock, launchFingerprint, LOCK_FILE, parseLock, pinsToLock, serializeLock, urlFingerprint,
  loadState, statePath,
} from '@exorcist-98/shield';
import type { Lock, LockChange, ServerListing } from '@exorcist-98/shield';
import type { ToolDef } from '@exorcist-98/shield';
import { parse, stateDir, str } from '../util.js';
import type { Io } from '../util.js';

export const LOCK_HELP = `Usage: exorcist lock [options]
       exorcist lock --check [options]
       exorcist lock --from-shield [options]

Write exorcist.lock, the committed list of MCP tools your team approved, like
a package lockfile for tool descriptions. Every server in the MCP config is
started, its tools listed, and each tool's fingerprint pinned. Remote (http
and sse) servers are listed with their URL and skipped with a note.

Options:
  --config <file>       MCP config (default: .kiro/settings/mcp.json)
  --from-shield         Build the lock from the local Shield pin file, without
                        starting any server
  --check               Re-list the tools and exit 1 on any difference
  --out <file>          Lock file to write or check (default: ${LOCK_FILE})
  --dir <folder>        State folder for --from-shield (default: the project's
                        .exorcist folder, or EXORCIST_DIR)
  --timeout <ms>        Per-server listing timeout (default: 20000)
`;

const DEFAULT_TIMEOUT_MS = 20_000;

type McpEntry = Record<string, unknown>;

function readConfig(path: string, io: Io): { mcpServers: Record<string, McpEntry> } | null {
  if (!existsSync(path)) { io.err(`MCP config not found: ${path}`); return null; }
  try {
    const json = JSON.parse(readFileSync(path, 'utf8')) as unknown;
    if (!json || typeof json !== 'object' || Array.isArray(json)) throw new Error('not an object');
    const servers = (json as { mcpServers?: unknown }).mcpServers;
    if (servers !== undefined && (typeof servers !== 'object' || servers === null || Array.isArray(servers))) throw new Error('mcpServers is not an object');
    return { mcpServers: (servers ?? {}) as Record<string, McpEntry> };
  } catch {
    io.err(`${path} is not a valid MCP config (a JSON object with mcpServers).`);
    return null;
  }
}

// ── listing one stdio server ─────────────────────────────────────────────────

type ListResult = { ok: true; tools: ToolDef[] } | { ok: false; error: string };

/**
 * A minimal MCP stdio client: initialize, then tools/list (with pagination).
 * The server's descriptions and schemas are treated as data only; they are
 * hashed, never followed.
 */
export function listTools(o: {
  command: string;
  args: string[];
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  timeoutMs: number;
}): Promise<ListResult> {
  return new Promise<ListResult>((resolveP) => {
    let settled = false;
    const finish = (r: ListResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (child) child.kill();
      resolveP(r);
    };
    const fail = (error: string): void => finish({ ok: false, error });

    let child: ReturnType<typeof spawn> | null = null;
    try {
      child = spawn(o.command, o.args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: o.env ?? process.env,
        ...(o.cwd ? { cwd: o.cwd } : {}),
      });
    } catch (err) {
      resolveP({ ok: false, error: String(err).split('\n')[0] ?? 'could not start' });
      return;
    }
    const { stdin, stdout, stderr } = child;
    if (!stdin || !stdout || !stderr) {
      resolveP({ ok: false, error: `Could not open pipes to "${o.command}".` });
      return;
    }

    const timer = setTimeout(() => fail(`The server did not answer within ${o.timeoutMs} ms.`), o.timeoutMs);
    const send = (m: unknown): void => { if (!stdin.destroyed) stdin.write(`${JSON.stringify(m)}\n`); };

    let nextId = 1;
    const waiting = new Map<number, (value: { tools: ToolDef[]; nextCursor?: string } | { error: string }) => void>();
    const call = (method: string, params: unknown): Promise<{ tools: ToolDef[]; nextCursor?: string } | { error: string }> =>
      new Promise((res) => {
        const id = nextId++;
        waiting.set(id, res);
        send({ jsonrpc: '2.0', id, method, params });
      });
    const rl = createInterface({ input: stdout });
    const lineHandler = (line: string): void => {
      if (settled) return;
      let msg: { id?: unknown; result?: unknown; error?: unknown } | null = null;
      try { msg = JSON.parse(line); } catch { return; }
      if (!msg || msg.id === undefined) return;
      if (typeof msg.id !== 'number') return;
      const waiter = waiting.get(msg.id);
      if (!waiter) return;
      waiting.delete(msg.id);
      if (msg.error !== undefined) waiter({ error: String((msg.error as { message?: unknown }).message ?? 'the server returned an error') });
      else {
        const r = (msg.result ?? {}) as { tools?: unknown; nextCursor?: unknown };
        const tools = Array.isArray(r.tools)
          ? r.tools.filter((t): t is ToolDef => t !== null && typeof t === 'object' && typeof (t as ToolDef).name === 'string')
          : [];
        waiter({ tools, ...(typeof r.nextCursor === 'string' ? { nextCursor: r.nextCursor } : {}) });
      }
    };
    rl.on('line', lineHandler);
    stderr.on('data', () => { /* the server's own logs are not ours to show */ });
    child.on('error', (err) => fail(`Could not start "${o.command}": ${err.message}`));
    child.on('close', (code) => { if (!settled) fail(`The server exited early (code ${code ?? 'null'}).`); });

    void (async () => {
      const init = await new Promise<boolean>((res) => {
        const id = nextId++;
        waiting.set(id, () => res(true));
        send({
          jsonrpc: '2.0', id, method: 'initialize',
          params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'exorcist-lock', version: '0.1.0' } },
        });
      });
      if (!settled && !init) { fail('The server did not answer initialize.'); return; }
      send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      const all: ToolDef[] = [];
      let cursor: string | undefined;
      let pages = 0;
      do {
        const page = await call('tools/list', cursor === undefined ? {} : { cursor });
        if ('error' in page) { fail(page.error); return; }
        all.push(...page.tools);
        cursor = page.nextCursor;
        pages += 1;
      } while (cursor !== undefined && pages < 10);
      finish({ ok: true, tools: all });
    })().catch((err: unknown) => fail(String(err).split('\n')[0] ?? 'listing failed'));
  });
}

// ── collecting listings from a config ─────────────────────────────────────────

export type CollectResult = { ok: true; listings: ServerListing[] } | { ok: false; error: string };

/** Start every enabled local server and list its tools; note the remote ones. */
export async function collectListings(
  cfg: { mcpServers: Record<string, McpEntry> },
  configDir: string,
  timeoutMs: number,
): Promise<CollectResult> {
  const listings: ServerListing[] = [];
  const failures: string[] = [];
  for (const [name, entry] of Object.entries(cfg.mcpServers)) {
    if (entry['disabled'] === true) {
      listings.push({ name, launch: urlFingerprint(`disabled:${name}`), tools: [], note: 'skipped: this server is disabled (in the vault).' });
      continue;
    }
    const url = typeof entry['url'] === 'string' ? entry['url'] : undefined;
    if (url) {
      listings.push({
        name, launch: urlFingerprint(url), tools: [], url,
        note: `remote server; listed with its URL (${url}) and skipped: the lock does not pin remote tools.`,
      });
      continue;
    }
    const command = entry['command'];
    if (typeof command !== 'string') {
      failures.push(`"${name}" has neither a command nor a URL; the lock does not know what it is.`);
      continue;
    }
    const args = Array.isArray(entry['args']) && entry['args'].every((a) => typeof a === 'string') ? (entry['args'] as string[]) : [];
    const entryEnv = entry['env'];
    const env = entryEnv && typeof entryEnv === 'object' && !Array.isArray(entryEnv)
      ? { ...process.env, ...(entryEnv as Record<string, string>) }
      : process.env;
    const cwd = typeof entry['cwd'] === 'string'
      ? (isAbsolute(entry['cwd']) ? entry['cwd'] : resolve(configDir, entry['cwd']))
      : process.cwd();
    const r = await listTools({ command, args, env, ...(cwd ? { cwd } : {}), timeoutMs });
    if (!r.ok) { failures.push(`Could not list "${name}": ${r.error}`); continue; }
    listings.push({ name, launch: launchFingerprint(command, args, cwd).hash, tools: r.tools });
  }
  if (failures.length > 0) return { ok: false, error: failures.join('\n') };
  return { ok: true, listings };
}

function printChanges(io: Io, changes: LockChange[]): void {
  for (const c of changes) {
    io.out(`${c.server}${c.tool ? `: tool "${c.tool}"` : ''} ${c.message}`);
    if (c.detail) io.out(c.detail.trimEnd().split('\n').map((l) => `    ${l}`).join('\n'));
  }
}

/** Build the current lock: from live servers, or from the Shield pin file. */
async function currentLock(o: { cfg: { mcpServers: Record<string, McpEntry> } | null; configDir: string; fromShield: boolean; dir: string; timeoutMs: number; io: Io }): Promise<{ lock: Lock } | { error: string; code: number }> {
  if (o.fromShield) {
    const r = loadState(statePath(o.dir));
    if (!r.ok) return { error: r.error, code: 2 };
    return { lock: pinsToLock(r.state) };
  }
  if (!o.cfg) return { error: 'There is no MCP config to list servers from; pass --config <file>.', code: 2 };
  const r = await collectListings(o.cfg, o.configDir, o.timeoutMs);
  if (!r.ok) return { error: r.error, code: 1 };
  return { lock: buildLock(r.listings) };
}

export async function lockCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, {
    config: { type: 'string' }, 'from-shield': { type: 'boolean' }, check: { type: 'boolean' },
    out: { type: 'string' }, dir: { type: 'string' }, timeout: { type: 'string' },
    help: { type: 'boolean', short: 'h' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${LOCK_HELP}`); return 2; }
  if (p.values['help']) { io.out(LOCK_HELP); return 0; }

  const timeoutMs = Number(str(p.values['timeout']) ?? DEFAULT_TIMEOUT_MS);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) { io.err('--timeout must be a positive number of milliseconds.'); return 2; }
  const outPath = resolve(str(p.values['out']) ?? LOCK_FILE);
  const configArg = str(p.values['config']);
  const configPath = resolve(configArg ?? join('.kiro', 'settings', 'mcp.json'));
  const cfg = existsSync(configPath) ? readConfig(configPath, io) : null;
  if (configArg && !cfg) return 2;

  const built = await currentLock({
    cfg, configDir: dirname(configPath),
    fromShield: p.values['from-shield'] === true,
    dir: stateDir(str(p.values['dir'])),
    timeoutMs, io,
  });
  if ('error' in built) { io.err(built.error); return built.code; }
  const fresh = built.lock;

  if (p.values['check']) {
    if (!existsSync(outPath)) { io.err(`No ${outPath}. Run "exorcist lock" first to create one.`); return 2; }
    const old = parseLock(readFileSync(outPath, 'utf8'));
    if (!old.ok) { io.err(old.error); return 2; }
    const changes = diffLock(old.lock, fresh);
    if (changes.length === 0) { io.out(`${outPath} is up to date: every tool matches its locked fingerprint.`); return 0; }
    io.out(`${outPath} does not match the MCP servers (${changes.length} difference${changes.length === 1 ? '' : 's'}):`);
    printChanges(io, changes);
    io.out('Review the changes, then run "exorcist lock" to record them (or revert the server).');
    return 1;
  }

  const text = serializeLock(fresh);
  writeFileSync(outPath, text, 'utf8');
  const servers = Object.keys(fresh.servers).sort();
  const tools = servers.reduce((n, s) => n + Object.keys(fresh.servers[s]!.tools).length, 0);
  const skipped = servers.filter((s) => fresh.servers[s]!.note !== undefined);
  io.out(`Wrote ${outPath}: ${servers.length} server${servers.length === 1 ? '' : 's'}, ${tools} pinned tool${tools === 1 ? '' : 's'}.`);
  for (const s of skipped) io.out(`  ${s}: ${fresh.servers[s]!.note}`);
  io.out('Commit exorcist.lock so your whole team, and CI, verifies the same tool fingerprints.');
  return 0;
}
