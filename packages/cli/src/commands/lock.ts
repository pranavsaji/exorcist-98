/**
 * `exorcist lock`: write and verify exorcist.lock, the committed list of the
 * MCP tools a team approved (m5).
 *
 * Every enabled local server in the MCP config is started and its tools are
 * listed with the MCP SDK client over stdio, bounded by a timeout (20 s by
 * default). Servers marked `disabled` are never started. Remote (http/sse)
 * servers are recorded with their URL and a note; their tools are not
 * listed. `--from-shield` builds the lock from the local Shield pin file
 * without starting anything. `--check` builds the current lock the same way
 * and exits 1 on any difference from the committed one.
 *
 * Tool descriptions are untrusted text: they are hashed and stored as data,
 * and control and invisible characters are escaped before they reach the
 * terminal.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { z } from 'zod';
import {
  buildLock, configLabel, diffLock, launchEntryOf, launchFingerprint, loadState, loaderEnvKeys, lockUrl, parseLock, pinsToLock, serializeLock, statePath, unwrapConfig,
  LOCK_FILE,
} from '@exorcist-98/shield';
import type { Lock, LockChange, LockServer, ServerListing, ToolDef } from '@exorcist-98/shield';
import { parse, stateDir, str } from '../util.js';
import type { Io } from '../util.js';

export const DEFAULT_LOCK_TIMEOUT_MS = 20_000;
const DEFAULT_CONFIG = join('.kiro', 'settings', 'mcp.json');
/** A server that keeps returning a next page is cut off here. */
const MAX_PAGES = 100;

export const LOCK_HELP = `Usage: exorcist lock [options]
       exorcist lock --check [options]
       exorcist lock --from-shield [options]

Write ${LOCK_FILE}, the list of MCP tools your team approved, like a package
lockfile for tool descriptions. Commit it: every teammate's Shield then treats
a tool that differs from the lock as a rug pull, even on a machine that never
saw the tool before. The lock never approves a tool by itself: one that
matches still gets the Shield's first-use checks.

Every local server in the MCP config is started and its tools are listed.
Servers marked "disabled" are never started (their entry in an existing lock
is kept). Remote (http/sse) servers are recorded with their URL and a note.

Options:
  --config <file>   MCP config (default: ${DEFAULT_CONFIG})
  --check           Do not write: compare the servers with the lock and exit 1
                    on any difference (added, removed or changed tool, changed
                    program), with a diff of each changed description
  --static          With --check: start nothing. Compare only the server names,
                    each server's program (command, arguments, argument files)
                    and remote URLs with the lock. Use this in CI on pull
                    requests: the full check starts every server in the config,
                    which a pull request can change to run any command
  --from-shield     Use the local Shield pin file instead of starting servers
  --lock <file>     Lock file to write or check (default: ./${LOCK_FILE})
  --dir <folder>    Shield state folder for --from-shield (default: the
                    project's .exorcist folder, or EXORCIST_DIR)
  --timeout <ms>    Time allowed for each server to list its tools
                    (default: ${DEFAULT_LOCK_TIMEOUT_MS})

Servers that are started get a minimal environment (PATH, HOME, LANG, LC_*,
TMPDIR) plus their own "env" from the config; tokens and keys in your shell
are not passed on.

Exit codes: 0 written or up to date, 1 the lock does not match, 2 error.
`;

// ── the MCP config ───────────────────────────────────────────────────────────

const ConfigSchema = z.object({ mcpServers: z.record(z.unknown()).default({}) }).passthrough();
const EntrySchema = z.object({
  command:  z.string().min(1).optional(),
  args:     z.array(z.string()).default([]),
  env:      z.record(z.string()).optional(),
  cwd:      z.string().optional(),
  url:      z.string().optional(),
  disabled: z.boolean().optional(),
}).passthrough();

type Config = { mcpServers: Record<string, unknown> };

function readConfig(path: string): { ok: true; config: Config } | { ok: false; error: string } {
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return { ok: false, error: `${path} is not valid JSON.` };
  }
  const parsed = ConfigSchema.safeParse(json);
  if (!parsed.success) return { ok: false, error: `${path} is not an MCP config (a JSON object with "mcpServers").` };
  // A config run through "exorcist wrap" starts each server through the
  // Shield; the lock fingerprints the server itself, as the Shield does.
  const { config } = unwrapConfig(parsed.data as never);
  return { ok: true, config: { mcpServers: (config.mcpServers ?? {}) as Record<string, unknown> } };
}

// ── listing one stdio server with the MCP SDK client ─────────────────────────

export type ListResult = { ok: true; tools: ToolDef[] } | { ok: false; error: string };

/** tools/list, kept raw: the Shield fingerprints the JSON the server sent, so the lock must too. */
const RawToolsPage = z.object({ tools: z.array(z.unknown()), nextCursor: z.string().optional() }).passthrough();

const firstLine = (err: unknown): string => (err instanceof Error ? err.message : String(err)).split('\n')[0]?.slice(0, 300) ?? 'unknown error';

/** Start one stdio MCP server, list its tools (all pages) and stop it, within `timeoutMs`. */
export async function listTools(o: {
  command: string;
  args: string[];
  env: Record<string, string>;
  cwd: string;
  timeoutMs: number;
}): Promise<ListResult> {
  const transport = new StdioClientTransport({ command: o.command, args: o.args, env: o.env, cwd: o.cwd, stderr: 'ignore' });
  const client = new Client({ name: 'exorcist-lock', version: '0.1.2' }, { capabilities: {} });
  let timer: NodeJS.Timeout | undefined;
  const timedOut = new Promise<ListResult>((res) => {
    timer = setTimeout(() => res({ ok: false, error: `it did not list its tools within ${o.timeoutMs} ms.` }), o.timeoutMs);
  });
  const work = (async (): Promise<ListResult> => {
    try {
      await client.connect(transport, { timeout: o.timeoutMs });
      const tools: ToolDef[] = [];
      let cursor: string | undefined;
      for (let page = 0; page < MAX_PAGES; page++) {
        const r = await client.request(
          { method: 'tools/list', params: cursor === undefined ? {} : { cursor } },
          RawToolsPage,
          { timeout: o.timeoutMs },
        );
        for (const t of r.tools) {
          if (t !== null && typeof t === 'object' && typeof (t as { name?: unknown }).name === 'string') tools.push(t as ToolDef);
        }
        cursor = r.nextCursor;
        if (cursor === undefined) return { ok: true, tools };
      }
      return { ok: false, error: `it kept returning more pages of tools (over ${MAX_PAGES}).` };
    } catch (err) {
      return { ok: false, error: firstLine(err) };
    }
  })();
  try {
    return await Promise.race([work, timedOut]);
  } finally {
    clearTimeout(timer);
    await client.close().catch(() => undefined); // stops the server process
  }
}

// ── collecting the current lock ──────────────────────────────────────────────

export type CollectResult =
  | { ok: true; listings: ServerListing[]; kept: Array<[string, LockServer]>; notes: string[]; warnings: string[] }
  | { ok: false; errors: string[] };

/** What a started server may inherit from this process: enough to run, nothing that grants access. */
const INHERITED_ENV = /^(PATH|HOME|LANG|LC_[A-Z0-9_]+|TMPDIR|TEMP|TMP|SYSTEMROOT|WINDIR|USERPROFILE|APPDATA|LOCALAPPDATA|PATHEXT|COMSPEC)$/i;
/** Never inherited, even if a pattern above matched: CI credentials, tokens, keys, loader hooks. */
const NEVER_INHERITED_ENV = /^(GITHUB_|ACTIONS_|RUNNER_|AWS_|LD_|DYLD_)|^(NPM_TOKEN|NODE_OPTIONS)$|_(TOKEN|KEY|SECRET)$/i;

/**
 * The environment for a server that `exorcist lock` starts: a minimal set
 * inherited from this process (PATH, HOME, LANG/LC_*, TMPDIR and the Windows
 * equivalents) plus the entry's own `env`, which is the only way to pass
 * anything else. Secrets in this shell or CI (GITHUB_TOKEN, AWS_*, *_TOKEN,
 * *_KEY, *_SECRET, NODE_OPTIONS, LD_ and DYLD_ variables) never reach it
 * unless the entry sets them itself.
 */
export function serverEnv(base: NodeJS.ProcessEnv, entryEnv: Record<string, string> = {}): Record<string, string> {
  const inherited = Object.entries(base).filter((e): e is [string, string] =>
    typeof e[1] === 'string' && INHERITED_ENV.test(e[0]) && !NEVER_INHERITED_ENV.test(e[0]));
  return { ...Object.fromEntries(inherited), ...entryEnv };
}

/**
 * Start every enabled local server and list its tools. Disabled servers are
 * never started: their entry in `previous` (the existing lock) is kept as is.
 *
 * With `static`, nothing is started at all: each local server's program
 * fingerprint is computed from the config (command, arguments, and the
 * contents of argument files, read but never run), and its tools are taken
 * from `previous`. That is the only safe mode for a config someone else
 * controls, such as a pull request in CI.
 */
export async function collectListings(
  config: Config,
  o: { timeoutMs: number; cwd: string; previous?: Lock; list?: typeof listTools; static?: boolean; configPath?: string },
): Promise<CollectResult> {
  const list = o.list ?? listTools;
  const listings: ServerListing[] = [];
  const kept: Array<[string, LockServer]> = [];
  const notes: string[] = [];
  const warnings: string[] = [];
  const errors: string[] = [];
  const jobs: Array<Promise<void>> = [];
  for (const name of Object.keys(config.mcpServers).sort()) {
    const parsed = EntrySchema.safeParse(config.mcpServers[name]);
    if (!parsed.success) { errors.push(`"${name}": the entry is not valid (${parsed.error.issues[0]?.path.join('.') || 'entry'}: ${parsed.error.issues[0]?.message ?? 'invalid'}).`); continue; }
    const entry = parsed.data;
    if (entry.disabled === true) {
      const old = o.previous && Object.hasOwn(o.previous.servers, name) ? o.previous.servers[name] : undefined;
      if (old) kept.push([name, old]);
      notes.push(`${name}: disabled, so it was not started.${old ? ` Its entry in ${LOCK_FILE} was kept as it was.` : ''}`);
      continue;
    }
    if (entry.url !== undefined && entry.command === undefined) {
      const url = lockUrl(entry.url);
      const note = 'remote server: recorded with its URL; its tools are not listed by exorcist lock';
      listings.push({ name, tools: [], url, note });
      notes.push(`${name}: remote server at ${url}, skipped (${note}).`);
      continue;
    }
    if (entry.command === undefined) { errors.push(`"${name}" has neither a "command" nor a "url".`); continue; }
    const command = entry.command;
    // The same view of the entry the Shield pins (env, cwd and which config it is in).
    const launchEntry = launchEntryOf(entry);
    if (!launchEntry.ok) { errors.push(`"${name}": ${launchEntry.error}.`); continue; }
    const pinEntry = { ...launchEntry.entry, ...(o.configPath ? { config: configLabel(o.configPath) } : {}) };
    const loaders = loaderEnvKeys(entry.env);
    if (loaders.length > 0) {
      warnings.push(`HIGH EX-025: "${name}" sets ${loaders.join(', ')} in its env, which changes how its program loads ` +
        '(for example NODE_OPTIONS=--require runs extra code first). Make sure you know why it is there.');
    }
    const cwd = entry.cwd === undefined ? o.cwd : isAbsolute(entry.cwd) ? entry.cwd : resolve(o.cwd, entry.cwd);
    if (o.static) {
      const old = o.previous && Object.hasOwn(o.previous.servers, name) ? o.previous.servers[name] : undefined;
      kept.push([name, { launch: launchFingerprint(command, entry.args, cwd, undefined, pinEntry).hash, tools: old?.tools ?? {} }]);
      continue;
    }
    jobs.push((async () => {
      const r = await list({ command, args: entry.args, env: serverEnv(process.env, entry.env), cwd, timeoutMs: o.timeoutMs });
      if (!r.ok) { errors.push(`Could not list the tools of "${name}": ${r.error}`); return; }
      // The same fingerprint the Shield pins before it starts the server (S-006).
      listings.push({ name, launch: launchFingerprint(command, entry.args, cwd, undefined, pinEntry).hash, tools: r.tools });
    })());
  }
  await Promise.all(jobs);
  if (errors.length > 0) return { ok: false, errors: errors.sort() };
  return { ok: true, listings, kept, notes, warnings: warnings.sort() };
}

/** The lock for the listed servers, plus the entries carried over unchanged (disabled servers). */
function lockFrom(listings: ServerListing[], kept: Array<[string, LockServer]>): Lock {
  const lock = buildLock(listings);
  return { ...lock, servers: Object.fromEntries([...Object.entries(lock.servers), ...kept]) };
}

// ── output ───────────────────────────────────────────────────────────────────

/** Untrusted text made safe for a terminal or a PR comment: control and invisible characters are shown escaped. */
export function printable(s: string): string {
  return s.replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f­؜᠎​-‏‪-‮⁠-⁩﻿]/gu,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function printChanges(io: Io, changes: LockChange[]): void {
  for (const c of changes) {
    io.out(`- ${printable(c.message)}`);
    if (c.detail) io.out(printable(c.detail.trimEnd()).split('\n').map((l) => `    ${l}`).join('\n'));
  }
}

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? '' : 's'}`;

// ── the command ──────────────────────────────────────────────────────────────

export async function lockCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, {
    config: { type: 'string' }, check: { type: 'boolean' }, 'from-shield': { type: 'boolean' },
    lock: { type: 'string' }, dir: { type: 'string' }, timeout: { type: 'string' }, static: { type: 'boolean' },
    help: { type: 'boolean', short: 'h' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${LOCK_HELP}`); return 2; }
  if (p.values['help']) { io.out(LOCK_HELP); return 0; }
  if (p.positionals.length > 0) { io.err(`Unexpected argument: ${p.positionals[0]}\n\n${LOCK_HELP}`); return 2; }

  const timeoutText = str(p.values['timeout']);
  const timeoutMs = timeoutText === undefined ? DEFAULT_LOCK_TIMEOUT_MS : Number(timeoutText);
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) { io.err('--timeout must be a positive whole number of milliseconds.'); return 2; }
  const lockPath = resolve(str(p.values['lock']) ?? LOCK_FILE);
  const checking = p.values['check'] === true;
  const fromShield = p.values['from-shield'] === true;
  const isStatic = p.values['static'] === true;
  if (isStatic && !checking) { io.err('--static only works with --check: a lock is written from the tools the servers list.'); return 2; }
  if (isStatic && fromShield) { io.err('--static and --from-shield cannot be combined.'); return 2; }

  let previous: Lock | undefined;
  if (existsSync(lockPath)) {
    let text: string;
    try { text = readFileSync(lockPath, 'utf8'); } catch (err) { io.err(`Could not read ${lockPath}: ${firstLine(err)}`); return 2; }
    const r = parseLock(text);
    if (r.ok) previous = r.lock;
    else if (checking) { io.err(r.error); return 2; }
    else io.err(`${r.error} It will be replaced.`);
  } else if (checking) {
    io.err(`There is no ${lockPath}. Run "exorcist lock" to create it, then commit it.`);
    return 2;
  }

  let current: Lock;
  const notes: string[] = [];
  if (fromShield) {
    const st = loadState(statePath(stateDir(str(p.values['dir']))));
    if (!st.ok) { io.err(st.error); return 2; }
    current = pinsToLock(st.state);
  } else {
    const configPath = resolve(str(p.values['config']) ?? DEFAULT_CONFIG);
    if (!existsSync(configPath)) { io.err(`MCP config not found: ${configPath}. Pass --config <file>, or --from-shield.`); return 2; }
    const cfg = readConfig(configPath);
    if (!cfg.ok) { io.err(cfg.error); return 2; }
    const r = await collectListings(cfg.config, { timeoutMs, cwd: process.cwd(), static: isStatic, configPath, ...(previous ? { previous } : {}) });
    if (!r.ok) {
      for (const e of r.errors) io.err(printable(e));
      io.err(checking ? `Could not check ${lockPath}.` : `${lockPath} was not written.`);
      return 2;
    }
    current = lockFrom(r.listings, r.kept);
    notes.push(...r.notes);
    for (const w of r.warnings) io.out(printable(w));
    if (isStatic) notes.push('static check: no server was started, so tool descriptions were not compared; server names, programs and URLs were.');
  }
  for (const n of notes) io.out(`  ${printable(n)}`);

  if (checking) {
    const changes = diffLock(previous as Lock, current);
    if (changes.length === 0) {
      io.out(isStatic
        ? `${LOCK_FILE} is up to date: every server and program matches the lock (tools not listed: --static).`
        : `${LOCK_FILE} is up to date: every MCP tool matches its locked fingerprint.`);
      return 0;
    }
    io.out(`${LOCK_FILE} does not match the MCP servers (${plural(changes.length, 'difference')}):`);
    printChanges(io, changes);
    io.out(`If every change is expected, run "exorcist lock" and commit ${LOCK_FILE}. If not, a tool may have been changed under you (a rug pull).`);
    return 1;
  }

  const text = serializeLock(current);
  try { writeFileSync(lockPath, text, 'utf8'); } catch (err) { io.err(`Could not write ${lockPath}: ${firstLine(err)}`); return 2; }
  const servers = Object.values(current.servers);
  const tools = servers.reduce((n, s) => n + Object.keys(s.tools).length, 0);
  const changed = previous ? diffLock(previous, current).length : undefined;
  io.out(`Wrote ${lockPath}: ${plural(servers.length, 'server')}, ${plural(tools, 'locked tool')}` +
    `${changed === undefined ? '' : changed === 0 ? ' (no changes)' : ` (${plural(changed, 'change')})`}.`);
  io.out(`Commit ${LOCK_FILE} so every teammate's Shield, and CI ("exorcist lock --check"), checks the same tools.`);
  return 0;
}
