import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { loadDefinitions } from '@exorcist-98/core';
import type { Readable, Writable } from 'node:stream';
import { ShieldEngine } from './engine.js';
import type { Action } from './engine.js';
import { LineSplitter } from './jsonrpc.js';
import { loadPolicy } from './policy.js';
import { loadCanariesFile } from '@exorcist-98/core';
import { canariesFileFor } from './canary.js';
import { dirname } from 'node:path';
import { findLockFile, parseLock, seedFromLock } from './lockfile.js';
import type { LockExpectations } from './lockfile.js';
import { alertsPath, appendAlert, loadState, policyPath, saveState, serverState, statePath, vaultPath } from './state.js';
import type { Alert, ServerState, State } from './state.js';
import { quarantineServer } from './vault.js';
import { checkLaunch, configLabel, launchEntryOf, launchFingerprint, loaderEnvKeys, packageSpec, specIsPinned } from './launch.js';
import type { LaunchCheck, LaunchEntry, LaunchEntryResult, LaunchPin } from './launch.js';
import { AiReview } from './ai-review.js';
import type { AiJudge } from './ai-review.js';
import { throttle } from './notify.js';
import type { Notifier } from './notify.js';

export type ProxyOptions = {
  server: string;
  command: string;
  args: string[];
  /** State folder (pins.json, policy.json, alerts.jsonl, vault/). */
  dir: string;
  definitionsDir: string;
  /** MCP config that holds this server, so it can be quarantined. */
  configPath?: string;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  stdin?: Readable;
  stdout?: Writable;
  stderr?: Writable;
  /** How often to check the pin file for approvals (ms). */
  pollMs?: number;
  /** Shows desktop notifications for critical and high alerts, unless the policy sets `notify: false`. */
  notify?: Notifier;
  /** The AI judge for `aiReview: true`; defaults to Amazon Bedrock. Tests pass a fake. */
  aiJudge?: AiJudge;
  /**
   * exorcist.lock to seed pins from (m5). Default: the nearest exorcist.lock
   * at or above the MCP config's folder or the current folder, up to the
   * project root. `null` turns lock seeding off.
   */
  lockPath?: string | null;
};

export const FAIL_CLOSED_EXIT = 78;

/** What both proxies (local stdio and remote HTTP) need: policy, pins, definitions, alerts. */
export type ShieldSetupOptions = {
  server: string;
  dir: string;
  definitionsDir: string;
  configPath?: string;
  stderr?: Writable;
  pollMs?: number;
  notify?: Notifier;
  /** The local server's program, pinned before it starts (S-006). Remote servers have none. */
  launch?: { command: string; args: string[]; cwd: string; env?: NodeJS.ProcessEnv };
  /** The AI judge for `aiReview: true`; defaults to Amazon Bedrock. Tests pass a fake. */
  aiJudge?: AiJudge;
  /**
   * exorcist.lock to seed pins from (m5). Default: the nearest exorcist.lock
   * at or above the MCP config's folder or the current folder, up to the
   * project root. `null` turns lock seeding off.
   */
  lockPath?: string | null;
};

export type ShieldContext = {
  engine: ShieldEngine;
  log: (s: string) => void;
  /** Handle every non-forward action (alerts, quarantine). Forwards are returned for the caller to deliver. */
  handle: (actions: Action[]) => Array<{ to: 'server' | 'client'; message: unknown }>;
  /**
   * With AI review on, await this for every server line before the engine
   * sees it, in order: it judges new tool descriptions first (S-009).
   */
  prepareServerLine?: (line: string) => Promise<void>;
  /** Start watching the pin file for approvals; returns a stop function. */
  watch: (deliver: (actions: Action[]) => void) => () => void;
};

/** Load and check everything the Shield needs; a number is a fail-closed exit code. */
export async function prepareShield(o: ShieldSetupOptions): Promise<ShieldContext | number> {
  const stderr = o.stderr ?? process.stderr;
  const log = (s: string): void => void stderr.write(`[exorcist] ${s}\n`);

  // Fail closed: never run unprotected because the safety files are unreadable.
  mkdirSync(o.dir, { recursive: true });
  const policy = loadPolicy(policyPath(o.dir));
  if (!policy.ok) { log(policy.error); return FAIL_CLOSED_EXIT; }
  const first = loadState(statePath(o.dir));
  if (!first.ok) { log(first.error); return FAIL_CLOSED_EXIT; }
  let defs;
  try {
    defs = await loadDefinitions(o.definitionsDir);
  } catch (err) {
    log(`Could not load the virus definitions from ${o.definitionsDir}: ${String(err).split('\n')[0]}`);
    return FAIL_CLOSED_EXIT;
  }
  if (defs.length === 0) {
    log(`No virus definitions were found in ${o.definitionsDir}. The shield will not run without them.`);
    return FAIL_CLOSED_EXIT;
  }

  // EX-022: the canary records, from the policy's `canaries` path (relative
  // to the state folder) or `<state folder>/canaries.json`, which is where
  // `exorcist canary plant` writes them (the state folder is the project's
  // `.exorcist` by default). An unreadable records file fails closed, like
  // the policy: the traps would silently stop working otherwise.
  const canariesAt = canariesFileFor(o.dir, policy.policy.canaries);
  const canariesFile = loadCanariesFile(canariesAt);
  if (!canariesFile.ok) { log(canariesFile.error); return FAIL_CLOSED_EXIT; }
  if (policy.policy.canaries && !existsSync(canariesAt)) log(`The policy names canary records at ${canariesAt}, but there is no such file; no canary traps are active.`);
  const canaries = canariesFile.canaries.map((r) => ({ token: r.token, file: r.file }));
  if (canaries.length > 0) log(`Watching for ${canaries.length} canary token${canaries.length === 1 ? '' : 's'} (EX-022).`);

  // exorcist.lock (m5): the team's record of the tools it approved. It is a
  // file from the project folder (untrusted), so it never approves anything
  // here: it is not written into the pins. Its fingerprints only make drift
  // visible on a machine that never pinned the tool: a tool or program that
  // differs from the lock is treated as a rug pull. A tool that matches goes
  // through the normal first-use checks (signatures, AI review, review hold).
  let lockExpected: LockExpectations | undefined;
  let lockLaunch: string | undefined;
  const lockFile = o.lockPath === undefined
    ? findLockFile([...(o.configPath ? [dirname(o.configPath)] : []), process.cwd()])
    : o.lockPath;
  if (lockFile && existsSync(lockFile)) {
    let text: string | undefined;
    try { text = readFileSync(lockFile, 'utf8'); } catch { log(`Could not read ${lockFile}; running with the local pins only.`); }
    const parsed = text === undefined ? undefined : parseLock(text);
    if (parsed && !parsed.ok) log(`Not using ${lockFile}: ${parsed.error} Running with the local pins only.`);
    const ls = parsed?.ok && Object.hasOwn(parsed.lock.servers, o.server) ? parsed.lock.servers[o.server] : undefined;
    if (ls) {
      const r = seedFromLock(serverState(first.state, o.server), ls, log, { server: o.server, withLaunch: o.launch !== undefined && policy.policy.launchPin !== 'off' });
      lockExpected = r.expected;
      lockLaunch = r.launch;
      const n = Object.keys(r.expected).length;
      log(`Checking "${o.server}" against ${lockFile} (${n} locked tool${n === 1 ? '' : 's'}${lockLaunch ? ' and the program' : ''}).`);
    }
  }

  const launchAlerts: Alert[] = [];
  if (o.launch && policy.policy.launchPin !== 'off') {
    const { command, args, cwd } = o.launch;
    const s = serverState(first.state, o.server);
    const blocking = policy.policy.launchPin === 'block' && policy.policy.mode === 'enforce';
    /** Raise EX-010; returns the exit code when the policy holds the server. */
    const hold = (problem: string, advice: string, detail?: string): number | undefined => {
      launchAlerts.push({
        time: new Date().toISOString(), server: o.server, ruleId: 'EX-010', severity: 'high',
        message: `${problem} ${blocking ? 'It was not started.' : 'It was started anyway (policy).'} ${advice}`,
        ...(detail ? { detail } : {}),
      });
      if (!blocking) return undefined;
      for (const a of launchAlerts) recordLaunchAlert(a);
      return FAIL_CLOSED_EXIT;
    };

    // The entry's env and cwd, from the MCP config this Shield was given.
    // Fail closed: a config that cannot be read, or that does not hold this
    // server, means the pin cannot cover what the program really gets.
    const entry: LaunchEntry = {};
    if (o.configPath) {
      const r = readConfigEntry(o.configPath, o.server);
      if (!r.ok) {
        const code = hold(`Could not check the program behind "${o.server}": ${r.error} (${o.configPath}).`, 'Fix the MCP config, then restart the server.');
        if (code !== undefined) return code;
      } else {
        Object.assign(entry, r.entry, { config: configLabel(o.configPath) });
      }
    }
    // What the program really inherits, by whatever route it got there: a
    // loader variable in this process's environment (NODE_OPTIONS would also
    // change how this Node-based Shield runs) or in the child's.
    const childEnv = o.launch.env ?? process.env;
    const loaders = [...new Set([...loaderEnvKeys(process.env), ...loaderEnvKeys(childEnv)])].sort();
    if (loaders.length > 0) {
      const code = hold(
        `The environment of "${o.server}" sets ${loaders.join(', ')}, which changes how programs load (EX-025): it can run code of its choosing ` +
        `before the server${loaders.some((k) => /^NODE_OPTIONS$/i.test(k)) ? ', and before this Shield,' : ''} starts.`,
        `Remove ${loaders.length === 1 ? 'it' : 'them'} from the environment and from the server's "env" in the MCP config, or set "launchPin": "warn" in the policy to start anyway.`,
      );
      if (code !== undefined) return code;
      entry.inherited = Object.fromEntries(loaders.map((k) => [k, childEnv[k] ?? process.env[k] ?? '']));
    }

    const live = launchFingerprint(command, args, cwd, undefined, entry);
    // Never pinned here, and not the program recorded in exorcist.lock: hold
    // it as a changed program, so `exorcist approve server` is the way in.
    const check = !s.launch && lockLaunch !== undefined && live.hash !== lockLaunch
      ? holdAgainstLock(s, live, lockLaunch)
      : checkLaunch(s, live);
    if (check.result !== 'same') {
      try { saveState(statePath(o.dir), first.state); } catch (err) { log(`Could not save the pin file: ${String(err)}`); return FAIL_CLOSED_EXIT; }
    }
    if (check.result === 'pinned') log(`Pinned the program behind "${o.server}".`);
    if (check.result === 'changed') {
      const code = hold(
        `The program behind "${o.server}" changed since it was ${s.launch ? 'pinned' : 'recorded in exorcist.lock'}.`,
        `Check the change, then run: exorcist approve server ${o.server}`,
        [...check.removed.map((l) => `- ${l}`), ...check.added.map((l) => `+ ${l}`)].join('\n'),
      );
      if (code !== undefined) return code;
    }
    const spec = packageSpec(command, args);
    if (spec && !specIsPinned(spec)) {
      launchAlerts.push({
        time: new Date().toISOString(), server: o.server, ruleId: 'EX-010', severity: 'medium',
        message: `"${o.server}" runs the package ${spec} without a fixed version, so a new release would run without review. Pin it, for example ${spec.replace(/@[^@/]*$/, '')}@1.2.3.`,
      });
    }
  }
  function recordLaunchAlert(a: Alert): void {
    log(`${a.severity.toUpperCase()} ${a.ruleId}: ${a.message}`);
    if (a.detail) log(a.detail.split('\n').map((l) => `    ${l}`).join('\n'));
    try { appendAlert(alertsPath(o.dir), a); } catch { /* the console line above is enough */ }
    if (o.notify && policy.ok && policy.policy.notify && a.severity === 'high') o.notify(`Exorcist 98: warning (${o.server})`, a.message);
  }
  // State is re-read when the file changes, so `exorcist approve` takes effect
  // without restarting the proxy.
  let cached: State = first.state;
  let mtime = 0;
  let dirty = false; // the pin file was re-read since the last approval check
  const readMtime = (): number => { try { return statSync(statePath(o.dir)).mtimeMs; } catch { return 0; } };
  mtime = readMtime();
  const io = {
    load: (): State => {
      const m = readMtime();
      if (m !== mtime) {
        const r = loadState(statePath(o.dir));
        if (r.ok) { cached = r.state; mtime = m; dirty = true; }
        else log(`${r.error} Using the last good copy.`);
      }
      return cached;
    },
    save: (s: State): void => {
      cached = s;
      saveState(statePath(o.dir), s);
      mtime = readMtime();
    },
  };

  let review: AiReview | undefined;
  if (policy.policy.aiReview) {
    const judge = o.aiJudge ?? await bedrockJudge();
    if (typeof judge === 'string') log(`AI review is on in the policy, but ${judge}. The signature checks still run.`);
    else review = new AiReview(judge, { log });
  }
  const engine = new ShieldEngine({
    server: o.server, io, policy: policy.policy, defs,
    ...(canaries.length > 0 ? { canaries } : {}),
    ...(lockExpected ? { expected: lockExpected } : {}),
    ...(review ? { aiFindings: (fp: string) => (review as AiReview).findings(fp) } : {}),
  });
  const notifier = policy.policy.notify ? o.notify : undefined;
  const allowNotice = throttle();
  log(`Protecting "${o.server}". State folder: ${o.dir}`);
  for (const a of launchAlerts) recordLaunchAlert(a);

  const recordAlert = (a: Alert): void => {
    log(`${a.severity.toUpperCase()} ${a.ruleId}${a.tool ? ` [${a.tool}]` : ''}: ${a.message}`);
    if (notifier && (a.severity === 'critical' || a.severity === 'high') && allowNotice(`${a.ruleId}:${a.tool ?? ''}`)) {
      notifier(`Exorcist 98: ${a.severity === 'critical' ? 'threat blocked' : 'warning'} (${o.server})`, a.message);
    }
    if (a.detail) log(a.detail.trimEnd().split('\n').map((l) => `    ${l}`).join('\n'));
    try { appendAlert(alertsPath(o.dir), a); } catch { /* the console line above is enough */ }
  };

  const handle = (actions: Action[]): Array<{ to: 'server' | 'client'; message: unknown }> => {
    const out: Array<{ to: 'server' | 'client'; message: unknown }> = [];
    for (const a of actions) {
      if (a.type === 'forward') out.push({ to: a.to, message: a.message });
      else if (a.type === 'log') log(a.text);
      else if (a.type === 'alert') recordAlert(a.alert);
      else if (o.configPath) {
        const r = quarantineServer({ configPath: o.configPath, serverName: o.server, reason: a.reason, vaultDir: vaultPath(o.dir) });
        log(r.ok ? `Quarantined "${o.server}" (vault entry ${r.value.id}). Restore with: exorcist vault restore ${r.value.id}` : `Could not quarantine: ${r.error}`);
      } else {
        log('Auto-quarantine is on but no --config was given, so nothing was disabled.');
      }
    }
    return out;
  };

  // Notice approvals made from the command line while the agent is idle, so a
  // re-approved tool comes back without a reconnect.
  const watch = (deliver: (actions: Action[]) => void): (() => void) => {
    const t = setInterval(() => {
      if (dirty || readMtime() !== mtime) {
        dirty = false;
        deliver(engine.onStateChanged());
      }
    }, o.pollMs ?? 1000);
    t.unref();
    return () => clearInterval(t);
  };

  const prepareServerLine = review
    ? (line: string): Promise<void> => (review as AiReview).prepare(line, (name) => Boolean(io.load().servers[o.server]?.tools[name]))
    : undefined;
  return { engine, log, handle, watch, ...(prepareServerLine ? { prepareServerLine } : {}) };
}

/**
 * The `env` and `cwd` this server's entry sets in the MCP config, for the
 * launch pin. The MCP client applies them to this process, so only the config
 * says which variables are the entry's own. Fail closed: unreadable JSON, a
 * config without this server, or an env value that is not text is an error.
 */
function readConfigEntry(configPath: string, server: string): LaunchEntryResult {
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(configPath, 'utf8'));
  } catch {
    return { ok: false, error: 'the MCP config could not be read as JSON' };
  }
  const servers = json !== null && typeof json === 'object' ? (json as { mcpServers?: unknown }).mcpServers : undefined;
  if (servers === null || typeof servers !== 'object' || !Object.hasOwn(servers, server)) return { ok: false, error: 'the server is not in the MCP config' };
  const r = launchEntryOf((servers as Record<string, unknown>)[server]);
  return r.ok ? r : { ok: false, error: `its entry in the MCP config is not valid: ${r.error}` };
}

/** A program never pinned here that differs from exorcist.lock: held like a changed program (m5). */
function holdAgainstLock(s: ServerState, live: LaunchPin, locked: string): LaunchCheck {
  s.pendingLaunch = { hash: live.hash, parts: live.parts, seenAt: new Date().toISOString() };
  return { result: 'changed', removed: [`recorded in exorcist.lock: launch ${locked.slice(0, 12)}`], added: live.parts };
}

/** The AI judge on Amazon Bedrock, or the reason it cannot run. */
async function bedrockJudge(): Promise<AiJudge | string> {
  if (!process.env['AWS_REGION'] && !process.env['AWS_DEFAULT_REGION']) return 'AWS_REGION is not set';
  let llm: typeof import('@exorcist-98/core/llm');
  try {
    llm = await import('@exorcist-98/core/llm');
  } catch {
    return 'the AI judge could not be loaded';
  }
  const client = new llm.BedrockClientImpl();
  return async (text, label) => {
    let failed: string | undefined;
    const watched = {
      call: async (p: Parameters<typeof client.call>[0]) => {
        const r = await client.call(p);
        if (!r.ok) failed = r.error;
        return r;
      },
    };
    const v = await llm.judgeText(text, label, watched);
    if (failed) throw new Error(failed.split('\n')[0]?.slice(0, 200) ?? 'the model call failed');
    return v ? { verdict: v.verdict, threatClass: v.threatClass, span: v.span } : null;
  };
}
/**
 * Run one MCP server behind the shield. Resolves with the exit code.
 * stdout carries only protocol messages; everything else goes to stderr and to
 * alerts.jsonl, and never contains tool arguments or result text.
 */
export async function runProxy(o: ProxyOptions): Promise<number> {
  const stdin = o.stdin ?? process.stdin;
  const stdout = o.stdout ?? process.stdout;
  const stderr = o.stderr ?? process.stderr;
  const prepared = await prepareShield({ ...o, stderr, launch: { command: o.command, args: o.args, cwd: o.cwd ?? process.cwd(), env: o.env ?? process.env } });
  if (typeof prepared === 'number') return prepared;
  const { engine, log, handle } = prepared;

  const child = spawn(o.command, o.args, {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: o.env ?? process.env,
    ...(o.cwd ? { cwd: o.cwd } : {}),
  });


  const run = (actions: Action[]): void => {
    for (const f of handle(actions)) {
      const line = `${JSON.stringify(f.message)}\n`;
      if (f.to === 'server') child.stdin.write(line);
      else stdout.write(line);
    }
  };

  const fromClient = new LineSplitter();
  const fromServer = new LineSplitter();

  stdin.on('data', (chunk: Buffer) => { for (const l of fromClient.push(chunk)) run(engine.onClientLine(l)); });
  stdin.on('end', () => {
    for (const l of fromClient.flush()) run(engine.onClientLine(l));
    child.stdin.end();
  });
  // With AI review on, server lines wait in order while new tool descriptions are judged.
  let serverQueue: Promise<void> = Promise.resolve();
  const prep = prepared.prepareServerLine;
  const fromServerLine = (l: string): void => {
    if (!prep) { run(engine.onServerLine(l)); return; }
    serverQueue = serverQueue.then(() => prep(l)).catch(() => undefined).then(() => run(engine.onServerLine(l)));
  };
  child.stdout.on('data', (chunk: Buffer) => { for (const l of fromServer.push(chunk)) fromServerLine(l); });
  child.stderr.on('data', (chunk: Buffer) => void stderr.write(chunk));
  child.stdin.on('error', () => { /* the child went away; its exit is handled below */ });

  const stopWatch = prepared.watch(run);

  return await new Promise<number>((resolve) => {
    child.on('error', (err) => {
      stopWatch();
      log(`Could not start "${o.command}": ${err.message}`);
      resolve(127);
    });
    child.on('close', (code) => {
      stopWatch();
      for (const l of fromServer.flush()) fromServerLine(l);
      void serverQueue.then(() => resolve(code ?? 1));
    });
  });
}

