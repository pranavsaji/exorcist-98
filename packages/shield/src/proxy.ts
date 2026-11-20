import { spawn } from 'node:child_process';
import { mkdirSync, statSync } from 'node:fs';
import { loadDefinitions } from '@exorcist-98/core';
import type { Readable, Writable } from 'node:stream';
import { ShieldEngine } from './engine.js';
import type { Action } from './engine.js';
import { LineSplitter } from './jsonrpc.js';
import { loadPolicy } from './policy.js';
import { alertsPath, appendAlert, loadState, policyPath, saveState, statePath, vaultPath } from './state.js';
import type { Alert, State } from './state.js';
import { quarantineServer } from './vault.js';
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
};

export type ShieldContext = {
  engine: ShieldEngine;
  log: (s: string) => void;
  /** Handle every non-forward action (alerts, quarantine). Forwards are returned for the caller to deliver. */
  handle: (actions: Action[]) => Array<{ to: 'server' | 'client'; message: unknown }>;
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

  const engine = new ShieldEngine({ server: o.server, io, policy: policy.policy, defs });
  const notifier = policy.policy.notify ? o.notify : undefined;
  const allowNotice = throttle();
  log(`Protecting "${o.server}". State folder: ${o.dir}`);

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

  return { engine, log, handle, watch };
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
  const prepared = await prepareShield({ ...o, stderr });
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
  child.stdout.on('data', (chunk: Buffer) => { for (const l of fromServer.push(chunk)) run(engine.onServerLine(l)); });
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
      for (const l of fromServer.flush()) run(engine.onServerLine(l));
      resolve(code ?? 1);
    });
  });
}

