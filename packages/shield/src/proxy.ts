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
};

const FAIL_CLOSED_EXIT = 78;

/**
 * Run one MCP server behind the shield. Resolves with the exit code.
 * stdout carries only protocol messages; everything else goes to stderr and to
 * alerts.jsonl, and never contains tool arguments or result text.
 */
export async function runProxy(o: ProxyOptions): Promise<number> {
  const stdin = o.stdin ?? process.stdin;
  const stdout = o.stdout ?? process.stdout;
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
  const readMtime = (): number => { try { return statSync(statePath(o.dir)).mtimeMs; } catch { return 0; } };
  mtime = readMtime();
  const io = {
    load: (): State => {
      const m = readMtime();
      if (m !== mtime) {
        const r = loadState(statePath(o.dir));
        if (r.ok) { cached = r.state; mtime = m; }
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

  const child = spawn(o.command, o.args, {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: o.env ?? process.env,
    ...(o.cwd ? { cwd: o.cwd } : {}),
  });

  const recordAlert = (a: Alert): void => {
    log(`${a.severity.toUpperCase()} ${a.ruleId}${a.tool ? ` [${a.tool}]` : ''}: ${a.message}`);
    if (a.detail) log(a.detail.trimEnd().split('\n').map((l) => `    ${l}`).join('\n'));
    try { appendAlert(alertsPath(o.dir), a); } catch { /* the console line above is enough */ }
  };

  const run = (actions: Action[]): void => {
    for (const a of actions) {
      if (a.type === 'forward') {
        const line = `${JSON.stringify(a.message)}\n`;
        if (a.to === 'server') child.stdin.write(line);
        else stdout.write(line);
      } else if (a.type === 'alert') {
        recordAlert(a.alert);
      } else if (o.configPath) {
        const r = quarantineServer({ configPath: o.configPath, serverName: o.server, reason: a.reason, vaultDir: vaultPath(o.dir) });
        log(r.ok ? `Quarantined "${o.server}" (vault entry ${r.value.id}). Restore with: exorcist vault restore ${r.value.id}` : `Could not quarantine: ${r.error}`);
      } else {
        log('Auto-quarantine is on but no --config was given, so nothing was disabled.');
      }
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

  return await new Promise<number>((resolve) => {
    child.on('error', (err) => {
      log(`Could not start "${o.command}": ${err.message}`);
      resolve(127);
    });
    child.on('close', (code) => {
      for (const l of fromServer.flush()) run(engine.onServerLine(l));
      resolve(code ?? 1);
    });
  });
}

