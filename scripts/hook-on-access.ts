/**
 * Kiro PreToolUse hook for read-like tools: scan the file the agent is about
 * to read and block the read when it hides instructions aimed at the AI (m5).
 * Decision logic lives in packages/core/src/on-access.ts.
 */
import { existsSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDefinitions } from '../packages/core/src/definitions/loader.js';
import { decideRead } from '../packages/core/src/on-access.js';
import { readAllowedReads } from '../packages/core/src/allowed-reads.js';

const chunks: Buffer[] = [];
process.stdin.on('data', (c: Buffer) => chunks.push(c));
process.stdin.on('end', () => {
  void decide(Buffer.concat(chunks).toString('utf8'));
});

async function decide(stdin: string): Promise<void> {
  let exitCode = 0;
  try {
    exitCode = await run(stdin);
  } catch {
    exitCode = 0; // a broken hook must never stop the agent from reading (REQ-01.6)
  }
  process.exit(exitCode);
}

async function run(stdin: string): Promise<0 | 2> {
  const here = dirname(fileURLToPath(import.meta.url));
  const defsDir = [resolve(here, '..', 'definitions'), join(process.cwd(), 'definitions')]
    .find((d) => existsSync(d) && statSync(d).isDirectory()) ?? null;
  if (!defsDir) return 0;

  let cwd = process.cwd();
  let event: unknown = stdin;
  try {
    event = JSON.parse(stdin) as { cwd?: unknown };
    if (event && typeof event === 'object' && typeof (event as { cwd?: unknown }).cwd === 'string') {
      cwd = (event as { cwd: string }).cwd;
    }
  } catch {
    return 0; // unreadable JSON: allow
  }

  const defs = await loadDefinitions(defsDir);
  // The project the agent works in, not the repo the hook lives in.
  let allowed: ReadonlySet<string> = new Set();
  for (const dir of [join(cwd, '.exorcist'), join(process.cwd(), '.exorcist')]) {
    if (existsSync(dir)) {
      allowed = readAllowedReads(dir);
      break;
    }
  }

  const d = decideRead(event, defs, { cwd, allowed });
  if (d.message) process.stderr.write(`${d.message}\n`);
  return d.exitCode;
}
