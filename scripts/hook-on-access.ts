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
    if (event && typeof event === 'object' && typeof (event as { cwd?: unknown }).cwd === 'string' && (event as { cwd: string }).cwd) {
      cwd = (event as { cwd: string }).cwd;
    }
  } catch {
    return 0; // unreadable JSON: allow
  }

  const defs = await loadDefinitions(defsDir);
  // Per-user allowances for the project the agent works in, kept outside it
  // (a list inside the project is ignored: the project could plant it).
  const allowed = readAllowedReads(cwd);

  const d = decideRead(event, defs, { cwd, allowed });
  if (d.message) process.stderr.write(`${d.message}\n`);
  return d.exitCode;
}
