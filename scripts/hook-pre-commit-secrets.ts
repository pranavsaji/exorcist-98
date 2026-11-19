/**
 * Kiro PreToolUse hook for shell commands. Reads the hook event from stdin and
 * blocks `git commit` while secrets are staged. Logic lives in
 * packages/core/src/hook-guard.ts.
 */
import { decide } from '../packages/core/src/hook-guard.js';

const chunks: Buffer[] = [];
process.stdin.on('data', (c: Buffer) => chunks.push(c));
process.stdin.on('end', () => {
  const d = decide(Buffer.concat(chunks).toString('utf8'));
  if (d.message) process.stderr.write(`${d.message}\n`);
  process.exit(d.exitCode);
});
