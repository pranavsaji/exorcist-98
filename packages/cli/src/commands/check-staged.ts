import { findStagedCanaries, findStagedSecrets } from '@exorcist-98/core';
import type { Io } from '../util.js';

/**
 * Git pre-commit helper: refuse to commit staged secrets and canary tokens.
 * Unlike the Kiro hook this runs for every commit, whoever or whatever makes
 * it. Exit 0: clean. 1: something is staged that must not leave. 2: could not
 * read the staged files (a pre-commit hook treats any non-zero exit as "do
 * not commit").
 */
export async function checkStagedCommand(io: Io): Promise<number> {
  const r = findStagedSecrets(process.cwd());
  if (!r.ok) {
    io.err(`Exorcist 98: ${r.error}`);
    return 2;
  }
  const c = findStagedCanaries(process.cwd());
  if (!c.ok) {
    io.err(`Exorcist 98: ${c.error}`);
    return 2;
  }

  if (r.hits.length === 0 && c.hits.length === 0) return 0;

  if (r.hits.length > 0) {
    io.err(`Exorcist 98 blocked this commit: ${r.hits.length} possible secret(s) are staged.`);
    for (const h of r.hits) io.err(`  ${h.file}:${h.line}  ${h.pattern}  ${h.redacted}`);
    io.err('Remove them (use an environment variable or a secrets manager), unstage the file, then commit again.');
  }
  if (c.hits.length > 0) {
    io.err(`Exorcist 98 blocked this commit: ${c.hits.length} canary token(s) are staged outside .exorcist/ (EX-022).`);
    for (const h of c.hits) io.err(`  ${h.file}:${h.line}  ${h.redacted}`);
    io.err('A trap token has been copied out of its trap: something moved it out of the project. Find what copied it, then replant with: exorcist canary plant');
  }
  return 1;
}
