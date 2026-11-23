/**
 * Canary traps, Shield side: planting the trap files, loading the records
 * and finding a token inside a JSON-RPC message. The token shapes and the
 * record file live in @exorcist-98/core so the scanner and the pre-commit
 * hook share the exact same detection.
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import {
  CanariesFileSchema,
  findRecordIn,
  newToken,
  canariesPath as coreCanariesPath,
} from '@exorcist-98/core';
import type { CanaryHit, CanaryRecord } from '@exorcist-98/core';
import { collectStringsChecked } from './inspect.js';

export type { CanaryRecord, CanaryHit } from '@exorcist-98/core';

export { newToken } from '@exorcist-98/core';
export { canariesPath } from '@exorcist-98/core';

export type Canary = { token: string; file: string };

/**
 * The three trap files planted by default. Each says in a comment that it is
 * an Exorcist 98 canary, in words that do not tell an agent to avoid it.
 */
const TRAPS: Array<{ file: string; body: (token: string) => string }> = [
  {
    file: '.env.canary',
    body: (t) =>
      `# Exorcist 98 canary file. These values are decoys planted by Exorcist 98\n# to detect leaks; they are not real credentials.\nAWS_ACCESS_KEY_ID=${t}\nAWS_REGION=us-east-1\n`,
  },
  {
    file: 'NOTES.md',
    body: (t) =>
      `<!-- Exorcist 98 canary file: private-looking notes planted as a trap. -->\n# Personal notes\n\nDeploy key (keep to yourself): \`${t}\`\n\nRemember to rotate the staging key next week.\n`,
  },
  {
    file: 'config.json',
    body: (t) =>
      `${JSON.stringify({ _comment: 'Exorcist 98 canary file: decoy internal config planted as a trap.', internal_token: t, retries: 3 }, null, 2)}\n`,
  },
];

export type PlantResult =
  | { ok: true; records: CanaryRecord[]; dir: string }
  | { ok: false; error: string };

/**
 * Plant the trap files and record the tokens. `root` is the project root; the
 * traps go to `<root>/.exorcist/canary/` and the records to
 * `<root>/.exorcist/canaries.json`, which is also the Shield's state folder.
 */
export function plantCanaries(root: string, n: number = 3): PlantResult {
  if (n < 1 || n > TRAPS.length) return { ok: false, error: `plant between 1 and ${TRAPS.length} traps.` };
  const trapDir = join(root, '.exorcist', 'canary');
  try {
    mkdirSync(trapDir, { recursive: true });
  } catch (err) {
    return { ok: false, error: `Could not create ${trapDir}: ${String(err).split('\n')[0]}` };
  }
  const existing = loadCanaries(root);
  if (!existing.ok) return existing;
  const records = [...existing.canaries];
  for (const trap of TRAPS.slice(0, n)) {
    const token = newToken();
    const file = join('.exorcist', 'canary', trap.file);
    try {
      writeFileSync(join(trapDir, trap.file), trap.body(token));
    } catch (err) {
      return { ok: false, error: `Could not write the trap file: ${String(err).split('\n')[0]}` };
    }
    records.push({ token, file, created: new Date().toISOString() });
  }
  try {
    writeFileSync(coreCanariesPath(root), `${JSON.stringify({ version: 1, canaries: records }, null, 2)}\n`);
  } catch (err) {
    return { ok: false, error: `Could not write the canary records: ${String(err).split('\n')[0]}` };
  }
  return { ok: true, records, dir: trapDir };
}

export type LoadResult =
  | { ok: true; canaries: CanaryRecord[] }
  | { ok: false; error: string };

/** Read the project's canary records from `<root>/.exorcist/canaries.json`. */
export function loadCanaries(root: string): LoadResult {
  const path = coreCanariesPath(root);
  if (!existsSync(path)) return { ok: true, canaries: [] };
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return { ok: false, error: `The canary records file ${path} is not valid JSON.` };
  }
  const parsed = CanariesFileSchema.safeParse(json);
  if (!parsed.success) {
    return { ok: false, error: `The canary records file ${path} is invalid: ${parsed.error.issues[0]?.message ?? 'unknown problem'}` };
  }
  return { ok: true, canaries: parsed.data.canaries };
}

export type RemoveResult =
  | { ok: true; removed: string[] }
  | { ok: false; error: string };

/** Remove the trap files and the records. Nothing else in the project is touched. */
export function removeCanaries(root: string): RemoveResult {
  const existing = loadCanaries(root);
  if (!existing.ok) return existing;
  const removed: string[] = [];
  try {
    const trapDir = join(root, '.exorcist', 'canary');
    if (existsSync(trapDir)) {
      for (const r of existing.canaries) {
        const full = join(root, r.file);
        if (existsSync(full)) {
          rmSync(full);
          removed.push(r.file);
        }
      }
      // Only remove the trap folder when this install owns all of it.
      const left = Array.from(new Set(TRAPS.map((t) => t.file))).filter((f) => existsSync(join(trapDir, f)));
      if (left.length === 0) rmSync(trapDir, { recursive: true, force: true });
    }
    const records = coreCanariesPath(root);
    if (existsSync(records)) {
      rmSync(records);
      removed.push('.exorcist/canaries.json');
    }
  } catch (err) {
    return { ok: false, error: `Could not remove the canaries: ${String(err).split('\n')[0]}` };
  }
  return { ok: true, removed };
}

/**
 * Find a canary token anywhere in a JSON-like value: every string and key,
 * also base64- or percent-encoded, or with whitespace between its characters.
 * Fails closed when the value was too large to read fully.
 */
export function findCanary(value: unknown, canaries: readonly Canary[]): { hit: CanaryHit; canary: Canary } | { truncated: true } | null {
  const { strings, truncated } = collectStringsChecked(value);
  if (truncated) return { truncated: true };
  for (const c of canaries) {
    for (const s of strings) {
      const hit = findRecordIn({ token: c.token, file: c.file, created: '' }, s);
      if (hit) return { hit, canary: c };
    }
  }
  return null;
}
