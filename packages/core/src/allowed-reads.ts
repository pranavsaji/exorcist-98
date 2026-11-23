import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { z } from 'zod';

/**
 * "Allow once" for the on-access scanner (m5, REQ-03): `exorcist allow-read`
 * records a file's SHA-256 in `.exorcist/allowed-reads.json`. A read passes
 * while the file's current hash is in the list; any edit changes the hash and
 * the file is scanned again.
 */
const Hash = z.string().regex(/^[0-9a-f]{64}$/);
const AllowedReadsSchema = z.object({ version: z.literal(1), allowed: z.array(Hash) });

export function sha256Bytes(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

/** SHA-256 of a file, or null when it does not exist or cannot be read. */
export function sha256File(file: string): string | null {
  try {
    if (!existsSync(file) || !statSync(file).isFile()) return null;
    return sha256Bytes(readFileSync(file));
  } catch {
    return null;
  }
}

export function allowedReadsPath(stateDir: string): string {
  return resolve(stateDir, 'allowed-reads.json');
}

/**
 * The set of allowed hashes. A missing or damaged file yields an empty set:
 * the on-access hook must never fail closed because its state is unreadable.
 */
export function readAllowedReads(stateDir: string): ReadonlySet<string> {
  const file = allowedReadsPath(stateDir);
  if (!existsSync(file)) return new Set();
  try {
    const parsed: unknown = JSON.parse(readFileSync(file, 'utf8'));
    const result = AllowedReadsSchema.safeParse(parsed);
    return result.success ? new Set(result.data.allowed) : new Set();
  } catch {
    return new Set();
  }
}

export type AllowReadResult = { ok: true; hash: string; count: number } | { ok: false; error: string };

/** Record a file's current SHA-256 so the next on-access read of the same bytes passes. */
export function addAllowedRead(stateDir: string, file: string): AllowReadResult {
  const abs = resolve(file);
  const hash = sha256File(abs);
  if (hash === null) return { ok: false, error: `Cannot read ${file}, so it cannot be allowed.` };

  const path = allowedReadsPath(stateDir);
  const existing = [...readAllowedReads(stateDir)];
  if (!existing.includes(hash)) existing.push(hash);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify({ version: 1, allowed: existing }, null, 2)}\n`, 'utf8');
  return { ok: true, hash, count: existing.length };
}
