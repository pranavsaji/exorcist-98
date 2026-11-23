/**
 * Canary traps, Shield side: planting and removing the trap files, loading
 * the records and finding a token inside a JSON-RPC message (EX-022). The
 * token format, the records file and the detection itself live in
 * @exorcist-98/core, so the Shield, the scanner and the pre-commit hook all
 * find exactly the same things.
 */
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import {
  CANARY_RECORDS_FILE,
  CANARY_TRAP_DIR,
  canariesPath,
  findCanaryInText,
  loadCanariesFile,
  newToken,
} from '@exorcist-98/core';
import type { Canary, CanaryRecord, CanaryShape } from '@exorcist-98/core';
import { policyPath } from './state.js';

export type { Canary, CanaryRecord, CanaryShape } from '@exorcist-98/core';
export { newToken, canariesPath } from '@exorcist-98/core';

/**
 * The trap files. Each says in a comment that it is an Exorcist 98 canary, so
 * a person who opens one is not confused. The comment only says what the file
 * is; it does not ask anyone (or any AI) to stay away from it. The values do
 * not match any real credential format, so secret scanners (ours included)
 * have nothing to report in the trap itself.
 */
export const TRAPS: ReadonlyArray<{ name: string; body: (token: string) => string }> = [
  {
    name: '.env.canary',
    body: (t) =>
      '# Exorcist 98 canary trap, planted by "exorcist canary plant".\n' +
      '# The value below is a unique marker, not a key for any service.\n' +
      `DEPLOY_TOKEN=${t}\n`,
  },
  {
    name: 'NOTES.md',
    body: (t) =>
      '<!-- Exorcist 98 canary trap, planted by "exorcist canary plant". The key below is a unique marker, not a real credential. -->\n' +
      '# Ops notes\n\n' +
      `Staging deploy key: ${t}\n\n` +
      'Rotate it after the next release.\n',
  },
  {
    name: 'config.json',
    body: (t) =>
      `${JSON.stringify({
        _comment: 'Exorcist 98 canary trap, planted by "exorcist canary plant". internalToken is a unique marker, not a real credential.',
        service: 'billing-internal',
        internalToken: t,
      }, null, 2)}\n`,
  },
];

export const DEFAULT_TRAPS = TRAPS.length;

export type PlantOptions = {
  /** How many traps (1 to 3). Default 3. */
  count?: number;
  /**
   * The Shield's state folder. When it is not `<root>/.exorcist` (for example
   * EXORCIST_DIR points elsewhere), its policy is told where the records are.
   */
  stateDir?: string;
  now?: () => Date;
};

export type PlantResult =
  | { ok: true; records: CanaryRecord[]; recordsFile: string; policyUpdated?: string }
  | { ok: false; error: string };

const firstLine = (err: unknown): string => String(err).split('\n')[0] ?? '';

/**
 * Plant the trap files in `<root>/.exorcist/canary/` and record the tokens in
 * `<root>/.exorcist/canaries.json`. Refuses to plant over existing traps or
 * records: replanting is `remove` then `plant`, so no record ever points at a
 * file that no longer holds its token.
 */
export function plantCanaries(root: string, o: PlantOptions = {}): PlantResult {
  const count = o.count ?? DEFAULT_TRAPS;
  if (!Number.isInteger(count) || count < 1 || count > TRAPS.length) {
    return { ok: false, error: `Plant between 1 and ${TRAPS.length} traps.` };
  }
  const recordsFile = canariesPath(root);
  const existing = loadCanariesFile(recordsFile);
  if (!existing.ok) return existing;
  if (existing.canaries.length > 0) {
    return { ok: false, error: `Canary traps are already planted in ${root}. To replace them, run "exorcist canary --remove" first.` };
  }
  for (const d of ['.exorcist', CANARY_TRAP_DIR]) {
    const path = join(root, d);
    if (existsSync(path) || isSymlink(path)) {
      if (!isRealDir(path)) return { ok: false, error: `${path} is not a real folder (a symlink or a file); no traps were planted.` };
    }
  }
  const traps = TRAPS.slice(0, count);
  for (const t of traps) {
    const path = join(root, CANARY_TRAP_DIR, t.name);
    if (existsSync(path)) return { ok: false, error: `${path} already exists; it was not overwritten.` };
  }

  const created = (o.now ? o.now() : new Date()).toISOString();
  const records: CanaryRecord[] = [];
  const madeDirs = ['.exorcist', CANARY_TRAP_DIR].filter((d) => !existsSync(join(root, d)));
  try {
    mkdirSync(join(root, CANARY_TRAP_DIR), { recursive: true });
    for (const t of traps) {
      const token = newToken();
      const file = `${CANARY_TRAP_DIR}/${t.name}`;
      writeFileSync(join(root, file), t.body(token), { flag: 'wx' });
      records.push({ token, file, created });
    }
    writeFileSync(recordsFile, `${JSON.stringify({ version: 1, canaries: records, ...(madeDirs.length > 0 ? { madeDirs } : {}) }, null, 2)}\n`);
  } catch (err) {
    // Leave nothing half-planted behind.
    for (const r of records) rmSync(join(root, r.file), { force: true });
    for (const d of [...madeDirs].reverse()) rmdirIfEmpty(join(root, d));
    return { ok: false, error: `Could not plant the canary traps: ${firstLine(err)}` };
  }

  const result: PlantResult = { ok: true, records, recordsFile };
  if (o.stateDir && resolve(o.stateDir) !== resolve(root, '.exorcist')) {
    const told = setPolicyCanaries(o.stateDir, recordsFile);
    if (!told.ok) return { ok: false, error: `Planted the traps, but could not tell the Shield where they are: ${told.error}` };
    result.policyUpdated = policyPath(o.stateDir);
  }
  return result;
}

/** Read the project's canary records from `<root>/.exorcist/canaries.json`. */
export function loadCanaries(root: string): { ok: true; canaries: CanaryRecord[] } | { ok: false; error: string } {
  const r = loadCanariesFile(canariesPath(root));
  return r.ok ? { ok: true, canaries: r.canaries } : r;
}

export type RemoveResult =
  | { ok: true; removed: string[]; warnings: string[] }
  | { ok: false; error: string };

/** Remove a folder only if it is a real, empty folder (never through a symlink). */
function rmdirIfEmpty(path: string): void {
  try {
    if (lstatSync(path).isDirectory() && readdirSync(path).length === 0) rmdirSync(path);
  } catch {
    // missing or not removable: leave it
  }
}

function isSymlink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

/** True when `path` exists and is a real folder, not a symlink to one. */
function isRealDir(path: string): boolean {
  try {
    return lstatSync(path).isDirectory();
  } catch {
    return false;
  }
}

const TRAP_NAMES = new Set(TRAPS.map((t) => t.name));

/**
 * Remove the trap files named in the records, then the records file and the
 * folders `plant` created if they are left empty.
 *
 * A file is deleted only when all of these hold, and otherwise left in place
 * with a warning: its name is one `plant` writes, `.exorcist` and
 * `.exorcist/canary` are real folders (not symlinks), the file's folder
 * resolves to that trap folder, the file itself is a regular file (not a
 * symlink), and it still holds the recorded token. So a tampered records
 * file, a symlinked trap folder or a trap someone edited cannot make
 * `--remove` delete anything else. If any trap is left, the records are kept
 * too, so the Shield goes on watching those tokens.
 */
export function removeCanaries(root: string, o: { stateDir?: string } = {}): RemoveResult {
  const recordsFile = canariesPath(root);
  const existing = loadCanariesFile(recordsFile);
  if (!existing.ok) return existing;
  const removed: string[] = [];
  const warnings: string[] = [];
  const stateFolder = join(root, '.exorcist');
  const trapFolder = join(root, CANARY_TRAP_DIR);
  const foldersReal = isRealDir(stateFolder) && isRealDir(trapFolder);
  let trapReal: string | null = null;
  try {
    trapReal = foldersReal ? realpathSync(trapFolder) : null;
  } catch {
    trapReal = null;
  }

  let left = 0;
  for (const r of existing.canaries) {
    const full = join(root, r.file);
    const name = r.file.slice(`${CANARY_TRAP_DIR}/`.length);
    const leave = (why: string): void => { left++; warnings.push(`Left ${r.file} in place: ${why}`); };
    let st;
    try {
      st = lstatSync(full);
    } catch {
      continue; // already gone
    }
    if (!TRAP_NAMES.has(name)) { leave('it is not a file "exorcist canary plant" writes.'); continue; }
    if (!foldersReal || trapReal === null) { leave(`${CANARY_TRAP_DIR} is not a real folder inside the project (a symlink?).`); continue; }
    if (!st.isFile()) { leave('it is not a regular file (a symlink or a folder).'); continue; }
    try {
      if (realpathSync(dirname(full)) !== trapReal) { leave('it is not inside the trap folder.'); continue; }
      if (!readFileSync(full, 'utf8').includes(r.token)) { leave('it no longer holds the token it was planted with, so it may not be the trap any more.'); continue; }
      rmSync(full);
      removed.push(r.file);
    } catch (err) {
      leave(`it could not be removed (${firstLine(err)}).`);
    }
  }

  if (left > 0) {
    warnings.push(`Kept ${CANARY_RECORDS_FILE} so the Shield goes on watching those tokens. Check the files above by hand, then run "exorcist canary --remove" again.`);
    return { ok: true, removed, warnings };
  }
  try {
    const st = lstatSync(recordsFile);
    if (isRealDir(stateFolder) && st.isFile()) {
      rmSync(recordsFile);
      removed.push(CANARY_RECORDS_FILE);
    } else {
      warnings.push(`Left ${CANARY_RECORDS_FILE} in place: it or the .exorcist folder is not a regular file or folder (a symlink?).`);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') return { ok: false, error: `Could not remove the canary records: ${firstLine(err)}` };
  }
  // Only the folders `plant` made, and only if nothing else was put there since.
  if (existing.madeDirs.includes(CANARY_TRAP_DIR)) rmdirIfEmpty(trapFolder);
  if (existing.madeDirs.includes('.exorcist')) rmdirIfEmpty(stateFolder);
  if (o.stateDir && resolve(o.stateDir) !== resolve(root, '.exorcist')) clearPolicyCanaries(o.stateDir, recordsFile);
  return { ok: true, removed, warnings };
}

// ── telling the Shield's state folder ────────────────────────────────────────

function readPolicyObject(stateDir: string): { ok: true; obj: Record<string, unknown> } | { ok: false; error: string } {
  const path = policyPath(stateDir);
  if (!existsSync(path)) return { ok: true, obj: {} };
  try {
    const json: unknown = JSON.parse(readFileSync(path, 'utf8'));
    if (!json || typeof json !== 'object' || Array.isArray(json)) return { ok: false, error: `${path} is not a JSON object.` };
    return { ok: true, obj: json as Record<string, unknown> };
  } catch (err) {
    return { ok: false, error: `Could not read ${path}: ${firstLine(err)}` };
  }
}

function setPolicyCanaries(stateDir: string, recordsFile: string): { ok: true } | { ok: false; error: string } {
  const p = readPolicyObject(stateDir);
  if (!p.ok) return p;
  try {
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(policyPath(stateDir), `${JSON.stringify({ ...p.obj, canaries: resolve(recordsFile) }, null, 2)}\n`);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: firstLine(err) };
  }
}

function clearPolicyCanaries(stateDir: string, recordsFile: string): void {
  const p = readPolicyObject(stateDir);
  if (!p.ok || p.obj['canaries'] !== resolve(recordsFile)) return;
  const { canaries: _gone, ...rest } = p.obj;
  try {
    if (Object.keys(rest).length === 0) rmSync(policyPath(stateDir));
    else writeFileSync(policyPath(stateDir), `${JSON.stringify(rest, null, 2)}\n`);
  } catch {
    // the traps are gone; a stale path in the policy only means an empty list
  }
}

/** The records file the Shield reads: the policy's `canaries` (relative to the state folder) or `<stateDir>/canaries.json`. */
export function canariesFileFor(stateDir: string, policyCanaries?: string): string {
  if (!policyCanaries) return join(stateDir, 'canaries.json');
  return isAbsolute(policyCanaries) ? policyCanaries : resolve(stateDir, policyCanaries);
}

// ── detection in messages ────────────────────────────────────────────────────

/** Every string and key in a JSON-like value, with no depth or count limit (so nothing is left unread). */
function allStrings(value: unknown): string[] {
  const out: string[] = [];
  const seen = new Set<object>();
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v === 'string') out.push(v);
    else if (v && typeof v === 'object') {
      if (seen.has(v)) continue;
      seen.add(v);
      if (Array.isArray(v)) for (let i = v.length - 1; i >= 0; i--) stack.push(v[i]);
      else {
        const entries = Object.entries(v as Record<string, unknown>);
        for (let i = entries.length - 1; i >= 0; i--) {
          const [k, x] = entries[i] as [string, unknown];
          stack.push(x, k);
        }
      }
    }
  }
  return out;
}

/**
 * Find a canary token anywhere in a JSON-like value: in any string or key, at
 * any depth, raw, base64- or percent-encoded, or split by whitespace (also
 * across neighbouring items of an array). Returns the first canary found.
 */
export function findCanary<C extends Canary>(value: unknown, canaries: readonly C[]): { canary: C; shape: CanaryShape } | null {
  if (canaries.length === 0) return null;
  const hits = findCanaryInText(allStrings(value).join('\n'), canaries);
  const first = hits[0];
  return first ? { canary: first.canary, shape: first.shape } : null;
}
