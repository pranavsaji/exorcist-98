import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, parse, relative, resolve } from 'node:path';
import { z } from 'zod';

/**
 * "Allow once" for the on-access scanner (m5, REQ-03).
 *
 * The scanned repository is untrusted, so the allowances must not live in it:
 * a repo could ship its own list with the hash of its poisoned file. They are
 * kept per user, outside every project:
 *
 *   $EXORCIST_DIR/allowed-reads/<sha256 of the project's real path>.json
 *   (EXORCIST_DIR unset: ~/.exorcist/allowed-reads/...)
 *
 * and a list that would sit inside the project tree (EXORCIST_DIR pointing
 * into the project, or a project that contains the home folder) is ignored.
 * Each entry binds a file's real absolute path to its SHA-256: the same bytes
 * at another path, or other bytes at the same path, are scanned again.
 */
const Hash = z.string().regex(/^[0-9a-f]{64}$/);
const Entry = z.object({ path: z.string().min(1), sha256: Hash });
const AllowedReadsSchema = z.object({ version: z.literal(2), project: z.string(), entries: z.array(Entry) });
export type AllowedRead = z.infer<typeof Entry>;

/** Same markers as the Shield's state lookup (packages/shield/src/locate.ts). */
const PROJECT_MARKERS = ['.exorcist', '.kiro', '.git'];

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

/**
 * The real path (symlinks resolved). For a path that does not exist yet, the
 * nearest existing folder above it is resolved and the rest appended, so a
 * symlinked prefix (macOS /var -> /private/var) cannot hide that a new file
 * would land inside the project.
 */
export function realPath(p: string): string {
  const abs = resolve(p);
  const rest: string[] = [];
  for (let dir = abs; ; dir = dirname(dir)) {
    try {
      return join(realpathSync(dir), ...rest.reverse());
    } catch {
      if (dirname(dir) === dir) return abs;
      rest.push(basename(dir));
    }
  }
}

/** The project a path belongs to: the nearest folder with .exorcist, .kiro or .git, else `cwd` itself. Real path. */
export function findProjectRoot(cwd: string): string {
  const start = realPath(cwd);
  const { root } = parse(start);
  for (let dir = start; ; dir = dirname(dir)) {
    if (PROJECT_MARKERS.some((m) => existsSync(join(dir, m)))) return dir;
    if (dir === root || dirname(dir) === dir) break;
  }
  return start;
}

/** True when `p` is `dir` or inside it. Both are compared as real paths. */
export function isInside(p: string, dir: string): boolean {
  const rel = relative(realPath(dir), realPath(p));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

export type AllowedReadsLocation = { ok: true; file: string; project: string } | { ok: false; error: string };

/** Where the allowances for the project at `cwd` are kept, or why there is no safe place. */
export function allowedReadsLocation(cwd: string, env: NodeJS.ProcessEnv = process.env): AllowedReadsLocation {
  const project = findProjectRoot(cwd);
  const fromEnv = env['EXORCIST_DIR'];
  const base = fromEnv ? resolve(project, fromEnv) : join(homedir(), '.exorcist');
  const file = join(base, 'allowed-reads', `${sha256Bytes(Buffer.from(project, 'utf8'))}.json`);
  if (isInside(file, project)) {
    return { ok: false, error: `Allowances cannot be kept inside the project (${file}): the project itself could plant them. Set EXORCIST_DIR to a folder outside ${project}.` };
  }
  return { ok: true, file, project };
}

/** The key decideRead looks up: real absolute path plus content hash. */
export function allowKey(realAbsPath: string, sha256: string): string {
  return `${sha256}\u0000${realAbsPath}`;
}

/**
 * The allowances for the project at `cwd`, as allowKey strings. A missing,
 * damaged or misplaced list yields an empty set: the hook must not fail
 * because of its own state, and it never trusts a list inside the project.
 */
export function readAllowedReads(cwd: string, env: NodeJS.ProcessEnv = process.env): ReadonlySet<string> {
  const loc = allowedReadsLocation(cwd, env);
  if (!loc.ok || !existsSync(loc.file)) return new Set();
  try {
    // A symlink placed so that the list resolves into the project is ignored too.
    if (isInside(loc.file, loc.project)) return new Set();
    const result = AllowedReadsSchema.safeParse(JSON.parse(readFileSync(loc.file, 'utf8')));
    if (!result.success || result.data.project !== loc.project) return new Set();
    return new Set(result.data.entries.map((e) => allowKey(e.path, e.sha256)));
  } catch {
    return new Set();
  }
}

export type AllowReadResult = { ok: true; hash: string; path: string; store: string; count: number } | { ok: false; error: string };

/** Record a file's real path and current SHA-256 so the next on-access read of the same bytes at that path passes. */
export function addAllowedRead(cwd: string, file: string, env: NodeJS.ProcessEnv = process.env): AllowReadResult {
  const abs = realPath(resolve(cwd, file));
  const hash = sha256File(abs);
  if (hash === null) return { ok: false, error: `Cannot read ${file}, so it cannot be allowed.` };
  const loc = allowedReadsLocation(cwd, env);
  if (!loc.ok) return loc;

  let entries: AllowedRead[] = [];
  if (existsSync(loc.file)) {
    try {
      const parsed = AllowedReadsSchema.safeParse(JSON.parse(readFileSync(loc.file, 'utf8')));
      if (parsed.success && parsed.data.project === loc.project) entries = parsed.data.entries;
    } catch { /* a damaged list is replaced */ }
  }
  // One entry per path: allowing new bytes replaces the old allowance.
  entries = [...entries.filter((e) => e.path !== abs), { path: abs, sha256: hash }];
  mkdirSync(dirname(loc.file), { recursive: true });
  const tmp = `${loc.file}.tmp-${process.pid}`;
  writeFileSync(tmp, `${JSON.stringify({ version: 2, project: loc.project, entries }, null, 2)}\n`, 'utf8');
  renameSync(tmp, loc.file);
  return { ok: true, hash, path: abs, store: loc.file, count: entries.length };
}
