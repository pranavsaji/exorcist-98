import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { createGunzip } from 'node:zlib';

/**
 * Fetch a public GitHub repository as a tarball and unpack it, without git.
 *
 * Only regular files are written. Links, devices and anything else are
 * skipped; a path that would leave the target folder is skipped; files over
 * `maxFileBytes` are skipped (the scanner ignores them anyway). Every limit is
 * enforced while reading, so a hostile archive cannot exhaust memory or disk.
 */
export type TarLimits = {
  maxCompressedBytes: number;
  maxUnpackedBytes:   number;
  maxFiles:           number;
  maxFileBytes:       number;
};

export const DEFAULT_TAR_LIMITS: TarLimits = {
  maxCompressedBytes: 25 * 1024 * 1024,
  maxUnpackedBytes:   150 * 1024 * 1024,
  maxFiles:           20_000,
  maxFileBytes:       1024 * 1024,
};

export type TarEntry = { path: string; data: Buffer };
export type ExtractResult =
  | { ok: true; files: number; skipped: number }
  | { ok: false; error: string };

const BLOCK = 512;

function cstr(b: Buffer): string {
  const z = b.indexOf(0);
  return (z === -1 ? b : b.subarray(0, z)).toString('utf8');
}

function octal(b: Buffer): number | null {
  if ((b[0] ?? 0) & 0x80) return null; // base-256 sizes are only used for files over 8 GB
  const s = cstr(b).trim();
  if (s === '') return 0;
  if (!/^[0-7]+$/.test(s)) return null;
  return parseInt(s, 8);
}

/** "27 path=some/long/name\n" records; returns the path, if any. */
function paxPath(data: Buffer): string | null {
  let off = 0;
  let found: string | null = null;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    if (space === -1) break;
    const len = parseInt(data.subarray(off, space).toString('ascii'), 10);
    if (!Number.isFinite(len) || len <= 0 || off + len > data.length) break;
    const rec = data.subarray(space + 1, off + len - 1).toString('utf8');
    const eq = rec.indexOf('=');
    if (eq !== -1 && rec.slice(0, eq) === 'path') found = rec.slice(eq + 1);
    off += len;
  }
  return found;
}

/**
 * Make an archive path safe and relative, dropping GitHub's top folder
 * ("repo-HEAD/"). Returns null for anything that is not a plain relative path.
 */
export function safeRelativePath(raw: string, stripTop = true): string | null {
  if (raw.includes('\0') || raw.includes('\\')) return null;
  if (raw.startsWith('/') || /^[A-Za-z]:/.test(raw)) return null;
  const parts = raw.split('/').filter((p) => p !== '' && p !== '.');
  if (parts.some((p) => p === '..')) return null;
  const rest = stripTop ? parts.slice(1) : parts;
  if (rest.length === 0) return null;
  return rest.join('/');
}

/** Parse an uncompressed tar buffer into regular-file entries. Pure. */
export function readTar(tar: Buffer, limits: Pick<TarLimits, 'maxFiles' | 'maxFileBytes'> = DEFAULT_TAR_LIMITS, stripTop = true):
  { ok: true; entries: TarEntry[]; skipped: number } | { ok: false; error: string } {
  const entries: TarEntry[] = [];
  let skipped = 0;
  let off = 0;
  let longName: string | null = null;

  let ended = false;
  while (off + BLOCK <= tar.length) {
    const h = tar.subarray(off, off + BLOCK);
    if (h.every((b) => b === 0)) { ended = true; break; } // end of archive
    const size = octal(h.subarray(124, 136));
    if (size === null) return { ok: false, error: 'The archive has an entry with an unreadable size.' };
    const type = String.fromCharCode(h[156] ?? 0);
    const dataStart = off + BLOCK;
    const dataEnd = dataStart + size;
    if (dataEnd > tar.length) return { ok: false, error: 'The archive is truncated.' };
    const data = tar.subarray(dataStart, dataEnd);
    off = dataStart + Math.ceil(size / BLOCK) * BLOCK;

    if (type === 'x') { longName = paxPath(data); continue; }      // per-file pax header
    if (type === 'g') continue;                                    // global pax header
    if (type === 'L') { longName = cstr(data); continue; }         // GNU long name
    const prefix = cstr(h.subarray(345, 500));
    const name = longName ?? (prefix ? `${prefix}/${cstr(h.subarray(0, 100))}` : cstr(h.subarray(0, 100)));
    longName = null;

    if (type !== '0' && type !== '\0' && type !== '7') { skipped++; continue; } // directories, links, devices
    const rel = safeRelativePath(name, stripTop);
    if (rel === null || size > limits.maxFileBytes) { skipped++; continue; }
    if (entries.length >= limits.maxFiles) return { ok: false, error: `The repository has more than ${limits.maxFiles} files.` };
    entries.push({ path: rel, data: Buffer.from(data) });
  }
  // Bytes left over that do not form a whole header mean the download was cut short.
  if (!ended && off < tar.length) return { ok: false, error: 'The archive is truncated.' };
  return { ok: true, entries, skipped };
}

/** Write entries under `dir`. Every path is re-checked against `dir` before writing. */
export function writeEntries(dir: string, entries: TarEntry[]): number {
  const root = resolve(dir);
  let n = 0;
  for (const e of entries) {
    const target = resolve(root, e.path);
    if (!target.startsWith(root + sep)) continue; // belt and braces: safeRelativePath already refused this
    try {
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, e.data, { flag: 'wx' }); // never overwrite: a second entry with the same path is skipped
      n++;
    } catch {
      /* duplicate path, or a file where a folder is needed: skip it */
    }
  }
  return n;
}

/** What to do instead when a repository is too big to download here. */
export const TOO_BIG_HINT = 'Upload a .zip of the folders that matter (agent files, rules, MCP configs), or run the Exorcist 98 CLI on your machine, which has no size limit.';

async function gunzipCapped(body: AsyncIterable<Uint8Array>, limits: TarLimits): Promise<Buffer> {
  const gunzip = createGunzip();
  const out: Buffer[] = [];
  let compressed = 0;
  let unpacked = 0;
  let failure: Error | null = null;
  gunzip.on('data', (c: Buffer) => {
    unpacked += c.length;
    if (unpacked > limits.maxUnpackedBytes) {
      failure = new Error(`The repository is larger than ${Math.round(limits.maxUnpackedBytes / 1048576)} MB unpacked. ${TOO_BIG_HINT}`);
      gunzip.destroy(failure);
    } else out.push(c);
  });
  const finished = new Promise<void>((res, rej) => {
    gunzip.on('end', () => res());
    gunzip.on('error', (e) => rej(failure ?? e));
    gunzip.on('close', () => (failure ? rej(failure) : undefined));
  });
  for await (const chunk of body) {
    compressed += chunk.length;
    if (compressed > limits.maxCompressedBytes) {
      gunzip.destroy();
      throw new Error(`The repository download is larger than ${Math.round(limits.maxCompressedBytes / 1048576)} MB. ${TOO_BIG_HINT}`);
    }
    if (failure) throw failure;
    if (!gunzip.write(chunk)) await new Promise((r) => gunzip.once('drain', r));
  }
  gunzip.end();
  await finished;
  return Buffer.concat(out);
}

export type FetchLike = (url: string, init: { signal: AbortSignal; redirect: 'follow'; headers: Record<string, string> }) =>
  Promise<{ ok: boolean; status: number; body: AsyncIterable<Uint8Array> | ReadableStream<Uint8Array> | null }>;

/**
 * A git ref that is safe to put in a URL path: branch, tag or commit names
 * made of letters, digits, `.`, `_`, `-` and `/`, with no `..`, no leading
 * `/` or `-`, and no empty segment.
 */
export function isSafeRef(ref: string): boolean {
  return /^[A-Za-z0-9._/-]{1,200}$/.test(ref) && !ref.includes('..') && !ref.startsWith('/') && !ref.startsWith('-') && !ref.endsWith('/') && !ref.includes('//');
}

/** Download github.com/<owner>/<repo> at its default branch (or `ref`) and unpack it into `dir`. */
export async function fetchGithubRepo(o: {
  owner: string;
  repo: string;
  dir: string;
  limits?: Partial<TarLimits>;
  timeoutMs?: number;
  fetchImpl?: FetchLike;
  /** A branch, tag or commit; the default branch when omitted (W-020). */
  ref?: string;
}): Promise<ExtractResult> {
  const limits = { ...DEFAULT_TAR_LIMITS, ...o.limits };
  if (!/^[A-Za-z0-9_.-]{1,100}$/.test(o.owner) || !/^[A-Za-z0-9_.-]{1,100}$/.test(o.repo)) {
    return { ok: false, error: 'Not a valid GitHub owner and repository name.' };
  }
  if (o.ref !== undefined && !isSafeRef(o.ref)) {
    return { ok: false, error: 'Not a valid branch, tag or commit name.' };
  }
  const ref = o.ref === undefined ? 'HEAD' : o.ref.split('/').map(encodeURIComponent).join('/');
  const url = `https://codeload.github.com/${encodeURIComponent(o.owner)}/${encodeURIComponent(o.repo)}/tar.gz/${ref}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), o.timeoutMs ?? 30_000);
  try {
    const f = o.fetchImpl ?? (fetch as unknown as FetchLike);
    const res = await f(url, { signal: controller.signal, redirect: 'follow', headers: { 'user-agent': 'exorcist-98' } });
    if (res.status === 404) return { ok: false, error: 'That repository was not found, or it is private.' };
    if (!res.ok || !res.body) return { ok: false, error: `GitHub answered with status ${res.status}.` };
    const tar = await gunzipCapped(res.body as AsyncIterable<Uint8Array>, limits);
    const parsed = readTar(tar, limits);
    if (!parsed.ok) return parsed;
    mkdirSync(o.dir, { recursive: true });
    return { ok: true, files: writeEntries(o.dir, parsed.entries), skipped: parsed.skipped };
  } catch (err) {
    if (controller.signal.aborted) return { ok: false, error: 'Downloading the repository took too long.' };
    return { ok: false, error: (err as Error).message.startsWith('The repository') ? (err as Error).message : 'The repository could not be downloaded.' };
  } finally {
    clearTimeout(timer);
  }
}

