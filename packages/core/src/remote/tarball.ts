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
  /** Bytes downloaded. */
  maxCompressedBytes: number;
  /** Bytes of tar read after decompression (kept or not). */
  maxUnpackedBytes:   number;
  maxFiles:           number;
  maxFileBytes:       number;
  /** Bytes of files kept in memory to scan. */
  maxStoredBytes?:    number;
};
// The archive is unpacked while it downloads and only files the scanner can
// read are kept, so large repositories fit: images, fonts, archives, media and
// files over 1 MB are passed over without being stored.
export const DEFAULT_TAR_LIMITS: TarLimits = {
  maxCompressedBytes: 120 * 1024 * 1024,
  maxUnpackedBytes:   800 * 1024 * 1024,
  maxFiles:           20_000,
  maxFileBytes:       1024 * 1024,
  maxStoredBytes:     150 * 1024 * 1024,
};

/** File types the scanner never reads (binary); they are skipped while unpacking. */
const BINARY_EXT = /\.(png|jpe?g|gif|webp|bmp|ico|icns|tiff?|psd|avif|heic|mp[34]|m4[av]|mov|avi|mkv|webm|wav|ogg|flac|aac|zip|gz|tgz|bz2|xz|7z|rar|zst|jar|war|whl|egg|woff2?|ttf|otf|eot|pdf|docx?|xlsx?|pptx?|exe|dll|so|dylib|a|o|class|pyc|wasm|bin|dat|db|sqlite3?|node|pack|idx|parquet|onnx|pt|safetensors|ckpt|h5|npy|npz)$/i;

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
  // A control character (a newline, ESC, DEL, C1) in a file name can forge
  // lines in logs, terminals and patches that name the file. Never write one.
  if (/[\u0001-\u001F\u007F-\u009F]/.test(raw)) return null;
  if (raw.startsWith('/') || /^[A-Za-z]:/.test(raw)) return null;
  const parts = raw.split('/').filter((p) => p !== '' && p !== '.');
  if (parts.some((p) => p === '..')) return null;
  const rest = stripTop ? parts.slice(1) : parts;
  if (rest.length === 0) return null;
  return rest.join('/');
}

type StreamResult = { ok: true; entries: TarEntry[]; skipped: number } | { ok: false; error: string };

/**
 * A tar reader fed in chunks. It holds at most one header or one kept file in
 * memory at a time; data of skipped entries is dropped as it arrives.
 */
export class TarStream {
  private buf: Buffer = Buffer.alloc(0);
  private entries: TarEntry[] = [];
  private skipped = 0;
  private stored = 0;
  private longName: string | null = null;
  private ended = false;
  private failure: string | null = null;
  // What the bytes now arriving are: a header, data being kept, or data being dropped.
  private mode: 'header' | 'keep' | 'drop' = 'header';
  private remaining = 0;   // data bytes left in the current entry
  private pad = 0;         // padding after the current entry
  private keep: { kind: 'file' | 'pax' | 'gnu'; path: string } | null = null;

  constructor(
    private readonly limits: Pick<TarLimits, 'maxFiles' | 'maxFileBytes' | 'maxStoredBytes'> = DEFAULT_TAR_LIMITS,
    private readonly stripTop = true,
    private readonly skipBinary = false,
  ) {}

  push(chunk: Buffer): void {
    if (this.ended || this.failure) return;
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    for (;;) {
      if (this.ended || this.failure) { this.buf = Buffer.alloc(0); return; }
      if (this.mode === 'drop') {
        const n = Math.min(this.remaining + this.pad, this.buf.length);
        const fromData = Math.min(n, this.remaining);
        this.remaining -= fromData;
        this.pad -= n - fromData;
        this.buf = this.buf.subarray(n);
        if (this.remaining + this.pad > 0) return;
        this.mode = 'header';
        continue;
      }
      if (this.mode === 'keep') {
        if (this.buf.length < this.remaining) return;
        const data = Buffer.from(this.buf.subarray(0, this.remaining));
        this.buf = this.buf.subarray(this.remaining);
        this.remaining = 0;
        this.take(data);
        this.mode = this.pad > 0 ? 'drop' : 'header';
        continue;
      }
      if (this.buf.length < BLOCK) return;
      const h = this.buf.subarray(0, BLOCK);
      this.buf = this.buf.subarray(BLOCK);
      this.header(Buffer.from(h));
    }
  }

  private header(h: Buffer): void {
    if (h.every((b) => b === 0)) { this.ended = true; return; } // end of archive
    const size = octal(h.subarray(124, 136));
    if (size === null) { this.failure = 'The archive has an entry with an unreadable size.'; return; }
    const type = String.fromCharCode(h[156] ?? 0);
    this.remaining = size;
    this.pad = Math.ceil(size / BLOCK) * BLOCK - size;
    const small = size <= 64 * 1024;
    if (type === 'x') { this.keep = small ? { kind: 'pax', path: '' } : null; this.mode = small ? 'keep' : 'drop'; return; }
    if (type === 'g') { this.keep = null; this.mode = 'drop'; return; }
    if (type === 'L') { this.keep = small ? { kind: 'gnu', path: '' } : null; this.mode = small ? 'keep' : 'drop'; return; }
    const prefix = cstr(h.subarray(345, 500));
    const name = this.longName ?? (prefix ? `${prefix}/${cstr(h.subarray(0, 100))}` : cstr(h.subarray(0, 100)));
    this.longName = null;
    const rel = (type === '0' || type === '\0' || type === '7') ? safeRelativePath(name, this.stripTop) : null;
    if (rel === null || size > this.limits.maxFileBytes || (this.skipBinary && BINARY_EXT.test(rel))) {
      this.skipped++; // directories, links, devices, unsafe paths, large or binary files
      this.keep = null;
      this.mode = 'drop';
      return;
    }
    if (this.entries.length >= this.limits.maxFiles) { this.failure = `The repository has more than ${this.limits.maxFiles} files.`; return; }
    this.keep = { kind: 'file', path: rel };
    this.mode = 'keep';
  }

  private take(data: Buffer): void {
    const k = this.keep;
    this.keep = null;
    if (!k) return;
    if (k.kind === 'pax') { this.longName = paxPath(data); return; }
    if (k.kind === 'gnu') { this.longName = cstr(data); return; }
    this.stored += data.length;
    const cap = this.limits.maxStoredBytes ?? Number.POSITIVE_INFINITY;
    if (this.stored > cap) { this.failure = `The repository has more than ${Math.round(cap / 1048576)} MB of text files.`; return; }
    this.entries.push({ path: k.path, data });
  }

  /** Call once after the last chunk. */
  end(): StreamResult {
    if (this.failure) return { ok: false, error: this.failure };
    // Data cut short means the download was truncated; missing padding at the very end is fine.
    if (!this.ended && (this.remaining > 0 || (this.mode === 'header' && this.buf.length > 0))) {
      return { ok: false, error: 'The archive is truncated.' };
    }
    return { ok: true, entries: this.entries, skipped: this.skipped };
  }
}

/** Parse an uncompressed tar buffer into regular-file entries. Pure. */
export function readTar(tar: Buffer, limits: Pick<TarLimits, 'maxFiles' | 'maxFileBytes' | 'maxStoredBytes'> = DEFAULT_TAR_LIMITS, stripTop = true):
  StreamResult {
  const t = new TarStream(limits, stripTop);
  t.push(tar);
  return t.end();
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

/** Decompress and unpack while downloading; nothing but kept files is held in memory. */
async function unpackStream(body: AsyncIterable<Uint8Array>, limits: TarLimits): Promise<StreamResult> {
  const gunzip = createGunzip();
  const tar = new TarStream(limits, true, true);
  let compressed = 0;
  let unpacked = 0;
  let failure: Error | null = null;
  gunzip.on('data', (c: Buffer) => {
    unpacked += c.length;
    if (unpacked > limits.maxUnpackedBytes) {
      failure = new Error(`The repository is larger than ${Math.round(limits.maxUnpackedBytes / 1048576)} MB unpacked. ${TOO_BIG_HINT}`);
      gunzip.destroy(failure);
    } else tar.push(c);
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
  return tar.end();
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
    const parsed = await unpackStream(res.body as AsyncIterable<Uint8Array>, limits);
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

