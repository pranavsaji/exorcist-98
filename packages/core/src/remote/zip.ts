import * as zlib from 'node:zlib';
import { safeRelativePath } from './tarball.js';
import type { TarEntry } from './tarball.js';

/**
 * A small, strict ZIP reader for uploaded projects (L-032). It reads the
 * central directory, never trusts a size it has not checked, and refuses
 * anything it does not fully understand:
 *
 * - only stored (0) and deflate (8) entries; encrypted entries are skipped;
 * - no ZIP64 and no multi-disk archives;
 * - paths go through the same check as the GitHub download (no absolute paths,
 *   no "..", no backslashes), so nothing can be written outside the folder;
 * - symbolic links and folders are skipped;
 * - each file is inflated with an output cap, so a "zip bomb" stops at the
 *   cap instead of filling memory; the CRC-32 and the size must match.
 *
 * If every entry sits under one top folder (as GitHub's "Download ZIP" does),
 * that folder is dropped.
 */

export type ZipLimits = {
  maxZipBytes: number;
  maxUnpackedBytes: number;
  maxFiles: number;
  maxFileBytes: number;
};

export const DEFAULT_ZIP_LIMITS: ZipLimits = {
  maxZipBytes: 4 * 1024 * 1024,
  maxUnpackedBytes: 100 * 1024 * 1024,
  maxFiles: 20_000,
  maxFileBytes: 1024 * 1024,
};

export type ZipResult = { ok: true; entries: TarEntry[]; skipped: number } | { ok: false; error: string };

const EOCD = 0x06054b50;
const CEN = 0x02014b50;
const LOC = 0x04034b50;
const S_IFMT = 0o170000;
const S_IFLNK = 0o120000;

const fail = (error: string): ZipResult => ({ ok: false, error });

function crc32(b: Buffer): number | null {
  const fn = (zlib as unknown as { crc32?: (d: Buffer) => number }).crc32;
  return typeof fn === 'function' ? fn(b) >>> 0 : null;
}

export function readZip(zip: Buffer, limits: ZipLimits = DEFAULT_ZIP_LIMITS): ZipResult {
  if (zip.length > limits.maxZipBytes) return fail(`The file is larger than ${Math.round(limits.maxZipBytes / 1048576)} MB.`);
  if (zip.length < 22) return fail('This is not a ZIP file.');

  // End of central directory: the last 22 bytes, or up to 64 KB earlier if the archive has a comment.
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 22 - 0xffff); i--) {
    if (zip.readUInt32LE(i) === EOCD) { eocd = i; break; }
  }
  if (eocd === -1) return fail('This is not a ZIP file.');
  const disk = zip.readUInt16LE(eocd + 4);
  const cdDisk = zip.readUInt16LE(eocd + 6);
  const count = zip.readUInt16LE(eocd + 10);
  const cdSize = zip.readUInt32LE(eocd + 12);
  const cdOffset = zip.readUInt32LE(eocd + 16);
  if (disk !== 0 || cdDisk !== 0) return fail('Multi-part ZIP files are not supported.');
  if (count === 0xffff || cdOffset === 0xffffffff || cdSize === 0xffffffff) return fail('ZIP64 archives are not supported. Make a smaller ZIP.');
  if (cdOffset + cdSize > eocd) return fail('The ZIP file is damaged.');
  if (count > limits.maxFiles) return fail(`The ZIP has more than ${limits.maxFiles} entries.`);

  type Raw = { name: string; method: number; flags: number; crc: number; csize: number; usize: number; local: number; mode: number };
  const raws: Raw[] = [];
  let p = cdOffset;
  for (let n = 0; n < count; n++) {
    if (p + 46 > eocd || zip.readUInt32LE(p) !== CEN) return fail('The ZIP file is damaged.');
    const flags = zip.readUInt16LE(p + 8);
    const method = zip.readUInt16LE(p + 10);
    const crc = zip.readUInt32LE(p + 16);
    const csize = zip.readUInt32LE(p + 20);
    const usize = zip.readUInt32LE(p + 24);
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const mode = zip.readUInt32LE(p + 38) >>> 16;
    const local = zip.readUInt32LE(p + 42);
    if (p + 46 + nameLen > eocd) return fail('The ZIP file is damaged.');
    const name = zip.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    if (csize === 0xffffffff || usize === 0xffffffff || local === 0xffffffff) return fail('ZIP64 archives are not supported. Make a smaller ZIP.');
    raws.push({ name, method, flags, crc, csize, usize, local, mode });
    p += 46 + nameLen + extraLen + commentLen;
  }

  const files = raws.filter((r) => !r.name.endsWith('/'));
  const firsts = new Set(files.map((r) => r.name.split('/')[0]));
  const stripTop = files.length > 0 && firsts.size === 1 && files.every((r) => r.name.includes('/'));

  const entries: TarEntry[] = [];
  let skipped = 0;
  let unpacked = 0;
  for (const r of raws) {
    if (r.name.endsWith('/')) continue; // folder
    if ((r.mode & S_IFMT) === S_IFLNK) { skipped++; continue; } // symbolic link
    if (r.flags & 0x1) { skipped++; continue; } // encrypted
    if (r.method !== 0 && r.method !== 8) { skipped++; continue; }
    const rel = safeRelativePath(r.name, stripTop);
    if (rel === null || r.usize > limits.maxFileBytes) { skipped++; continue; }
    if (r.local + 30 > cdOffset || zip.readUInt32LE(r.local) !== LOC) return fail('The ZIP file is damaged.');
    const start = r.local + 30 + zip.readUInt16LE(r.local + 26) + zip.readUInt16LE(r.local + 28);
    if (start + r.csize > cdOffset) return fail('The ZIP file is damaged.');
    const comp = zip.subarray(start, start + r.csize);
    let data: Buffer;
    if (r.method === 0) {
      data = Buffer.from(comp);
    } else {
      try {
        data = zlib.inflateRawSync(comp, { maxOutputLength: limits.maxFileBytes + 1 });
      } catch {
        skipped++; // corrupt, or larger than the per-file cap
        continue;
      }
    }
    if (data.length !== r.usize) { skipped++; continue; } // size in the directory was a lie
    const c = crc32(data);
    if (c !== null && c !== r.crc) { skipped++; continue; }
    unpacked += data.length;
    if (unpacked > limits.maxUnpackedBytes) return fail(`The project is larger than ${Math.round(limits.maxUnpackedBytes / 1048576)} MB unpacked.`);
    entries.push({ path: rel, data });
  }
  return { ok: true, entries, skipped };
}
