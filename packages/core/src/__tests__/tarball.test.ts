import { describe, it, expect, afterEach } from 'vitest';
import * as fc from 'fast-check';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { gzipSync } from 'node:zlib';
import { fetchGithubRepo, readTar, safeRelativePath, writeEntries } from '../remote/tarball.js';
import type { FetchLike } from '../remote/tarball.js';

// ── a tiny tar writer for tests ───────────────────────────────────────────────

type Raw = { name: string; data?: Buffer | string; type?: string; linkname?: string };

function header(name: string, size: number, type: string, linkname = ''): Buffer {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0, 'utf8');
  h.write('0000644\0', 100, 'ascii');
  h.write('0000000\0', 108, 'ascii');
  h.write('0000000\0', 116, 'ascii');
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'ascii');
  h.write('00000000000\0', 136, 'ascii');
  h.write('        ', 148, 'ascii');
  h.write(type, 156, 'ascii');
  h.write(linkname.slice(0, 100), 157, 'utf8');
  h.write('ustar\0', 257, 'ascii');
  h.write('00', 263, 'ascii');
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
  return h;
}

function pad(b: Buffer): Buffer {
  const rest = b.length % 512;
  return rest === 0 ? b : Buffer.concat([b, Buffer.alloc(512 - rest)]);
}

function tar(entries: Raw[]): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? '');
    const type = e.type ?? '0';
    if (Buffer.byteLength(e.name) > 100) {
      const rec = (body: string) => { let len = body.length + 3; for (;;) { const s = `${len} ${body}`; if (Buffer.byteLength(s) === len) return s; len = Buffer.byteLength(s); } };
      const pax = Buffer.from(rec(`path=${e.name}\n`));
      parts.push(header('PaxHeader', pax.length, 'x'), pad(pax));
    }
    parts.push(header(e.name, type === '0' ? data.length : 0, type, e.linkname), pad(type === '0' ? data : Buffer.alloc(0)));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

const github = (files: Raw[]): Buffer =>
  tar([{ name: 'pax_global_header', type: 'g', data: '' }, { name: 'repo-HEAD/', type: '5' }, ...files.map((f) => ({ ...f, name: `repo-HEAD/${f.name}` }))]);

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-tar-')); dirs.push(d); return d; };

function listAll(dir: string, prefix = ''): string[] {
  const out: string[] = [];
  for (const e of readdirSync(join(dir, prefix), { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...listAll(dir, rel)); else out.push(rel);
  }
  return out.sort();
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe('safeRelativePath', () => {
  it('drops the top folder and keeps ordinary paths', () => {
    expect(safeRelativePath('repo-HEAD/src/a.ts')).toBe('src/a.ts');
    expect(safeRelativePath('repo-HEAD/./x//y')).toBe('x/y');
  });

  it.each(['repo-HEAD/../../etc/passwd', '/etc/passwd', 'repo-HEAD/a/../../b', 'C:/x', 'repo-HEAD/a\\b', 'repo-HEAD/a\0b', 'repo-HEAD/', 'repo-HEAD'])(
    'refuses %j', (p) => { expect(safeRelativePath(p)).toBeNull(); },
  );
});

describe('readTar and writeEntries', () => {
  it('reads a GitHub-shaped archive: skips the pax header and folders, strips the top folder', () => {
    const r = readTar(github([{ name: 'README.md', data: '# hi\n' }, { name: 'src/a.ts', data: 'x' }]));
    expect(r.ok && r.entries.map((e) => [e.path, e.data.toString()])).toEqual([['README.md', '# hi\n'], ['src/a.ts', 'x']]);
  });

  it('reads long names from pax headers', () => {
    const long = `${'deep/'.repeat(30)}file.md`;
    const r = readTar(github([{ name: long, data: 'ok' }]));
    expect(r.ok && r.entries[0]?.path).toBe(long);
  });

  it('never writes outside the target: traversal, absolute paths, symlinks and hard links are skipped', () => {
    const outside = tmp();
    const target = tmp();
    const archive = tar([
      { name: 'repo-HEAD/ok.md', data: 'fine' },
      { name: 'repo-HEAD/../../escape.md', data: 'bad' },
      { name: `${outside}/abs.md`, data: 'bad' },
      { name: 'repo-HEAD/link', type: '2', linkname: '/etc/passwd' },
      { name: 'repo-HEAD/hard', type: '1', linkname: 'repo-HEAD/ok.md' },
      { name: 'repo-HEAD/dev', type: '3' },
    ]);
    const r = readTar(archive);
    if (!r.ok) throw new Error(r.error);
    expect(r.entries.map((e) => e.path)).toEqual(['ok.md']);
    expect(r.skipped).toBe(5);
    writeEntries(target, r.entries);
    expect(listAll(target)).toEqual(['ok.md']);
    expect(readdirSync(outside)).toEqual([]);
  });

  it('writeEntries re-checks paths even if given a bad entry directly', () => {
    // Probe a unique name inside a sandbox: a shared path such as ../../x can
    // already exist on the machine (it does on macOS), which proves nothing.
    const box = tmp();
    const target = join(box, 'a', 'inside');
    const n = writeEntries(target, [
      { path: '../../escape-c3f1', data: Buffer.from('bad') },
      { path: '../escape-c3f1', data: Buffer.from('bad') },
      { path: 'good', data: Buffer.from('ok') },
    ]);
    expect(n).toBe(1);
    expect(existsSync(resolve(target, '../../escape-c3f1'))).toBe(false);
    expect(existsSync(resolve(target, '../escape-c3f1'))).toBe(false);
    expect(readFileSync(join(target, 'good'), 'utf8')).toBe('ok');
  });

  it('skips files over the size cap and refuses too many files', () => {
    const big = readTar(github([{ name: 'big.bin', data: Buffer.alloc(2048) }, { name: 'small', data: 'x' }]), { maxFiles: 10, maxFileBytes: 1024 });
    expect(big.ok && big.entries.map((e) => e.path)).toEqual(['small']);
    const many = readTar(github([{ name: 'a', data: '1' }, { name: 'b', data: '2' }, { name: 'c', data: '3' }]), { maxFiles: 2, maxFileBytes: 1024 });
    expect(many.ok).toBe(false);
  });

  it('reports a truncated archive instead of crashing', () => {
    const a = github([{ name: 'x', data: 'y'.repeat(2000) }]);
    expect(readTar(a.subarray(0, 1100)).ok).toBe(false);
  });

  const safeName = fc.stringMatching(/^[a-z0-9][a-z0-9._-]{0,10}$/);
  const pathArb = fc.array(safeName, { minLength: 1, maxLength: 4 }).map((p) => p.join('/'));

  it('PBT-TAR-01: any set of files round-trips through tar, read and write with identical bytes', () => {
    fc.assert(
      fc.property(fc.uniqueArray(fc.tuple(pathArb, fc.uint8Array({ maxLength: 700 })), { selector: ([p]) => p, maxLength: 8 }), (files) => {
        // A path cannot be both a file and a folder.
        const paths = files.map(([p]) => p);
        fc.pre(!paths.some((a) => paths.some((b) => b.startsWith(`${a}/`))));
        const target = tmp();
        const r = readTar(github(files.map(([name, data]) => ({ name, data: Buffer.from(data) }))));
        if (!r.ok) throw new Error(r.error);
        writeEntries(target, r.entries);
        expect(listAll(target)).toEqual([...paths].sort());
        for (const [p, data] of files) expect(new Uint8Array(readFileSync(join(target, p)))).toEqual(data);
        return true;
      }),
      { numRuns: 40 },
    );
  });

  it('PBT-TAR-02: whatever the entry names, nothing is ever written outside the target', () => {
    const hostile = fc.oneof(
      pathArb,
      pathArb.map((p) => `../${p}`),
      pathArb.map((p) => `${p}/../../..`),
      pathArb.map((p) => `/${p}`),
      fc.string({ maxLength: 30 }),
    );
    fc.assert(
      fc.property(fc.array(hostile, { maxLength: 6 }), (names) => {
        const box = tmp();
        const target = join(box, 'inside');
        const r = readTar(tar(names.map((n) => ({ name: `repo-HEAD/${n}`, data: 'z' }))));
        if (r.ok) writeEntries(target, r.entries);
        expect(readdirSync(box).filter((x) => x !== 'inside')).toEqual([]);
        return true;
      }),
      { numRuns: 60 },
    );
  });
});

describe('fetchGithubRepo', () => {
  const body = (b: Buffer) => (async function* () { for (let i = 0; i < b.length; i += 97) yield b.subarray(i, i + 97); })();
  const fake = (status: number, gz: Buffer | null): FetchLike => async () => ({ ok: status === 200, status, body: gz ? body(gz) : null });

  it('downloads, unpacks and reports counts', async () => {
    const dir = join(tmp(), 'repo');
    const r = await fetchGithubRepo({ owner: 'o', repo: 'r', dir, fetchImpl: fake(200, gzipSync(github([{ name: 'README.md', data: 'hello' }]))) });
    expect(r).toEqual({ ok: true, files: 1, skipped: 1 });
    expect(readFileSync(join(dir, 'README.md'), 'utf8')).toBe('hello');
  });

  it('reports a missing or private repository', async () => {
    expect(await fetchGithubRepo({ owner: 'o', repo: 'r', dir: tmp(), fetchImpl: fake(404, null) })).toMatchObject({ ok: false, error: expect.stringContaining('not found') });
  });

  it('stops at the compressed and unpacked size limits', async () => {
    const gz = gzipSync(github([{ name: 'a', data: Buffer.alloc(200_000) }]));
    expect(await fetchGithubRepo({ owner: 'o', repo: 'r', dir: tmp(), fetchImpl: fake(200, gz), limits: { maxCompressedBytes: 100 } }))
      .toMatchObject({ ok: false, error: expect.stringContaining('larger than') });
    expect(await fetchGithubRepo({ owner: 'o', repo: 'r', dir: tmp(), fetchImpl: fake(200, gz), limits: { maxUnpackedBytes: 10_000 } }))
      .toMatchObject({ ok: false, error: expect.stringContaining('larger than') });
  });

  it('refuses names that are not plain owner and repository names', async () => {
    expect((await fetchGithubRepo({ owner: '../x', repo: 'r', dir: tmp(), fetchImpl: fake(200, null) })).ok).toBe(false);
  });

  it('reports a timeout', async () => {
    const hang: FetchLike = (_u, init) => new Promise((_res, rej) => init.signal.addEventListener('abort', () => rej(new Error('aborted'))));
    expect(await fetchGithubRepo({ owner: 'o', repo: 'r', dir: tmp(), fetchImpl: hang, timeoutMs: 50 })).toMatchObject({ ok: false, error: expect.stringContaining('too long') });
  });
});
