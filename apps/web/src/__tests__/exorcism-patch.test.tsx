import { describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { renderToStaticMarkup } from 'react-dom/server';
import { scanRepo } from '@exorcist-98/core';
import type { Finding, VersionLookup } from '@exorcist-98/core';
import { ExorcismPatch } from '@/components/ExorcismPatch';
import { buildPatchEvent, scanTarget } from '@/lib/scan-service';
import { definitionsDir } from '@/lib/paths';
import { PATCH_MAX_BYTES, PatchEventSchema, ScanEventSchema } from '@/lib/protocol';
import { patchFile } from '@/lib/report';
import { initialScanState, scanReducer } from '@/lib/scan-state';
import type { PatchEvent, ScanEventMsg } from '@/lib/protocol';

vi.spyOn(console, 'log').mockImplementation(() => undefined);

async function haunted(lookup?: VersionLookup | null): Promise<ScanEventMsg[]> {
  const out: ScanEventMsg[] = [];
  for await (const ev of scanTarget({ kind: 'haunted-repo', display: 'Haunted Repo' }, lookup === undefined ? {} : { lookup })) out.push(ev);
  return out;
}

describe('REQ-03 the exorcism patch in the scan stream', { timeout: 60_000 }, () => {
  it('is the last event of a Haunted Repo scan and removes the hidden characters', async () => {
    const events = await haunted();
    for (const e of events) expect(ScanEventSchema.safeParse(e).success).toBe(true);
    const last = events.at(-1);
    expect(last?.type).toBe('patch');
    const p = last as PatchEvent;
    expect(p.files).toBeGreaterThanOrEqual(3);
    expect(p.fixes).toBeGreaterThanOrEqual(8);
    expect(p.patch).toContain('diff --git a/EX-001-hidden-unicode.md b/EX-001-hidden-unicode.md');
    expect(p.patch).toMatch(/^-Welcome​ to‌ this project\.$/m);
    expect(p.patch).toMatch(/^\+Welcome to this project\.$/m);
    expect(p.patch).toContain('+status <!-- exorcised: remote image removed -->');
    // Tests run offline (EXORCIST_OFFLINE=1): EX-010 is left out and counted.
    expect(p.patch).not.toContain('EX-010-unpinned-mcp-server.json');
    expect(p.skipped).toBeGreaterThanOrEqual(2);
    // Only fixable threats are touched: nothing from the other samples.
    for (const f of p.patch.matchAll(/^diff --git a\/(\S+)/gm)) {
      expect(['EX-001-hidden-unicode.md', 'EX-004-html-comment-smuggling.md', 'EX-012-markdown-image-exfil.md', 'EX-021-smuggled-bytes.md']).toContain(f[1]);
    }
  });

  it('pins unpinned MCP servers when versions can be looked up', async () => {
    const lookup: VersionLookup = async () => ({ ok: true, version: '2.4.0' });
    const p = (await haunted(lookup)).at(-1) as PatchEvent;
    expect(p.patch).toContain('+      "args": ["@modelcontextprotocol/server-filesystem@2.4.0", "/home/user/projects"],');
  });

  it('is built for uploaded and cloned projects too, before their copy is removed', async () => {
    const events: ScanEventMsg[] = [];
    for await (const ev of scanTarget({ kind: 'github', display: 'o/r', owner: 'o', repo: 'r' }, {
      lookup: null,
      clone: async (_t, dir) => {
        const { mkdir, writeFile } = await import('node:fs/promises');
        await mkdir(dir, { recursive: true });
        await writeFile(join(dir, 'AGENTS.md'), 'Be kind​​​​ to reviewers.\n');
      },
    })) events.push(ev);
    const p = events.at(-1) as PatchEvent;
    expect(p.type).toBe('patch');
    expect(p.patch).toContain('-Be kind​​​​ to reviewers.');
    expect(p.patch).toContain('+Be kind to reviewers.');
  });

  it('is never sent after a failed scan', async () => {
    const events: ScanEventMsg[] = [];
    for await (const ev of scanTarget({ kind: 'upload', display: 'x.zip', zip: Buffer.from('not a zip') })) events.push(ev);
    expect(events.some((e) => e.type === 'patch')).toBe(false);
  });

  it('is capped at 1 MB by whole files', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'exorcist-patch-'));
    try {
      writeFileSync(join(dir, 'AGENTS.md'), 'small​​​​ file\n');
      // Every line changes, so this file's diff alone is larger than the cap.
      const line = `${'x'.repeat(190)}​\n`;
      writeFileSync(join(dir, 'BIG.md'), line.repeat(Math.ceil(600_000 / line.length)));
      const findings: Finding[] = [];
      for await (const ev of scanRepo(dir, { definitionsDir: definitionsDir() })) if (ev.type === 'finding') findings.push(ev.finding);
      const p = await buildPatchEvent(dir, findings, null);
      expect(PatchEventSchema.safeParse(p).success).toBe(true);
      expect(Buffer.byteLength(p.patch, 'utf8')).toBeLessThanOrEqual(PATCH_MAX_BYTES);
      expect(p.omitted).toBe(1);
      expect(p.files).toBe(1);
      expect(p.patch).toContain('a/AGENTS.md');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const patch = (over: Partial<Omit<PatchEvent, 'type'>> = {}): Omit<PatchEvent, 'type'> => ({
  patch: 'diff --git a/a.md b/a.md\n', files: 2, fixes: 5, omitted: 0, skipped: 0, ...over,
});

describe('the exorcism patch on the page', () => {
  it('the reducer keeps it and logs it', () => {
    const s = scanReducer(scanReducer(initialScanState, { type: 'reset', target: 't' }), { type: 'event', event: { type: 'patch', ...patch() } });
    expect(s.patch).toEqual(patch());
    expect(s.log.at(-1)?.text).toBe('Exorcism patch ready: 5 safe fixes in 2 files.');
    expect(scanReducer(s, { type: 'reset', target: 'u' }).patch).toBeNull();
  });

  it('offers an accessible download button that says what it does', () => {
    const html = renderToStaticMarkup(<ExorcismPatch patch={patch({ skipped: 1 })} target="Haunted Repo" />);
    expect(html).toContain('<h4 id="exorcise-heading"');
    expect(html).toContain('aria-labelledby="exorcise-heading"');
    expect(html).toMatch(/<button type="button" class="btn font-bold" aria-describedby="exorcise-desc">Download exorcism patch<\/button>/);
    expect(html).toContain('id="exorcise-desc"');
    expect(html).toContain('5 threats in 2 files have a');
    expect(html).toContain('git apply exorcist-haunted-repo.patch');
    expect(html).toContain('1 fixable threat could not be fixed safely');
  });

  it('says so when nothing can be fixed automatically, or the patch is too big', () => {
    const none = renderToStaticMarkup(<ExorcismPatch patch={patch({ patch: '', files: 0, fixes: 0 })} target="t" />);
    expect(none).not.toContain('<button');
    expect(none).toContain('No threat in this scan has a safe automatic fix');
    const big = renderToStaticMarkup(<ExorcismPatch patch={patch({ patch: '', files: 0, fixes: 0, omitted: 3 })} target="t" />);
    expect(big).toContain('larger than 1 MB');
  });

  it('downloads as a .patch file', () => {
    expect(patchFile('owner/repo@main', 'x')).toEqual({ filename: 'exorcist-owner-repo-main.patch', mime: 'text/x-diff', body: 'x' });
  });
});
