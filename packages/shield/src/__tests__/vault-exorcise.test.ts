import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { backupAndRewrite, diffEntry, listEntries, restoreEntry } from '../vault.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'vault-exo-')); dirs.push(d); return d; };

describe('vault: exorcised files (m5-exorcise REQ-02.2)', () => {
  it('backs up exact bytes before writing, diffs and restores them', () => {
    const root = tmp();
    const vault = join(tmp(), 'vault');
    const original = 'a​b\r\nc\n';
    writeFileSync(join(root, 'A.md'), original);
    const r = backupAndRewrite({ root, files: [{ rel: 'A.md', before: original, after: 'ab\r\nc\n' }], reason: 'test', vaultDir: vault });
    if (!r.ok) throw new Error(r.error);
    expect(r.value.kind).toBe('exorcise');
    expect(readFileSync(join(root, 'A.md'), 'utf8')).toBe('ab\r\nc\n');
    expect(readFileSync(join(vault, r.value.id, 'files', 'A.md'), 'utf8')).toBe(original);
    const d = diffEntry(vault, r.value.id);
    expect(d.ok && d.value).toContain('A.md (backup)');
    expect(listEntries(vault)[0]?.files?.[0]?.rel).toBe('A.md');
    expect(restoreEntry(vault, r.value.id).ok).toBe(true);
    expect(readFileSync(join(root, 'A.md'), 'utf8')).toBe(original);
  });

  it('writes nothing when a file changed since it was scanned', () => {
    const root = tmp();
    const vault = join(tmp(), 'vault');
    writeFileSync(join(root, 'A.md'), 'now different');
    const r = backupAndRewrite({ root, files: [{ rel: 'A.md', before: 'what was scanned', after: 'x' }], reason: 't', vaultDir: vault });
    expect(r.ok).toBe(false);
    expect(readFileSync(join(root, 'A.md'), 'utf8')).toBe('now different');
    expect(existsSync(vault)).toBe(false);
  });

  it('refuses paths outside the folder', () => {
    const root = tmp();
    for (const rel of ['../x.md', '/etc/passwd', 'a/../../x', 'a\\b']) {
      const r = backupAndRewrite({ root, files: [{ rel, before: '', after: 'x' }], reason: 't', vaultDir: join(root, 'v') });
      expect(r.ok, rel).toBe(false);
    }
  });
});
