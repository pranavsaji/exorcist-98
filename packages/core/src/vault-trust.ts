/**
 * Backups in the Quarantine Vault (`.exorcist/vault/<id>/...`) are exact copies
 * of possessed files, so a scan finds every threat in them again. The vault is
 * NOT skipped (anything could be committed there to hide from the scanner).
 * Instead, on a local scan, a file is recognised as a genuine backup only when
 * all of this holds, and its findings are then reported at low severity with
 * a note rather than hidden:
 *
 * - `<id>/manifest.json` exists, is valid, and names the same id;
 * - the file is the backup that manifest describes (`files/<rel>` of an
 *   exorcism, `files/<name>` of a quarantined file, `entry.json` of a server);
 * - its sha256 equals the hash the CLI recorded;
 * - the manifest's target is this project, by absolute path (a vault committed
 *   to a repository and checked out somewhere else does not match).
 *
 * Remote, tarball, zip and MCP-server scans never use this.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename, isAbsolute, join, relative, resolve } from 'node:path';
import { z } from 'zod';
import type { Finding } from './types.js';

const ManifestSchema = z.object({
  id:     z.string(),
  kind:   z.enum(['mcp-server', 'file', 'exorcise']),
  target: z.string(),
  sha256: z.string(),
  files:  z.array(z.object({ rel: z.string(), sha256: z.string() })).optional(),
});
type Manifest = z.infer<typeof ManifestSchema>;

export type VaultBackup = { id: string; kind: Manifest['kind'] };

const VAULT_PATH = /^(?:(.*)\/)?\.exorcist\/vault\/([^/]+)\/(.+)$/;

const inside = (dir: string, p: string): boolean => {
  const r = relative(dir, p);
  return r === '' || (!r.startsWith('..') && !isAbsolute(r));
};

/** A checker for one scan root. Manifests are read once per vault entry. */
export function vaultBackupChecker(root: string): (rel: string, bytes: Buffer) => VaultBackup | null {
  const absRoot = resolve(root);
  const manifests = new Map<string, Manifest | null>();
  return (rel, bytes) => {
    const m = VAULT_PATH.exec(rel.replace(/\\/g, '/'));
    if (!m) return null;
    const [, prefix, id, inner] = m;
    if (!id || !inner || inner === 'manifest.json') return null;
    const project = join(absRoot, prefix ?? '');
    const key = `${project}\0${id}`;
    if (!manifests.has(key)) {
      let parsed: Manifest | null = null;
      try {
        const r = ManifestSchema.safeParse(JSON.parse(readFileSync(join(project, '.exorcist', 'vault', id, 'manifest.json'), 'utf8')));
        parsed = r.success && r.data.id === id ? r.data : null;
      } catch {
        parsed = null;
      }
      manifests.set(key, parsed);
    }
    const e = manifests.get(key);
    if (!e) return null;
    const digest = createHash('sha256').update(bytes).digest('hex');
    const target = resolve(e.target);
    if (e.kind === 'exorcise') {
      if (target !== project) return null;
      const f = e.files?.find((x) => `files/${x.rel}` === inner);
      return f && f.sha256 === digest ? { id, kind: e.kind } : null;
    }
    if (!inside(project, target)) return null;
    const expected = e.kind === 'mcp-server' ? 'entry.json' : `files/${basename(target)}`;
    return inner === expected && e.sha256 === digest ? { id, kind: e.kind } : null;
  };
}

/** A finding in a verified backup: low severity, with where it came from. */
export function asBackupFinding(f: Finding, b: VaultBackup): Finding {
  const who = b.kind === 'exorcise' ? 'exorcist exorcise' : 'the Quarantine Vault';
  return { ...f, severity: 'low', fix: `Backup copy kept by ${who} (restore with exorcist vault restore ${b.id}). ${f.fix}` };
}
