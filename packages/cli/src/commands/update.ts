import { isAbsolute, resolve } from 'node:path';
import {
  DOWNLOAD_LIMIT_BYTES,
  activeVersion,
  downloadBundle,
  installBundle,
  installedDefinitionsRoot,
  listInstalledSets,
  trustedPublicKey,
} from '@exorcist-98/core';import { parse, str } from '../util.js';
import type { Io } from '../util.js';

const UPDATE_HELP = `Usage: exorcist update [--from <url-or-file>] [--status]

LiveUpdate: download a signed definitions bundle, verify it and install it.

Options:
  --from <url-or-file>   Where the bundle comes from: an https:// URL or a local
                         .tar file. Default: EXORCIST_UPDATE_URL.
  --status               Show which definitions set is active and what is
                         installed; change nothing.
  --home <dir>           Where installed sets live (default ~/.exorcist/definitions,
                         or EXORCIST_DEFINITIONS_HOME).

A bundle only installs when its Ed25519 signature, every file hash, every YAML
definition and its version all check out. Any failure leaves the current
definitions untouched.
`;

export async function updateCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, {
    from: { type: 'string' }, status: { type: 'boolean' }, home: { type: 'string' }, help: { type: 'boolean', short: 'h' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${UPDATE_HELP}`); return 2; }
  if (p.values['help']) { io.out(UPDATE_HELP); return 0; }

  const env = process.env;
  const root = p.values['home'] !== undefined || env['EXORCIST_DEFINITIONS_HOME'] !== undefined
    ? resolve(str(p.values['home']) ?? env['EXORCIST_DEFINITIONS_HOME']!)
    : installedDefinitionsRoot(env);
  const publicKey = trustedPublicKey(env);

  if (p.values['status'] === true) {
    return status(io, root, publicKey);
  }

  const from = str(p.values['from']) ?? env['EXORCIST_UPDATE_URL'];
  if (!from) {
    io.err(`No update source. Pass --from <url-or-file> or set EXORCIST_UPDATE_URL.\n\n${UPDATE_HELP}`);
    return 2;
  }

  const current = activeVersion({ env, root, publicKeyPem: publicKey });
  const source = describeSource(from);
  io.out(`Exorcist 98 LiveUpdate`);
  io.out(`Current definitions: ${current.version} (${current.date}, ${current.source === 'installed' ? 'updated' : 'bundled'})`);

  const tar = await fetchOrRead(from, env);
  if (!tar.ok) { io.err(tar.error); return 1; }

  const r = installBundle(tar.tar, { root, currentVersion: current.version, publicKeyPem: publicKey });
  if (!r.ok) { io.err(r.error); return 1; }
  io.out(`Installed definitions ${r.set.version} (${r.set.date}, ${r.set.files} rules) from ${source}.`);
  io.out(`The next scan uses the updated definitions.`);
  return 0;
}

function status(io: Io, root: string, publicKey: string): number {
  const current = activeVersion({ root, publicKeyPem: publicKey });
  const sets = listInstalledSets(root, publicKey);
  io.out('Definitions status');
  io.out(`  Active:   version ${current.version} (${current.date}) — ${current.source === 'installed' ? 'LiveUpdate set' : 'bundled with this build'}`);
  if (sets.length === 0) {
    io.out('  Installed updates: none. Run "exorcist update --from <url-or-file>".');
  } else {
    io.out('  Installed updates (newest first):');
    for (const s of sets) {
      io.out(`    ${s.version}  ${s.date}  ${s.files} rules  ${s.dir}`);
    }
  }
  io.out(`  Install root: ${root}`);
  io.out(`  Trusted key: ${publicKey.includes('BEGIN PUBLIC KEY') ? 'Ed25519 (' + (publicKey === trustedPublicKey() ? 'embedded' : 'from EXORCIST_DEFINITIONS_PUBLIC_KEY') + ')' : 'custom'}`);
  return 0;
}

function describeSource(from: string): string {
  return isAbsolute(from) || !/^https?:\/\//i.test(from) ? `local file ${resolve(from)}` : from;
}

async function fetchOrRead(from: string, env: NodeJS.ProcessEnv): Promise<{ ok: true; tar: Buffer } | { ok: false; error: string }> {
  if (/^https:\/\//i.test(from)) {
    return downloadBundle(from, { limitBytes: DOWNLOAD_LIMIT_BYTES });
  }
  if (/^http:\/\//i.test(from)) {
    return { ok: false, error: 'The update source must be an https:// URL or a local file.' };
  }
  const { readFile, stat } = await import('node:fs/promises');
  const path = resolve(from);
  try {
    const st = await stat(path);
    if (st.size > DOWNLOAD_LIMIT_BYTES) {
      return { ok: false, error: `The bundle is larger than the ${Math.round(DOWNLOAD_LIMIT_BYTES / 1024)} KB limit.` };
    }
    if (st.size === 0) return { ok: false, error: 'The bundle is empty.' };
    return { ok: true, tar: await readFile(path) };
  } catch (e) {
    return { ok: false, error: `Could not read the update source: ${(e as Error).message}` };
  }
}
