import {
  BUNDLED_DEFINITIONS_DATE,
  BUNDLED_DEFINITIONS_VERSION,
  DEFINITIONS_PUBLIC_KEY,
  activeDefinitions,
  compareVersions,
  inspectInstalledSets,
  installedDefinitionsRoot,
  publicKeyFingerprint,
  runLiveUpdate,
} from '@exorcist-98/core';
import type { UpdateFetchLike } from '@exorcist-98/core';
import { parse, str } from '../util.js';
import type { Io } from '../util.js';

const UPDATE_HELP = `Usage: exorcist update [--from <https-url-or-file>]
       exorcist update --status

LiveUpdate: fetch a signed virus definitions bundle, verify it and install it.

Options:
  --from <src>   An https:// URL or a local .tar file. Default: EXORCIST_UPDATE_URL.
  --status       Show which definitions are active and what is installed.

A bundle installs only when its Ed25519 signature (checked against the key
built into Exorcist 98), every file hash, every YAML definition and its
version (newer than the definitions in use) all check out. Downloads are
https only, at most 2 MB and 15 seconds. Sets go to ~/.exorcist/definitions/
<version>/ (or EXORCIST_DEFINITIONS_HOME). Any failure leaves the current
definitions untouched.
`;

/** Injected by tests; the real CLI always uses the embedded key and real fetch. */
export type UpdateDeps = {
  publicKeyPem?: string;
  fetchImpl?: UpdateFetchLike;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  timeoutMs?: number;
};

export async function updateCommand(argv: string[], io: Io, deps: UpdateDeps = {}): Promise<number> {
  const p = parse(argv, { from: { type: 'string' }, status: { type: 'boolean' }, help: { type: 'boolean', short: 'h' } });
  if (!p.ok) { io.err(`${p.error}\n\n${UPDATE_HELP}`); return 2; }
  if (p.values['help']) { io.out(UPDATE_HELP); return 0; }
  if (p.positionals.length > 0) { io.err(`Unexpected argument: ${p.positionals[0]}\n\n${UPDATE_HELP}`); return 2; }

  const env = deps.env ?? process.env;
  const root = installedDefinitionsRoot(env);
  const publicKeyPem = deps.publicKeyPem ?? DEFINITIONS_PUBLIC_KEY;

  if (p.values['status'] === true) {
    if (p.values['from'] !== undefined) { io.err('--status and --from cannot be used together.'); return 2; }
    return status(io, root, publicKeyPem, env);
  }

  const from = str(p.values['from']) ?? env['EXORCIST_UPDATE_URL'];
  if (!from) {
    io.err(`No update source. Pass --from <https-url-or-file> or set EXORCIST_UPDATE_URL.\n\n${UPDATE_HELP}`);
    return 2;
  }

  io.out('Exorcist 98 LiveUpdate');
  const r = await runLiveUpdate({
    from,
    root,
    publicKeyPem,
    ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
    ...(deps.timeoutMs ? { timeoutMs: deps.timeoutMs } : {}),
    ...(deps.cwd ? { cwd: deps.cwd } : {}),
  });
  io.out(`Definitions in use: ${describe(r.previous.version, r.previous.date, r.previous.source)}`);
  if (!r.ok) {
    io.err(`LiveUpdate refused the bundle: ${r.error}`);
    io.err(`Nothing was installed. The definitions in use are unchanged (version ${r.previous.version}).`);
    return 1;
  }
  io.out(`Signature, hashes and all ${r.set.files} definitions verified (key sha256:${(publicKeyFingerprint(publicKeyPem) ?? '?').slice(0, 16)}...).`);
  io.out(`Installed definitions ${r.set.version} (${r.set.date}) into ${r.set.dir}`);
  io.out('The next scan and the next Shield start use them.');
  return 0;
}

function describe(version: string, date: string, source: 'installed' | 'bundled'): string {
  return `${version} (${date}, ${source === 'installed' ? 'installed by LiveUpdate' : 'bundled with this build'})`;
}

function status(io: Io, root: string, publicKeyPem: string, env: NodeJS.ProcessEnv): number {
  const active = activeDefinitions({ root, publicKeyPem });
  const sets = inspectInstalledSets(root, publicKeyPem);
  io.out('Exorcist 98 LiveUpdate status');
  io.out(`  Active definitions: ${describe(active.version, active.date, active.source)}`);
  if (active.set) io.out(`                      ${active.set.definitionsDir}`);
  const override = env['EXORCIST_DEFINITIONS'];
  if (override) io.out(`  Note: EXORCIST_DEFINITIONS is set, so scans use ${override} instead.`);
  io.out(`  Bundled with this build: ${BUNDLED_DEFINITIONS_VERSION} (${BUNDLED_DEFINITIONS_DATE})`);
  io.out(`  Install folder: ${root}`);
  if (sets.length === 0) {
    io.out('  Installed sets: none. Run "exorcist update --from <https-url-or-file>".');
  } else {
    io.out('  Installed sets (newest first):');
    for (const s of sets) {
      if (!s.ok) io.out(`    ${s.name}  REJECTED, not used: ${s.error}`);
      else {
        const note = active.source === 'installed' && s.set.version === active.version ? 'active'
          : compareVersions(s.set.version, BUNDLED_DEFINITIONS_VERSION) <= 0 ? 'verified, unused: not newer than the bundled set'
            : 'verified, superseded by a newer set';
        io.out(`    ${s.name}  ${s.set.date}  ${s.set.files} definitions  ${note}`);
      }
    }
  }
  io.out(`  Trusted key: Ed25519 sha256:${publicKeyFingerprint(publicKeyPem) ?? 'unusable'}`);
  return 0;
}
