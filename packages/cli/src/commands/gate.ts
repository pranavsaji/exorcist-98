import { existsSync } from 'node:fs';
import { lstat, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  AGENT_FILE_HARD_LIMIT, gateFindings, isBlocking, isGateFile, gitRepoRoot, loadDefinitions, renderGate, runGit, tooLargeFinding,
} from '@exorcist-98/core';
import type { GateThreshold, SignatureFinding, VirusDefinition } from '@exorcist-98/core';
import { findDefinitionsDir, parse, str } from '../util.js';
import type { Io } from '../util.js';

export const GATE_HELP = `Usage: exorcist gate [dir] [--fail-on <critical|high|medium|low>]
The gate for the end of an agent's turn. It looks only at the files an AI agent
obeys (steering, specs, hooks, custom agents, MCP configs, AGENTS.md and the
other rule files, READMEs) that changed since the last commit, and exits 1 with
a short list when the change adds a finding at or above --fail-on (default high).
Findings that the committed version already had are ignored.
Read-only: it never writes, never uses the network and runs no repository program.
Exit codes: 0 nothing added (or nothing could be checked: the reason is printed
to stdout, so an environment problem never stops an agent), 1 the change adds a finding.
The Kiro hook written by "exorcist init" runs it when the agent stops.
`;

const THRESHOLDS: readonly GateThreshold[] = ['critical', 'high', 'medium', 'low'];
const GIT_MS = 10_000;

const nothingChecked = (io: Io, why: string): number => {
  io.out(`Exorcist gate: nothing checked (${why}).`);
  return 0;
};

/** Paths git lists, NUL separated. */
const paths = (stdout: string): string[] => stdout.split('\0').filter((p) => p !== '');

/**
 * Every file git knows (index) or could add (untracked, not ignored) that an
 * agent obeys. Only the index and .gitignore are read, so no clean filter or
 * other repository program runs; changed or not is decided by comparing the
 * file on disk with its committed blob.
 */
async function candidateFiles(root: string): Promise<{ ok: true; files: string[]; hasHead: boolean } | { ok: false; why: string }> {
  const head = await runGit(root, ['rev-parse', '--verify', '--quiet', 'HEAD^{commit}'], GIT_MS);
  const all = await runGit(root, ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], GIT_MS);
  if (!all.ok) return { ok: false, why: all.error.message };
  return { ok: true, files: [...new Set(paths(all.stdout))].filter(isGateFile).sort(), hasHead: head.ok };
}

async function committed(root: string, rel: string): Promise<string | null> {
  const r = await runGit(root, ['cat-file', 'blob', `HEAD:${rel}`], GIT_MS);
  return r.ok ? r.stdout : null;
}

/** Committed object ids of the given paths (one git call). Paths not in HEAD are absent from the map. */
async function committedIds(root: string, wanted: ReadonlySet<string>): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const r = await runGit(root, ['ls-tree', '-r', '-z', 'HEAD'], GIT_MS);
  if (!r.ok) return out;
  for (const entry of paths(r.stdout)) {
    const tab = entry.indexOf('\t');
    const path = entry.slice(tab + 1);
    if (tab > 0 && wanted.has(path)) out.set(path, entry.slice(0, tab).split(' ')[2] ?? '');
  }
  return out;
}

/** Object ids of the files on disk, as git would store them without any filter (one git call). */
async function diskIds(root: string, rels: readonly string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  if (rels.length === 0) return out;
  const r = await runGit(root, ['hash-object', '--no-filters', '--', ...rels], GIT_MS);
  if (!r.ok) return out;
  const ids = r.stdout.split('\n');
  rels.forEach((rel, i) => { const id = ids[i]; if (id) out.set(rel, id); });
  return out;
}

export async function gateCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, { 'fail-on': { type: 'string' }, definitions: { type: 'string' }, help: { type: 'boolean', short: 'h' } });
  if (!p.ok) { io.err(`${p.error}\n\n${GATE_HELP}`); return 2; }
  if (p.values['help']) { io.out(GATE_HELP); return 0; }
  if (p.positionals.length > 1) { io.err(`Give at most one folder.\n\n${GATE_HELP}`); return 2; }
  const failOn = str(p.values['fail-on']) ?? 'high';
  const threshold = THRESHOLDS.find((t) => t === failOn);
  if (!threshold) { io.err(`--fail-on must be one of: ${THRESHOLDS.join(', ')}.\n\n${GATE_HELP}`); return 2; }

  const start = resolve(p.positionals[0] ?? '.');
  if (!existsSync(start)) return nothingChecked(io, 'that folder does not exist');
  const top = await gitRepoRoot(start);
  if (!top) return nothingChecked(io, 'this folder is not a git repository, or git is not available');
  const repo = { root: top };
  const changed = await candidateFiles(repo.root);
  if (!changed.ok) return nothingChecked(io, changed.why);
  const defsDir = findDefinitionsDir(str(p.values['definitions']));
  if (!defsDir) return nothingChecked(io, 'no virus definitions were found');
  let defs: VirusDefinition[];
  try { defs = await loadDefinitions(defsDir); } catch { return nothingChecked(io, 'the virus definitions could not be loaded'); }

  // Which files differ from the last commit: compare object ids, read only those.
  const onDisk: string[] = [];
  const sizes = new Map<string, number>();
  for (const rel of changed.files) {
    const info = await lstat(resolve(repo.root, rel)).catch(() => null);
    if (!info || !info.isFile()) continue; // gone, a folder or a symlink: nothing of its own to read
    onDisk.push(rel);
    sizes.set(rel, info.size);
  }
  const ids = await diskIds(repo.root, onDisk);
  const then = changed.hasHead ? await committedIds(repo.root, new Set(onDisk)) : new Map<string, string>();
  const added: SignatureFinding[] = [];
  for (const rel of onDisk) {
    const id = ids.get(rel);
    if (id !== undefined && id === then.get(rel)) continue; // unchanged since the last commit
    const size = sizes.get(rel) ?? 0;
    if (size > AGENT_FILE_HARD_LIMIT) {
      const f = tooLargeFinding(rel, size, defs);
      if (f) added.push(f);
      continue;
    }
    const after = await readFile(resolve(repo.root, rel), 'utf8').catch(() => null);
    if (after === null) continue;
    const before = then.has(rel) ? await committed(repo.root, rel) : null;
    added.push(...gateFindings(rel, before, after, defs));
  }
  const blocking = added.filter((f) => isBlocking(f, threshold));
  if (blocking.length === 0) return 0;
  io.err(renderGate(blocking));
  return 1;
}
