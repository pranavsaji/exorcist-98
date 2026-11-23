import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, isAbsolute, relative, resolve } from 'node:path';
import {
  FIXABLE_RULES, exorciseRepo, isFixableRule, loadDefinitions, plainFor, registryLookup, rescanTexts, scanRepo, toUnifiedDiff,
} from '@exorcist-98/core';
import type { FileExorcism, Finding, VersionLookup, VirusDefinition } from '@exorcist-98/core';
import { backupAndRewrite, vaultPath } from '@exorcist-98/shield';
import { isIgnored, readIgnoreFile } from './scan.js';
import { DEFAULT_DIR, findDefinitionsDir, parse, stateDir, str, strs } from '../util.js';
import type { Io } from '../util.js';

export const EXORCISE_HELP = `Usage: exorcist exorcise [path] [options]

Disinfect: repair the threats that have one safe, mechanical fix, and report
the rest. Without --write it only prints the changes as a unified diff
(save it with "> fix.patch" and apply it with "git apply fix.patch").

Fixes:
  EX-001  remove hidden characters (emoji sequences and real spelling are kept)
  EX-002  remove an HTML comment that holds instructions for an AI
  EX-004  remove a smuggled HTML comment
  EX-010  pin "npx pkg" / "uvx pkg" to the exact current version (looked up on
          npm or PyPI; skipped with a note when offline)
  EX-012  replace a data-carrying remote image with its alt text
  EX-021  remove runs of 4+ variation selectors (smuggled bytes); one to three,
          as in emoji, are never touched

Options:
  --write              Apply the changes. Every file is copied into the
                       Quarantine Vault first; "exorcist vault restore <id>" undoes it.
  --only <ids>         Only these fixes, e.g. --only EX-001,EX-010
  --offline            Do not look up versions (EX-010 is skipped)
  --ignore <path>      Skip a path prefix (repeatable; .exorcistignore is read too)
  --definitions <dir>  Folder of virus definitions (YAML)
  --dir <folder>       State folder for the vault (default: ${DEFAULT_DIR})
`;

export type ExorciseDeps = { lookup?: VersionLookup | null };

function parseOnly(raw: string[]): { ok: true; ids: string[] } | { ok: false; error: string } {
  if (raw.length === 0) return { ok: true, ids: [...FIXABLE_RULES] };
  const ids = raw.flatMap((r) => r.split(',')).map((s) => s.trim().toUpperCase()).filter(Boolean);
  const bad = ids.filter((id) => !isFixableRule(id));
  if (bad.length > 0) return { ok: false, error: `${bad.join(', ')} cannot be fixed automatically. Fixable: ${FIXABLE_RULES.join(', ')}.` };
  return { ok: true, ids: [...new Set(ids)] };
}

const where = (f: { file: string; line: number; col: number }): string => `${f.file}:${f.line}:${f.col}`;

function changeLines(results: readonly FileExorcism[]): string[] {
  const out: string[] = [];
  for (const r of results) {
    for (const c of r.changes) out.push(`  ${c.ruleId}  ${where({ file: r.file, ...c })}  ${c.summary}`);
  }
  return out;
}

function noteLines(results: readonly FileExorcism[]): string[] {
  const out: string[] = [];
  for (const r of results) for (const n of r.notes) out.push(`  ${n.ruleId}  ${where({ file: r.file, ...n })}  ${n.message}`);
  return out;
}

function humanLines(findings: readonly Finding[], max = 25): string[] {
  const out = findings.slice(0, max).map((f) => `  ${f.severity.toUpperCase().padEnd(8)} ${where(f)}  ${plainFor(f.ruleId, f.title).headline} (${f.ruleId})`);
  if (findings.length > max) out.push(`  ... and ${findings.length - max} more (run "exorcist scan" for the full list)`);
  return out;
}

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? '' : /(?:x|s|ch)$/.test(word) ? 'es' : 's'}`;

export async function exorciseCommand(argv: string[], io: Io, deps: ExorciseDeps = {}): Promise<number> {
  const p = parse(argv, {
    write: { type: 'boolean' }, only: { type: 'string', multiple: true }, offline: { type: 'boolean' },
    ignore: { type: 'string', multiple: true }, definitions: { type: 'string' }, dir: { type: 'string' },
    help: { type: 'boolean', short: 'h' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${EXORCISE_HELP}`); return 2; }
  if (p.values['help']) { io.out(EXORCISE_HELP); return 0; }
  if (p.positionals.length > 1) { io.err(`Give at most one folder or file.\n\n${EXORCISE_HELP}`); return 2; }
  const only = parseOnly(strs(p.values['only']));
  if (!only.ok) { io.err(only.error); return 2; }

  const target = p.positionals[0] ?? '.';
  const abs = resolve(target);
  if (!existsSync(abs)) { io.err(`Path not found: ${target}`); return 2; }
  const isFile = statSync(abs).isFile();
  const root = isFile ? dirname(abs) : abs;
  const single = isFile ? basename(abs) : null;

  const defsDir = findDefinitionsDir(str(p.values['definitions']));
  if (!defsDir) { io.err('Could not find the virus definitions. Pass --definitions <dir> or set EXORCIST_DEFINITIONS.'); return 2; }
  let defs: VirusDefinition[];
  try {
    defs = await loadDefinitions(defsDir);
  } catch (err) {
    io.err(`Could not load the virus definitions from ${defsDir}: ${String(err).split('\n')[0]}`);
    return 2;
  }
  if (defs.length === 0) { io.err(`No virus definitions were found in ${defsDir}. Check --definitions.`); return 2; }

  // The vault holds the original (possessed) copies: never scan or fix those.
  const vault = vaultPath(stateDir(str(p.values['dir'])));
  const state = relative(root, resolve(vault, '..'));
  const ignore = [...strs(p.values['ignore']), ...readIgnoreFile(root)];
  if (state === '' ) ignore.push('vault');
  else if (!state.startsWith('..') && !isAbsolute(state)) ignore.push(state.replace(/\\/g, '/'));
  const keep = (rel: string): boolean => (single === null || rel === single) && !isIgnored(rel, ignore);

  const findings: Finding[] = [];
  try {
    for await (const ev of scanRepo(root, { definitionsDir: defsDir, trustVault: true })) {
      if (ev.type === 'finding' && keep(ev.finding.file)) findings.push(ev.finding);
    }
  } catch (err) {
    io.err(`The scan failed: ${String(err).split('\n')[0]}`);
    return 2;
  }

  const offline = p.values['offline'] === true || process.env['EXORCIST_OFFLINE'] === '1';
  const lookup = deps.lookup !== undefined ? deps.lookup : offline ? null : registryLookup({ timeoutMs: 5000 });
  const results = await exorciseRepo(root, findings, { only: only.ids, lookup });
  const changed = results.filter((r) => r.after !== r.before);
  const fixes = changed.reduce((n, r) => n + r.changeCount, 0);
  const notes = noteLines(results);

  if (p.values['write'] !== true) {
    const patch = toUnifiedDiff(results);
    if (patch.patch) io.out(patch.patch);
    const summary: string[] = [];
    if (fixes === 0) summary.push(`Nothing to exorcise automatically (${plural(findings.length, 'threat')} found).`);
    else {
      summary.push(`Dry run: ${plural(fixes, 'fix')} in ${plural(changed.length, 'file')}. Nothing was changed.`);
      summary.push(...changeLines(changed));
    }
    if (notes.length) summary.push('', 'Left for a human:', ...notes);
    if (fixes > 0) summary.push('', 'Run again with --write to apply them (each file is backed up in the Quarantine Vault first).');
    io.err(summary.join('\n'));
    return 0;
  }

  if (changed.length === 0) {
    io.out([`Nothing to exorcise automatically. ${plural(findings.length, 'threat')} need${findings.length === 1 ? 's' : ''} a human.`, ...humanLines(findings), ...(notes.length ? ['', 'Notes:', ...notes] : [])].join('\n'));
    return 0;
  }
  const written = backupAndRewrite({
    root,
    files: changed.map((r) => ({ rel: r.file, before: r.before, after: r.after })),
    reason: `exorcise: ${plural(fixes, 'fix')} (${only.ids.join(', ')})`,
    vaultDir: vault,
  });
  if (!written.ok) { io.err(written.error); return 1; }

  // Re-scan the changed files as they are on disk now.
  const changedSet = new Set(changed.map((r) => r.file));
  const now = changed.map((r) => ({ file: r.file, text: readFileSync(resolve(root, r.file), 'utf8') }));
  const after = [...findings.filter((f) => !changedSet.has(f.file)), ...rescanTexts(now, defs).filter((f) => keep(f.file))];
  const removed = Math.max(0, findings.length - after.length);
  const dirFlag = str(p.values['dir']) ? ` --dir ${str(p.values['dir'])}` : '';
  io.out([
    `Exorcised ${plural(changed.length, 'file')} (${plural(fixes, 'fix')}):`,
    ...changeLines(changed),
    '',
    `Backup: Quarantine Vault entry ${written.value.id}`,
    `Undo with: exorcist vault restore ${written.value.id}${dirFlag}`,
    '',
    `${plural(removed, 'threat')} removed, ${after.length} need${after.length === 1 ? 's' : ''} a human.`,
    ...humanLines(after),
    ...(notes.length ? ['', 'Notes:', ...notes] : []),
  ].join('\n'));
  return 0;
}
