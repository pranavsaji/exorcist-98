/**
 * `exorcist origin [dir]`: scan, then walk git history to name the commit
 * that introduced each threat - an infection timeline.
 *
 * Commit subjects, author names, file paths and spans all come from the
 * repository, so they are attacker-controlled. The core sanitises commit
 * text; this file additionally shows paths and spans with every control or
 * hidden character as a visible [U+XXXX] marker. Nothing is interpreted.
 */

import { existsSync, realpathSync, statSync } from 'node:fs';
import { posix, relative, resolve, sep } from 'node:path';
import {
  displayMessage, loadDefinitions, openRepo, plainFor, scanRepo,
  shortSha, traceOrigins, buildTimeline, OriginReportSchema, ORIGIN_TIMEOUT_MS, ORIGIN_TOTAL_TIMEOUT_MS,
} from '@exorcist-98/core';
import type { Finding, OriginReport, TimelineThreat } from '@exorcist-98/core';
import { findDefinitionsDir, parse, str, strs } from '../util.js';
import type { Io } from '../util.js';
import { SEVERITY_RANK, isIgnored, readIgnoreFile } from './scan.js';

export const ORIGIN_HELP = `Usage: exorcist origin [dir] [options]

Scan a git repository, then walk its history to find the commit that
introduced each threat: an infection timeline, oldest first, grouped by
commit ("a1b2c3d by dependabot[bot] (bot) on 2026-10-02 added 3 threats").

Options:
  --format <text|json>   Output format (default: text)
  --max-time <seconds>   Stop tracing after this long in total (default: ${ORIGIN_TOTAL_TIMEOUT_MS / 1000}).
                         Each finding gets at most ${ORIGIN_TIMEOUT_MS / 1000} s of git time.
  --definitions <dir>    Folder of virus definitions (YAML)
  --ignore <path>        Skip a path prefix (repeatable)
  --fail-on <critical|high|medium|low|none>
                         Exit 1 if a finding is at least this bad (default: high)

The directory defaults to the current folder and must be inside a git
repository. On a shallow clone the oldest commit shown may only be where
the clone was cut; fetch full history (git fetch --unshallow) for the truth.
Commit subjects and author names are shown with control and hidden
characters removed: they are written by whoever made the commit.
git only reads committed history, never the working tree, and a repository
whose own git config names programs (filters, textconv, fsmonitor, hooks,
includes) is refused before git runs: clone it fresh instead.
`;

export const SHALLOW_NOTE =
  'Note: this is a shallow clone, so history before the clone point is missing. A commit marked "shallow cut-off" may not be the true origin; run git fetch --unshallow for full history.';

/** A repository path or span made safe for the terminal: one line, hidden characters as [U+XXXX]. */
const shown = (s: string, max = 120): string => {
  const one = displayMessage(s.replace(/[\t\n\r]+/g, ' ')).replace(/\s+/g, ' ').trim();
  return one.length <= max ? one : `${one.slice(0, max - 1)}…`;
};

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? '' : 's'}`;

function renderText(report: OriginReport): string {
  const lines: string[] = [];
  const files = plural(report.filesScanned, 'scanned file');
  lines.push(`Possession origin: ${plural(report.findingsTotal, 'threat')} in ${files} under ${shown(report.target, 400)}.`);
  for (const n of report.notes) lines.push(n);
  lines.push('');
  if (report.findingsTotal === 0) {
    lines.push('No threats found: nothing to trace.');
    return `${lines.join('\n')}\n`;
  }

  if (report.commits.length > 0) {
    lines.push('Infection timeline (oldest first):', '');
    for (const c of report.commits) {
      const who = c.bot ? `${c.author || '(no name)'} (bot)` : c.author || '(no name)';
      const when = c.date ? c.date.slice(0, 10) : 'an unknown date';
      lines.push(`${shortSha(c.sha)} by ${who} on ${when} added ${plural(c.threats.length, 'threat')}`);
      lines.push(`    subject: "${c.subject}"`);
      if (c.boundary) lines.push('    shallow cut-off: history before this commit is missing, so the threat may be older');
      if (c.hiddenText) lines.push('    warning: this commit\'s author or subject carried hidden or control characters (removed above)');
      for (const t of c.threats) lines.push(...threatLines(t));
      lines.push('');
    }
  }

  if (report.unknown.length > 0) {
    lines.push(`Origin unknown (${report.unknown.length}):`);
    for (const t of report.unknown) {
      lines.push(`    ${t.severity.toUpperCase().padEnd(8)} ${shown(t.file, 200)}:${t.line}  ${t.ruleId}: ${t.reason ?? t.origin}`);
    }
    lines.push('');
  }

  const bots = report.commits.filter((c) => c.bot).length;
  const traced = report.commits.reduce((n, c) => n + c.threats.length, 0);
  let summary = `${plural(traced, 'threat')} traced to ${plural(report.commits.length, 'commit')}`;
  if (bots > 0) summary += ` (${bots} by a bot)`;
  if (report.unknown.length > 0) summary += `; ${report.unknown.length} not traced`;
  lines.push(`${summary}.`);
  return `${lines.join('\n')}\n`;
}

function threatLines(t: TimelineThreat): string[] {
  const headline = plainFor(t.ruleId, t.title).headline;
  return [
    `    ${t.severity.toUpperCase().padEnd(8)} ${shown(t.file, 200)}:${t.line}  ${headline} (${t.ruleId})`,
    `             found: ${shown(t.span)}`,
  ];
}

export async function originCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, {
    format: { type: 'string' }, definitions: { type: 'string' }, 'fail-on': { type: 'string' },
    ignore: { type: 'string', multiple: true }, 'max-time': { type: 'string' }, help: { type: 'boolean', short: 'h' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${ORIGIN_HELP}`); return 2; }
  if (p.values['help']) { io.out(ORIGIN_HELP); return 0; }

  const format = str(p.values['format']) ?? 'text';
  if (format !== 'text' && format !== 'json') { io.err(`Unknown format "${format}". Use text or json.\n\n${ORIGIN_HELP}`); return 2; }
  const failOn = str(p.values['fail-on']) ?? 'high';
  if (failOn !== 'none' && !(failOn in SEVERITY_RANK)) { io.err(`Unknown --fail-on "${failOn}". Use critical, high, medium, low or none.`); return 2; }
  const rawMax = str(p.values['max-time']);
  const maxSeconds = rawMax === undefined ? ORIGIN_TOTAL_TIMEOUT_MS / 1000 : Number(rawMax);
  if (!Number.isInteger(maxSeconds) || maxSeconds < 1 || maxSeconds > 3600) { io.err('--max-time must be a whole number of seconds from 1 to 3600.'); return 2; }
  const totalMs = maxSeconds * 1000;

  if (p.positionals.length > 1) { io.err(`Give at most one directory.\n\n${ORIGIN_HELP}`); return 2; }
  const target = resolve(p.positionals[0] ?? '.');
  if (!existsSync(target) || !statSync(target).isDirectory()) { io.err(`Not a directory: ${target}`); return 2; }

  // The repository's own git config is checked before git runs at all: a
  // downloaded folder can carry a .git/config that names programs.
  const repo = await openRepo(target);
  if (!repo.ok) {
    if (repo.kind === 'not-a-repo' || repo.kind === 'git') {
      io.err(`Not a git repository (or git could not open it): ${target}. "exorcist origin" needs git history to trace; use "exorcist scan" without it.`);
    } else {
      io.err(`Refusing to run git in ${target}: ${repo.message}`);
    }
    return 2;
  }
  const { root: repoRoot, shallow, boundaries } = repo;
  // git prints the canonical spelling of the root (/private/var/... on
  // macOS); match the target's spelling before working out the prefix.
  const scanRoot = realpathSync(target);
  const prefix = relative(realpathSync(repoRoot), scanRoot).split(sep).join('/');
  if (prefix.startsWith('..')) { io.err(`The folder is outside the git repository git reported (${repoRoot}).`); return 2; }

  const defsDir = findDefinitionsDir(str(p.values['definitions']));
  if (!defsDir) { io.err('Could not find the virus definitions. Pass --definitions <dir> or set EXORCIST_DEFINITIONS.'); return 2; }
  try {
    if ((await loadDefinitions(defsDir)).length === 0) {
      io.err(`No virus definitions were found in ${defsDir}, so the scan would find nothing. Check --definitions.`);
      return 2;
    }
  } catch (err) {
    io.err(`Could not load the virus definitions from ${defsDir}: ${String(err).split('\n')[0]}`);
    return 2;
  }

  const ignore = [...strs(p.values['ignore']), ...readIgnoreFile(scanRoot)];
  const findings: Finding[] = [];
  let counted = 0;
  try {
    for await (const ev of scanRepo(scanRoot, { definitionsDir: defsDir })) {
      if (ev.type === 'finding') {
        if (!isIgnored(ev.finding.file, ignore)) findings.push(ev.finding);
      } else if (ev.type === 'file') {
        if (!isIgnored(ev.file.rel, ignore)) counted++;
      }
    }
  } catch (err) {
    io.err(`The scan failed: ${String(err).split('\n')[0]}`);
    return 2;
  }

  // Git paths are relative to the repository root; findings to the scanned folder.
  const gitPath = (file: string): string => (prefix ? posix.join(prefix, file) : file);
  const hits = await traceOrigins(
    repoRoot,
    findings.map((f) => ({ file: gitPath(f.file), line: f.line, span: f.span })),
    { perFindingMs: ORIGIN_TIMEOUT_MS, totalMs, boundaries },
  );
  const { commits, unknown } = buildTimeline(findings.map((f, i) => ({
    threat: { ruleId: f.ruleId, severity: f.severity, file: f.file, line: f.line, title: f.title, span: f.span },
    hit: hits[i] ?? { status: 'error', reason: 'not traced' },
  })));

  const notes: string[] = [];
  if (shallow) notes.push(SHALLOW_NOTE);
  if (unknown.some((t) => t.origin === 'timeout')) notes.push(`Note: some findings were not traced within the time limits (${ORIGIN_TIMEOUT_MS / 1000} s each, ${maxSeconds} s in total; see --max-time).`);

  // Boundary check: the report parses against its own schema before it leaves the process.
  const checked = OriginReportSchema.safeParse({
    tool: 'exorcist-origin', target, repoRoot, shallowClone: shallow, notes,
    limits: { perFindingMs: ORIGIN_TIMEOUT_MS, totalMs },
    commits, unknown, filesScanned: counted, findingsTotal: findings.length,
  });
  if (!checked.success) {
    io.err(`Internal error: the origin report did not validate. ${checked.error.issues[0]?.message ?? ''}`);
    return 2;
  }

  io.out(format === 'json' ? `${JSON.stringify(checked.data, null, 2)}\n` : renderText(checked.data));

  if (failOn === 'none') return 0;
  const limit = SEVERITY_RANK[failOn] ?? 0;
  return findings.some((f) => (SEVERITY_RANK[f.severity] ?? 9) <= limit) ? 1 : 0;
}
