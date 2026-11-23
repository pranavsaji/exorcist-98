/**
 * `exorcist origin [dir]`: scan, then walk git history to name the commit
 * that introduced each threat — an infection timeline.
 */

import { existsSync, realpathSync, statSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { loadDefinitions, plainFor, scanRepo } from '@exorcist-98/core';
import {
  findOriginCommit, gitRepoRoot, isShallowClone, shortSha,
  sortCommitsByDate, OriginReportSchema,
} from '@exorcist-98/core';
import type { Finding, ScanStats, OriginHit, TimelineCommit, TimelineThreat } from '@exorcist-98/core';
import { findDefinitionsDir, parse, str, strs } from '../util.js';
import type { Io } from '../util.js';
import { SEVERITY_RANK, isIgnored, readIgnoreFile } from './scan.js';

export const ORIGIN_HELP = `Usage: exorcist origin [dir] [options]

Scan a repository, then walk its git history to find the commit that
introduced each threat: an infection timeline.

Options:
  --format <text|json>   Output format (default: text)
  --definitions <dir>    Folder of virus definitions (YAML)
  --ignore <path>        Skip a path prefix (repeatable)
  --fail-on <critical|high|medium|low|none>
                         Exit 1 if a finding is at least this bad (default: high)

The directory defaults to the current folder. Requires a git repository.
`;

const SHALLOW_NOTE =
  'Note: this is a shallow clone, so history before the clone point is missing. The commits shown may be the clone cut-off, not the true origin.';

function threatFrom(f: Finding, origin: OriginHit): TimelineThreat {
  const base: TimelineThreat = {
    ruleId: f.ruleId,
    severity: f.severity,
    file: f.file,
    line: f.line,
    title: f.title,
    span: f.span.slice(0, 120),
    origin: origin.status === 'found' ? origin.method : origin.status,
  };
  if (origin.status !== 'found') base.reason = origin.reason;
  return base;
}

function renderText(report: {
  target: string; commits: TimelineCommit[]; unknown: TimelineThreat[];
  filesScanned: number; findingsTotal: number; shallow: boolean;
}): string {
  const lines: string[] = [];
  lines.push(`Possession origin: ${report.findingsTotal} threat${report.findingsTotal === 1 ? '' : 's'} in ${report.filesScanned} scanned files under ${report.target}.`);
  if (report.shallow) lines.push(SHALLOW_NOTE);
  lines.push('');
  if (report.commits.length === 0 && report.unknown.length === 0) {
    lines.push('No threats found: nothing to trace.');
    return `${lines.join('\n')}\n`;
  }
  lines.push('Infection timeline:');
  lines.push('');
  for (const c of report.commits) {
    const who = c.bot ? `${c.author} (bot)` : c.author;
    lines.push(`${shortSha(c.sha)} by ${who} on ${c.date.slice(0, 10)} added ${c.threats.length} threat${c.threats.length === 1 ? '' : 's'}`);
    lines.push(`         "${c.subject}"`);
    for (const t of c.threats) {
      const headline = plainFor(t.ruleId, t.title ?? t.ruleId).headline;
      lines.push(`  ${t.severity.toUpperCase().padEnd(8)} ${t.file}:${t.line}  ${headline} (${t.ruleId})`);
      lines.push(`           found: ${t.span}`);
    }
  }
  if (report.unknown.length > 0) {
    lines.push('');
    lines.push('Origin unknown:');
    for (const t of report.unknown) {
      lines.push(`  ${t.severity.toUpperCase().padEnd(8)} ${t.file}:${t.line}  ${t.ruleId}${t.reason ? ` — ${t.reason}` : ''}`);
    }
  }
  return `${lines.join('\n')}\n`;
}

export async function originCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, {
    format: { type: 'string' }, definitions: { type: 'string' }, 'fail-on': { type: 'string' },
    ignore: { type: 'string', multiple: true }, help: { type: 'boolean', short: 'h' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${ORIGIN_HELP}`); return 2; }
  if (p.values['help']) { io.out(ORIGIN_HELP); return 0; }

  const format = str(p.values['format']) ?? 'text';
  if (format !== 'text' && format !== 'json') { io.err(`Unknown format "${format}". Use text or json.\n\n${ORIGIN_HELP}`); return 2; }
  const failOn = str(p.values['fail-on']) ?? 'high';
  if (failOn !== 'none' && !(failOn in SEVERITY_RANK)) { io.err(`Unknown --fail-on "${failOn}". Use critical, high, medium, low or none.`); return 2; }

  const target = resolve(p.positionals[0] ?? '.');
  if (p.positionals.length > 1) { io.err(`Give at most one directory.\n\n${ORIGIN_HELP}`); return 2; }
  if (!existsSync(target) || !statSync(target).isDirectory()) { io.err(`Not a directory: ${target}`); return 2; }

  const repoRoot = await gitRepoRoot(target);
  if (!repoRoot) { io.err(`Not a git repository: ${target}. "exorcist origin" needs git history to trace.`); return 2; }
  const shallow = await isShallowClone(repoRoot);
  // git reports the canonical spelling of the root (/private/... on macOS);
  // the target may use another (/var/...). Match them before diffing paths.
  const scanRoot = realpathSync(target);
  // Git paths are relative to the repository root; findings are relative to
  // the scanned folder.
  const prefix = relative(repoRoot, scanRoot);

  const defsDir = findDefinitionsDir(str(p.values['definitions']));
  if (!defsDir) { io.err('Could not find the virus definitions. Pass --definitions <dir> or set EXORCIST_DEFINITIONS.'); return 2; }
  try {
    if ((await loadDefinitions(defsDir)).length === 0) {
      io.err(`No virus definitions were found in ${defsDir}, so the scan would find nothing.`);
      return 2;
    }
  } catch (err) {
    io.err(`Could not load the virus definitions from ${defsDir}: ${String(err).split('\n')[0]}`);
    return 2;
  }

  const ignore = [...strs(p.values['ignore']), ...readIgnoreFile(scanRoot)];
  const findings: Finding[] = [];
  let stats: ScanStats = { filesScanned: 0, filesSkipped: 0, findingsTotal: 0, durationMs: 0 };
  let counted = 0;
  try {
    for await (const ev of scanRepo(scanRoot, { definitionsDir: defsDir })) {
      if (ev.type === 'finding') {
        if (!isIgnored(ev.finding.file, ignore)) findings.push(ev.finding);
      } else if (ev.type === 'file') {
        if (!isIgnored(ev.file.rel, ignore)) counted++;
      } else if (ev.type === 'done') {
        stats = ev.stats;
      }
    }
  } catch (err) {
    io.err(`The scan failed: ${String(err).split('\n')[0]}`);
    return 2;
  }

  const bySha = new Map<string, TimelineCommit>();
  const unknown: TimelineThreat[] = [];
  for (const f of findings) {
    const relForGit = prefix ? `${prefix}/${f.file}` : f.file;
    const hit = await findOriginCommit(repoRoot, relForGit, f.line, f.span);
    if (hit.status === 'found') {
      const threat = threatFrom(f, hit);
      const existing = bySha.get(hit.commit.sha);
      if (existing) existing.threats.push(threat);
      else bySha.set(hit.commit.sha, { ...hit.commit, method: hit.method, threats: [threat] });
    } else {
      unknown.push(threatFrom(f, hit));
    }
  }

  const commits = sortCommitsByDate([...bySha.values()]);
  const report = {
    tool: 'exorcist-origin' as const,
    target,
    repoRoot,
    shallowClone: shallow,
    commits,
    unknown,
    filesScanned: counted,
    findingsTotal: findings.length,
  };
  // Boundary check: the report we are about to print parses against its
  // own schema before it leaves the process.
  const checked = OriginReportSchema.safeParse(report);
  if (!checked.success) {
    io.err(`Internal error: the origin report did not validate. ${checked.error.issues[0]?.message ?? ''}`);
    return 2;
  }

  if (format === 'json') {
    io.out(`${JSON.stringify(checked.data, null, 2)}\n`);
  } else {
    io.out(renderText({ ...report, shallow }));
  }

  if (failOn === 'none') return 0;
  const limit = SEVERITY_RANK[failOn] ?? 0;
  return findings.some((f) => (SEVERITY_RANK[f.severity] ?? 9) <= limit) ? 1 : 0;
}
