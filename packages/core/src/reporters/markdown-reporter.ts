import { plainFor } from '../plain.js';
import type { Finding, ScanStats, Severity } from '../types.js';

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

function cell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

/** Markdown summary for pull-request comments and job summaries. */
export function toMarkdown(findings: Finding[], stats: ScanStats, limit = 50): string {
  const counts = ORDER.map((s) => ({ s, n: findings.filter((f) => f.severity === s).length }));
  const lines: string[] = ['## Exorcist 98 scan', ''];

  if (findings.length === 0) {
    lines.push(`No threats found in ${stats.filesScanned} files.`);
    return lines.join('\n') + '\n';
  }

  lines.push(
    `**${findings.length} threat${findings.length === 1 ? '' : 's'}** in ${stats.filesScanned} files: ` +
      counts.filter((c) => c.n > 0).map((c) => `${c.n} ${c.s}`).join(', ') + '.',
    '',
    '| Level | What | Where | Rule |',
    '| --- | --- | --- | --- |',
  );

  const sorted = [...findings].sort(
    (a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line,
  );
  for (const f of sorted.slice(0, limit)) {
    lines.push(
      `| ${f.severity.toUpperCase()} | ${cell(plainFor(f.ruleId, f.title).headline)} | \`${cell(f.file)}:${f.line}\` | ${f.ruleId} |`,
    );
  }
  if (sorted.length > limit) lines.push('', `Showing the first ${limit} of ${sorted.length}. See the SARIF report for the rest.`);
  lines.push('', '<sub>Scanned with Exorcist 98. Fixes are in the Threat Encyclopedia.</sub>');
  return lines.join('\n') + '\n';
}
