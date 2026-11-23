import { badgeStatus, toBadgeSvg, toMarkdown, toSarif } from '@exorcist-98/core/browser';
import type { Finding } from '@exorcist-98/core/browser';
import type { WebFinding, WebScanStats } from './protocol';

/** The web protocol's finding as the engine's type (heuristic fields filled in). */
export function toEngineFinding(f: WebFinding): Finding {
  const { rationale, confidence, ...rest } = f;
  if (f.source === 'heuristic') {
    return { ...rest, source: 'heuristic', rationale: rationale ?? '', confidence: confidence ?? 'medium' };
  }
  return { ...rest, source: 'signature' };
}

export type ReportKind = 'sarif' | 'markdown' | 'json' | 'badge';

export type ReportFile = { filename: string; mime: string; body: string };

function slug(target: string): string {
  return target.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'scan';
}

/** Build a downloadable report from the findings already on screen. Pure. */
export function buildReport(kind: ReportKind, findings: WebFinding[], stats: WebScanStats | null, target: string): ReportFile {
  const engine = findings.map(toEngineFinding);
  const s = stats ?? { filesScanned: 0, filesSkipped: 0, findingsTotal: findings.length, durationMs: 0 };
  const base = `exorcist-${slug(target)}`;
  switch (kind) {
    case 'sarif':
      return { filename: `${base}.sarif`, mime: 'application/sarif+json', body: `${JSON.stringify(toSarif(engine, ''), null, 2)}\n` };
    case 'markdown':
      return { filename: `${base}.md`, mime: 'text/markdown', body: toMarkdown(engine, s) };
    case 'json':
      return {
        filename: `${base}.json`,
        mime: 'application/json',
        body: `${JSON.stringify({ version: '1', target, createdAt: new Date().toISOString(), stats: s, findings }, null, 2)}\n`,
      };
    case 'badge':
      return { filename: 'exorcist-badge.svg', mime: 'image/svg+xml', body: toBadgeSvg(engine) };
  }
}

/** README snippet for a committed badge file. */
export function badgeMarkdown(findings: WebFinding[]): string {
  const b = badgeStatus(findings);
  return `![${b.label}: ${b.message}](./exorcist-badge.svg)`;
}

/** The exorcism patch as a download. Pure. */
export function patchFile(target: string, patch: string): ReportFile {
  return { filename: `exorcist-${slug(target)}.patch`, mime: 'text/x-diff', body: patch };
}
