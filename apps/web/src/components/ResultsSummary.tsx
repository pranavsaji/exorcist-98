import { ShapeIcon } from './Icons';
import { SeverityBadge } from './SeverityBadge';
import { plainFor } from '@/lib/plain';
import { SEVERITY_INFO, SEVERITY_ORDER, overallLevel, sortFindings } from '@/lib/severity';
import type { FindingEntry } from '@/lib/scan-state';
import type { Severity } from '@/lib/protocol';

type Level = Severity | 'clean';

/** The gauge, mildest to worst. */
const GAUGE: Level[] = ['clean', 'low', 'medium', 'high', 'critical'];

export function verdictFor(level: Level): { word: string; line: string } {
  if (level === 'clean') return { word: 'CLEAN', line: 'Nothing here tries to give your AI agent orders.' };
  if (level === 'critical' || level === 'high') return { word: 'POSSESSED', line: 'Your AI agent would read these as orders. Fix them first.' };
  return { word: 'HAUNTED', line: 'Nothing urgent, but worth a look before your agent reads it.' };
}

/** Worst first, one per kind of threat, so the top three say three different things. */
export function topThreats(findings: FindingEntry[], n = 3): FindingEntry[] {
  const sorted = sortFindings(findings.map((e) => ({ ...e, severity: e.finding.severity, file: e.finding.file, line: e.finding.line })));
  const seen = new Set<string>();
  const out: FindingEntry[] = [];
  for (const e of sorted) {
    if (seen.has(e.finding.ruleId)) continue;
    seen.add(e.finding.ruleId);
    out.push(e);
    if (out.length === n) break;
  }
  return out;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** A segmented meter, clean to critical. Decorative: the verdict and badge say the same in text. */
function Gauge({ level }: { level: Level }) {
  const at = GAUGE.indexOf(level);
  return (
    <div className="gauge" aria-hidden="true" data-level={level}>
      {GAUGE.map((g, i) => (
        <div key={g} className="gauge-seg" data-on={i <= at ? 'true' : 'false'} data-current={i === at ? 'true' : 'false'} data-sev={g}>
          <span className="gauge-mark">{i === at ? '▼' : ''}</span>
          <span className="gauge-box">
            {g === 'clean'
              ? <svg width="12" height="12" viewBox="0 0 16 16" data-shape="check"><path d="M3 8.5l3.2 3.2L13 5" fill="none" stroke="currentColor" strokeWidth="2.4" /></svg>
              : <ShapeIcon shape={SEVERITY_INFO[g].shape} />}
          </span>
          <span className="gauge-label">{g === 'clean' ? 'CLEAN' : SEVERITY_INFO[g].label}</span>
        </div>
      ))}
    </div>
  );
}

type Props = {
  findings:     FindingEntry[];
  filesScanned: number;
  onSelect:     (id: number) => void;
};

/** The top of the results: a verdict, counts by level and the three worst threats. */
export function ResultsSummary({ findings, filesScanned, onSelect }: Props) {
  const level = overallLevel(findings.map((f) => f.finding));
  const verdict = verdictFor(level);
  const files = new Set(findings.map((f) => f.finding.file)).size;
  const counts = SEVERITY_ORDER.map((s) => ({ s, n: findings.filter((e) => e.finding.severity === s).length }));
  const top = topThreats(findings);

  return (
    <section className="summary" aria-labelledby="summary-title" data-testid="results-summary" data-level={level}>
      <div className="summary-head">
        <h3 id="summary-title" className="summary-verdict">
          <span className="summary-kicker">Verdict:</span> <span className="summary-word">{verdict.word}</span>
        </h3>
        <p className="m-0 flex flex-wrap items-center gap-1.5 text-sm">
          Infection level: <SeverityBadge severity={level} />
        </p>
      </div>
      <Gauge level={level} />
      <p className="m-0 text-sm">
        {findings.length === 0
          ? `No threats in ${plural(filesScanned, 'file')}. `
          : `${plural(findings.length, 'threat')} in ${plural(files, 'file')} (of ${filesScanned} scanned). `}
        {verdict.line}
      </p>
      {findings.length > 0 && (
        <>
          <ul className="summary-counts" aria-label="Threats by infection level">
            {counts.map(({ s, n }) => (
              <li key={s} data-zero={n === 0 ? 'true' : 'false'}>
                <SeverityBadge severity={s} /> <span className="summary-n">{n}</span>
              </li>
            ))}
          </ul>
          <h4 id="top-threats" className="m-0 text-sm font-extrabold">Top threats</h4>
          <ol className="summary-top" aria-labelledby="top-threats">
            {top.map((e) => (
              <li key={e.id}>
                <button type="button" className="summary-threat" onClick={() => onSelect(e.id)}>
                  <SeverityBadge severity={e.finding.severity} />
                  <span className="summary-threat-text">{plainFor(e.finding.ruleId, e.finding.title).headline}</span>
                  <span className="summary-threat-where">{e.finding.file}:{e.finding.line}</span>
                </button>
              </li>
            ))}
          </ol>
        </>
      )}
    </section>
  );
}
