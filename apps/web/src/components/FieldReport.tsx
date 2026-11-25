import report from '@/lib/field-report.json';
import facts from '@/lib/facts.json';

const REPORT_URL = 'https://github.com/pranavsaji/exorcist-98/blob/main/docs/FIELD_REPORT.md';
const fmt = (n: number) => n.toLocaleString('en-US');
const perRepo = (findings: number, repos: number) => (findings / repos).toFixed(findings / repos >= 1 ? 1 : 2);

/** What happened when Exorcist 98 was pointed at real public repositories. */
export function FieldReport() {
  const r1 = report.round1;
  const r2 = report;
  const repos = facts.fieldReport.repos;
  const files = facts.fieldReport.files;
  const before = perRepo(r1.highCritical.findings, r1.repos);
  const after = perRepo(r2.highCritical.findings, r2.repos);

  return (
    <div className="flex flex-col gap-2 text-sm">
      <p className="m-0">
        We scanned <strong>{fmt(repos)} public MCP servers and agent-config repos</strong> ({fmt(files)} files) in{' '}
        {facts.fieldReport.rounds} rounds, and read every serious alert by hand. The numbers below come from the first two
        rounds, each on its own set of repositories.
      </p>

      <div className="field-stats">
        <div className="field-stat">
          <span className="field-num">{before} → {after}</span>
          <span>serious false alarms per repository, after fixing what round 1 exposed</span>
        </div>
        <div className="field-stat">
          <span className="field-num">{facts.benchmarkAttacksCaught} / {facts.benchmarkAttacks}</span>
          <span>labelled attacks still caught, and {facts.benchmarkBenignClean} of {facts.benchmarkBenign} look-alikes left alone</span>
        </div>
        <div className="field-stat">
          <span className="field-num">2</span>
          <span>real threats found in public repositories (round 1)</span>
        </div>
      </div>

      <h3 className="m-0 text-sm font-bold">What it found</h3>
      <ol className="m-0 flex flex-col gap-1.5 pl-5">
        <li>
          <strong>A jailbreak hidden in base64</strong> (EX-003) in{' '}
          <a className="underline" href="https://github.com/Jia-Ethan/grok-keysmith/blob/d87def09e22d94a8b0fbd8fb4608017bbbe04e1a/grok-keysmith.py#L54" target="_blank" rel="noopener noreferrer">
            Jia-Ethan/grok-keysmith (opens in a new tab)
          </a>
          : an 18.7 KB prompt, invisible in the code, installed as standing orders for an AI agent. It tells the agent
          to treat its own refusals as drafts.
        </li>
        <li>
          <strong>A GitHub access token</strong> (EX-011) quoted in full in an old review note. The repository is
          withheld until the maintainer has revoked it; we never used the token.
        </li>
      </ol>

      <div className="bevel-in p-2">
        <p className="m-0 font-bold">Measured honestly</p>
        <p className="m-0 mt-1">
          Round 1 (old rules): {fmt(r1.highCritical.findings)} serious alerts, {r1.highCritical.perIssue['true-positive']} real
          issues out of {r1.highCritical.issues} ({r1.precision.value}%). Not good enough, so each false-alarm pattern got
          a general fix, measured on {r2.repos} <em>new</em> repositories.
        </p>
        <p className="m-0 mt-1">
          Round 2 (new rules): {r2.highCritical.findings} serious alerts in {fmt(r2.files)} files. None of the{' '}
          {r2.highCritical.issues} issues was a real attack ({r2.highCritical.perIssue.debatable} debatable): that set had
          no real threats. So round 2 shows how quiet the scanner is, not how often an alert is right.
        </p>
      </div>

      <p className="m-0">
        <a className="font-semibold underline" href={REPORT_URL} target="_blank" rel="noopener noreferrer">
          Read the full field report (opens in a new tab)
        </a>
      </p>
    </div>
  );
}
