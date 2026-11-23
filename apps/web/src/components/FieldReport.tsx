import report from '@/lib/field-report.json';

const REPORT_URL = 'https://github.com/pranavsaji/exorcist-98/blob/main/docs/FIELD_REPORT.md';
const fmt = (n: number) => n.toLocaleString('en-US');
const perRepo = (findings: number, repos: number) => (findings / repos).toFixed(findings / repos >= 1 ? 1 : 2);

/** What happened when Exorcist 98 was pointed at real public repositories. */
export function FieldReport() {
  const r1 = report.round1;
  const r2 = report;
  const repos = r1.repos + r2.repos;
  const files = r1.files + r2.files;
  const before = perRepo(r1.highCritical.findings, r1.repos);
  const after = perRepo(r2.highCritical.findings, r2.repos);

  return (
    <div className="flex flex-col gap-2 text-sm">
      <p className="m-0">
        We pointed the scanner at <strong>{fmt(repos)} public MCP servers and agent-config repositories</strong>{' '}
        ({fmt(files)} files) in two rounds, each a held-out set chosen by a published, seeded method, and read every
        serious alert by hand.
      </p>

      <div className="field-stats">
        <div className="field-stat">
          <span className="field-num">{before} → {after}</span>
          <span>serious false alarms per repository, after fixing every false-alarm pattern round 1 exposed</span>
        </div>
        <div className="field-stat">
          <span className="field-num">19 / 19</span>
          <span>labelled attacks still caught after the fixes, and 19 of 19 look-alike files left alone</span>
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
          : an 18.7 KB system prompt, invisible to anyone reading the code, installed as standing orders for an AI
          agent. Decoded, it tells the agent to treat its own refusals as unfinished drafts.
        </li>
        <li>
          <strong>A GitHub access token</strong> (EX-011) quoted in full in an archived review note. The repository is
          withheld until the maintainer has revoked it; we never used or tested the token.
        </li>
      </ol>

      <div className="bevel-in p-2">
        <p className="m-0 font-bold">Measured honestly</p>
        <p className="m-0 mt-1">
          Round 1 (old rules): {fmt(r1.highCritical.findings)} serious alerts, {r1.highCritical.perIssue['true-positive']} real
          issues out of {r1.highCritical.issues} ({r1.precision.value}%). That was not good enough, so every false-alarm
          pattern got a general fix, and the fixes were measured on {r2.repos} <em>new</em> repositories instead of the
          ones they were designed on.
        </p>
        <p className="m-0 mt-1">
          Round 2 (new rules): {r2.highCritical.findings} serious alerts in {fmt(r2.files)} files. None of the{' '}
          {r2.highCritical.issues} issues was a real attack ({r2.highCritical.perIssue.debatable} were debatable), because
          that set happened to contain no real threats. So round 2 shows how quiet the scanner now is, not how often an
          alert is right; that still needs a set with known incidents.
        </p>
      </div>

      <p className="m-0">
        <a className="font-semibold underline" href={REPORT_URL} target="_blank" rel="noopener noreferrer">
          Read the full field report: method, every false alarm, limitations (opens in a new tab)
        </a>
      </p>
    </div>
  );
}
