'use client';

export type WelcomeProps = {
  onScanHaunted: () => void;
  onOpenLab: () => void;
  onOpenField?: () => void;
  onDismiss: () => void;
};

/** First-run tour: the three things worth seeing, in about a minute. */
export function Welcome({ onScanHaunted, onOpenLab, onOpenField, onDismiss }: WelcomeProps) {
  const steps = [
    {
      n: 1,
      label: 'Scan the Haunted Repo',
      body: 'A repository full of defanged attacks on AI agents: hidden Unicode, poisoned MCP tools, booby-trapped hooks. Watch them get found in under a second.',
      onClick: onScanHaunted,
    },
    {
      n: 2,
      label: 'Watch the Shield stop a rug pull',
      body: 'An MCP tool you approved turns malicious. The same attack, replayed with and without the real Shield engine, side by side.',
      onClick: onOpenLab,
    },
    ...(onOpenField
      ? [{
          n: 3,
          label: 'See what we found in the wild',
          body: 'We scanned real public MCP servers and agent-config repos. Every serious finding was checked by hand.',
          onClick: onOpenField,
        }]
      : []),
  ];
  return (
    <div className="flex flex-col gap-2 text-sm">
      <p className="m-0 text-base font-bold">Your AI coding agent obeys what it reads.</p>
      <p className="m-0">
        READMEs, rules files, MCP tool descriptions, hooks: anyone can write them, and your agent treats them as orders.
        Exorcist 98 is the 90s antivirus, brought back to scan and shield all of it. Start here:
      </p>
      <ol className="m-0 flex list-none flex-col gap-2 p-0">
        {steps.map((s) => (
          <li key={s.n} className="bevel-in flex items-start gap-2 p-2">
            <span className="tour-num" aria-hidden="true">{s.n}</span>
            <div className="flex min-w-0 flex-1 flex-col gap-1">
              <button type="button" className="btn self-start" onClick={s.onClick}>{s.label}</button>
              <p className="m-0 text-[0.84rem]">{s.body}</p>
            </div>
          </li>
        ))}
      </ol>
      <p className="m-0 text-[0.84rem]">
        <strong>Protect a real repo in one step:</strong> scan it, then copy the GitHub Action shown under the results.
        It comments on every pull request that adds a threat.
      </p>
      <div className="flex justify-end">
        <button type="button" className="btn" onClick={onDismiss}>Close and don&apos;t show again</button>
      </div>
    </div>
  );
}
