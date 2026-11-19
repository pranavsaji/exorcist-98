'use client';

import { useState } from 'react';
import { badgeMarkdown, buildReport } from '@/lib/report';
import type { ReportKind } from '@/lib/report';
import type { WebFinding, WebScanStats } from '@/lib/protocol';

type Props = { findings: WebFinding[]; stats: WebScanStats | null; target: string };

const KINDS: Array<{ kind: ReportKind; label: string }> = [
  { kind: 'sarif', label: 'SARIF (code scanning)' },
  { kind: 'markdown', label: 'Markdown (pull request)' },
  { kind: 'json', label: 'JSON' },
  { kind: 'badge', label: 'README badge (SVG)' },
];

function download(filename: string, mime: string, body: string): void {
  const url = URL.createObjectURL(new Blob([body], { type: mime }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Save the current scan as a report. Everything is built in the page; nothing is uploaded. */
export function ReportButtons({ findings, stats, target }: Props) {
  const [copied, setCopied] = useState(false);
  const snippet = badgeMarkdown(findings);

  return (
    <section aria-labelledby="save-report" className="flex flex-col gap-1 border-t border-shade/60 pt-2">
      <h3 id="save-report" className="m-0 text-sm font-bold">Save this report</h3>
      <div className="flex flex-wrap gap-1">
        {KINDS.map(({ kind, label }) => (
          <button
            key={kind}
            type="button"
            className="btn"
            onClick={() => {
              const r = buildReport(kind, findings, stats, target);
              download(r.filename, r.mime, r.body);
            }}
          >
            {label}
          </button>
        ))}
      </div>
      <p className="m-0 text-xs">
        Commit the badge file to your repository and add this line to your README:
      </p>
      <div className="flex flex-wrap items-center gap-1">
        <code className="field min-w-0 flex-1 truncate text-xs" aria-label="Badge Markdown">{snippet}</code>
        <button
          type="button"
          className="btn"
          onClick={() => {
            void navigator.clipboard?.writeText(snippet).then(() => setCopied(true), () => setCopied(false));
          }}
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
    </section>
  );
}
