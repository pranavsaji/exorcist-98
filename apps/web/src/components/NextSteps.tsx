'use client';
import { useState } from 'react';

/** What a visitor can do after a scan: keep the repo clean on every pull request. */
export const ACTION_YAML = `name: Exorcist 98
on: [pull_request]
permissions:
  contents: read
  pull-requests: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pranavsaji/exorcist-98@main
        with:
          fail-on: high`;

export function NextSteps({ step = 3 }: { step?: number }) {
  const [copied, setCopied] = useState(false);
  return (
    <section aria-labelledby="next-steps" className="next-item flex flex-col gap-1 text-sm">
      <h4 id="next-steps" className="next-title">
        <span className="next-num" aria-hidden="true">{step}</span> Guard every pull request
      </h4>
      <p className="m-0 text-xs">
        Save as <code className="font-mono">.github/workflows/exorcist.yml</code>. New threats get a comment; high or
        critical ones fail the check.
      </p>
      <details className="next-details">
        <summary>Show the workflow</summary>
        <pre className="log m-0 mt-1 max-h-40 overflow-auto whitespace-pre text-xs" tabIndex={0} aria-label="GitHub Actions workflow">
          {ACTION_YAML}
        </pre>
      </details>
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          className="btn"
          onClick={() => {
            void navigator.clipboard?.writeText(ACTION_YAML).then(() => setCopied(true), () => setCopied(false));
          }}
        >
          Copy workflow
        </button>
        <span role="status" aria-live="polite">{copied ? 'Copied.' : ''}</span>
      </div>
    </section>
  );
}
