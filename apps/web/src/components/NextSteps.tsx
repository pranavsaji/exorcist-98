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

export function NextSteps() {
  const [copied, setCopied] = useState(false);
  return (
    <section aria-labelledby="next-steps" className="bevel-in flex flex-col gap-2 p-2 text-sm">
      <h3 id="next-steps" className="m-0 text-sm font-extrabold">Protect this repo on every pull request</h3>
      <p className="m-0">
        Add this file as <code className="font-mono">.github/workflows/exorcist.yml</code>. Each pull request is
        scanned and gets a comment listing new threats; the check fails on high or critical ones.
      </p>
      <pre className="log m-0 max-h-48 overflow-auto whitespace-pre text-xs" tabIndex={0} aria-label="GitHub Actions workflow">
        {ACTION_YAML}
      </pre>
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
