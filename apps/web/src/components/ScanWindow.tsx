'use client';

import { useEffect, useId, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { ProgressBar } from './ProgressBar';
import { SeverityBadge } from './SeverityBadge';
import { parseGithubUrl } from '@/lib/github';
import { overallLevel } from '@/lib/severity';
import type { ScanState } from '@/lib/scan-state';

type Props = {
  state:         ScanState;
  onScanUrl:     (repoUrl: string, label: string) => void;
  onScanHaunted: () => void;
  onCancel:      () => void;
  onShowResults: () => void;
};

const STATUS_TEXT: Record<ScanState['status'], string> = {
  idle:      'Ready. Paste a public GitHub link or scan the Haunted Repo.',
  running:   'Scanning...',
  done:      'Scan complete.',
  failed:    'The scan stopped because of a problem.',
  cancelled: 'Scan cancelled.',
};

export function ScanWindow({ state, onScanUrl, onScanHaunted, onCancel, onShowResults }: Props) {
  const [url, setUrl] = useState('');
  const [urlError, setUrlError] = useState<string | null>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const inputId = useId();
  const errorId = useId();
  const running = state.status === 'running';

  // Keep the newest log line in view.
  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [state.log.length]);

  function submit(e: FormEvent) {
    e.preventDefault();
    const repo = parseGithubUrl(url);
    if (!repo) {
      setUrlError('Enter a public link like https://github.com/owner/repo');
      return;
    }
    setUrlError(null);
    onScanUrl(repo.cloneUrl.replace(/\.git$/, ''), `${repo.owner}/${repo.repo}`);
  }

  const level = overallLevel(state.findings.map((f) => f.finding));

  return (
    <div className="flex flex-col gap-3">
      <form onSubmit={submit} className="flex flex-col gap-2" noValidate>
        <label htmlFor={inputId} className="text-sm font-semibold">
          GitHub repository to scan
        </label>
        <div className="flex flex-wrap gap-2">
          <input
            id={inputId}
            className="field min-w-0 flex-1"
            type="url"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            placeholder="https://github.com/owner/repo"
            value={url}
            aria-invalid={urlError ? true : undefined}
            aria-describedby={urlError ? errorId : undefined}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button type="submit" className="btn" disabled={running}>
            Scan
          </button>
        </div>
        {urlError && (
          <p id={errorId} role="alert" className="m-0 text-sm font-semibold text-[#8a0020]">
            {urlError}
          </p>
        )}
        <div className="flex flex-wrap gap-2">
          <button type="button" className="btn" onClick={onScanHaunted} disabled={running}>
            Scan the Haunted Repo
          </button>
          <button type="button" className="btn" onClick={onCancel} disabled={!running}>
            Cancel
          </button>
          <button type="button" className="btn" onClick={onShowResults}>
            View results ({state.findings.length})
          </button>
        </div>
      </form>

      <div
        ref={logRef}
        className="log h-56"
        role="log"
        aria-label="Scan log"
        aria-live="polite"
        tabIndex={0}
      >
        {state.log.length === 0 && <div className="info">&gt; waiting for a scan...</div>}
        {state.log.map((line) => (
          <div key={line.id} className={line.kind}>
            &gt; {line.text}
          </div>
        ))}
      </div>

      <ProgressBar status={state.status} threatSeq={state.threatSeq} />

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm" aria-live="polite">
        <span className="font-semibold">{STATUS_TEXT[state.status]}</span>
        <span>Files: {state.filesSeen}</span>
        <span>Threats: {state.findings.length}</span>
        {state.status !== 'idle' && (
          <span className="inline-flex items-center gap-1">
            Infection level: <SeverityBadge severity={level} />
          </span>
        )}
        {state.stats && <span>Time: {Math.round(state.stats.durationMs)} ms</span>}
      </div>
      {state.notice && (
        <p role="status" className="m-0 text-sm font-semibold">
          {state.notice}
        </p>
      )}
    </div>
  );
}
