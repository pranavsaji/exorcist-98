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
  /** Upload a ZIP of a project (L-032). */
  onScanZip?:    (file: File) => void;
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

export function ScanWindow({ state, onScanUrl, onScanZip, onScanHaunted, onCancel, onShowResults }: Props) {
  const [url, setUrl] = useState('');
  const [urlError, setUrlError] = useState<string | null>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const inputId = useId();
  const errorId = useId();
  const zipId = useId();
  const zipHelpId = useId();
  const fileRef = useRef<HTMLInputElement>(null);
  const running = state.status === 'running';

  // A scan can start from the desktop icon or Start menu too, so clear any
  // old URL error whenever a scan begins.
  useEffect(() => {
    if (state.status === 'running') setUrlError(null);
  }, [state.status]);

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
    // Send the link as typed (it may name a branch, tag or commit); the server parses it again.
    onScanUrl(url.trim(), `${repo.owner}/${repo.repo}${repo.ref ? `@${repo.ref}` : ''}`);
  }

  const level = overallLevel(state.findings.map((f) => f.finding));

  return (
    <div className="flex flex-col gap-3">
      <p className="m-0 text-sm">
        <strong>Your AI coding agent obeys what it reads.</strong> Exorcist 98 scans a repository for hidden
        instructions, poisoned MCP tools and risky agent settings before Kiro, Cursor, Claude Code or Copilot read
        them. Try the Haunted Repo to see a possessed project, or paste any public GitHub link.
      </p>
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
            onChange={(e) => {
              setUrl(e.target.value);
              setUrlError(null);
            }}
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
          <button
            type="button"
            className="btn"
            onClick={() => {
              setUrlError(null);
              onScanHaunted();
            }}
            disabled={running}
          >
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
      {onScanZip && (
        <div className="flex flex-col gap-1">
          <label htmlFor={zipId} className="text-sm font-semibold">
            Or scan a private project: upload a .zip
          </label>
          <input
            ref={fileRef}
            id={zipId}
            type="file"
            accept=".zip,application/zip"
            className="text-sm"
            aria-describedby={zipHelpId}
            disabled={running}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (!f) return;
              if (!/\.zip$/i.test(f.name)) setUrlError('Choose a .zip file.');
              else if (f.size > 4 * 1024 * 1024) setUrlError('The ZIP file is larger than 4 MB. Leave out node_modules, build output and assets.');
              else { setUrlError(null); onScanZip(f); }
              if (fileRef.current) fileRef.current.value = '';
            }}
          />
          <p id={zipHelpId} className="m-0 text-xs">
            Up to 4 MB. The files are unpacked on the server only for this scan and deleted straight after; nothing is kept.
          </p>
        </div>
      )}

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

      <ProgressBar status={state.status} threatSeq={state.threatSeq} filesSeen={state.filesSeen} totalFiles={state.totalFiles} />

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm" aria-live="polite">
        <span className="font-semibold">{STATUS_TEXT[state.status]}</span>
        <span>Files: {state.filesSeen}{state.status === 'running' && state.totalFiles !== null ? ` of ${state.totalFiles}` : ''}</span>
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
