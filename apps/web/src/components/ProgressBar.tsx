import type { ScanStatus } from '@/lib/scan-state';

type Props = {
  status: ScanStatus;
  /** Files scanned so far and in total; with a total the bar shows real progress (W-010). */
  filesSeen?: number;
  totalFiles?: number | null;
  /** Changes whenever a threat is found; retriggers the "possessed" glitch. */
  threatSeq: number;
};

/**
 * While running, the bar fills by files scanned out of the total the server
 * counted; until that total arrives it is indeterminate. It glitches on each
 * threat (disabled for users who prefer reduced motion; the label still changes).
 */
export function ProgressBar({ status, threatSeq, filesSeen = 0, totalFiles = null }: Props) {
  const determinate = status === 'running' && totalFiles !== null && totalFiles > 0;
  const pct = determinate ? Math.min(100, Math.round((filesSeen / (totalFiles as number)) * 100)) : 0;
  const state =
    determinate ? 'progress'
    : status === 'running' ? 'running'
    : status === 'done' ? 'done'
    : status === 'idle' ? 'idle'
    : 'stopped';
  const label =
    status === 'running' ? 'Scanning'
    : status === 'done' ? 'Scan complete'
    : status === 'failed' ? 'Scan failed'
    : status === 'cancelled' ? 'Scan cancelled'
    : 'Ready';

  return (
    <div
      key={threatSeq}
      className="progress"
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      {...(status === 'done' ? { 'aria-valuenow': 100 } : determinate ? { 'aria-valuenow': pct, 'aria-valuetext': `${filesSeen} of ${totalFiles} files` } : {})}
      data-possessed={status === 'running' && threatSeq > 0 ? 'true' : 'false'}
    >
      <div className="progress-fill" data-state={state} style={determinate ? { width: `${pct}%` } : undefined} />
    </div>
  );
}
