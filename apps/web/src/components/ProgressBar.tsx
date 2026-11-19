import type { ScanStatus } from '@/lib/scan-state';

type Props = {
  status: ScanStatus;
  /** Changes whenever a threat is found; retriggers the "possessed" glitch. */
  threatSeq: number;
};

/**
 * The total number of files is not known while a scan streams, so the bar is
 * indeterminate while running and full when done. It glitches on each threat
 * (disabled for users who prefer reduced motion; the label still changes).
 */
export function ProgressBar({ status, threatSeq }: Props) {
  const state =
    status === 'running' ? 'running'
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
      {...(status === 'done' ? { 'aria-valuenow': 100 } : {})}
      data-possessed={status === 'running' && threatSeq > 0 ? 'true' : 'false'}
    >
      <div className="progress-fill" data-state={state} />
    </div>
  );
}
