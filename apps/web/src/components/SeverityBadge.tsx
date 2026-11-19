import { ShapeIcon } from './Icons';
import { SEVERITY_INFO } from '@/lib/severity';
import type { Severity } from '@/lib/protocol';

/** Infection level: always a text label plus a shape, with colour as a third cue. */
export function SeverityBadge({ severity }: { severity: Severity | 'clean' }) {
  if (severity === 'clean') {
    return (
      <span className="sev sev-clean" data-severity="clean">
        <svg width="12" height="12" viewBox="0 0 16 16" aria-hidden="true" focusable="false" data-shape="check">
          <path d="M3 8.5l3.2 3.2L13 5" fill="none" stroke="currentColor" strokeWidth="2.4" />
        </svg>
        CLEAN
      </span>
    );
  }
  const info = SEVERITY_INFO[severity];
  return (
    <span className={`sev sev-${severity}`} data-severity={severity}>
      <ShapeIcon shape={info.shape} />
      {info.label}
    </span>
  );
}
