'use client';

import { useLayoutEffect, useState } from 'react';

export type GuideTip = { target: string; title: string; body: string };

/** Three short tips, each pointing at one thing on the first screen. */
export const GUIDE_TIPS: GuideTip[] = [
  { target: 'haunted', title: 'Start here', body: 'Scan the Haunted Repo: a safe demo full of defanged attacks on AI agents.' },
  { target: 'own', title: 'Got your own repo?', body: 'Paste a public GitHub link or upload a .zip. Nothing is kept.' },
  { target: 'lab', title: 'Then watch it fight back', body: 'The Possession Lab replays a live attack, with and without the Shield.' },
];

type Place = { mode: 'side'; left: number; top: number; tail: number } | { mode: 'below'; left: number; top: number } | { mode: 'dock' };

const WIDTH = 270;

/** Our own lantern-carrying ghost, drawn on a 16 px grid (decorative). */
export function LanternGhost({ size = 56 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" shapeRendering="crispEdges" aria-hidden="true" focusable="false" className="guide-art">
      <path d="M2 14V6.5a4.5 4.5 0 0 1 9 0V14l-1.5-1.5L8 14l-1.5-1.5L5 14l-1.5-1.5z" fill="#f4f0fa" stroke="#120b22" strokeWidth="0.7" />
      <rect x="4.3" y="5.6" width="1.3" height="2" fill="#120b22" />
      <rect x="7.3" y="5.6" width="1.3" height="2" fill="#120b22" />
      <rect x="5.6" y="8.6" width="1.6" height="0.9" fill="#8a3fb0" />
      {/* the lantern, held out to the right */}
      <rect x="11" y="8.2" width="2.6" height="0.6" fill="#120b22" />
      <rect x="12.9" y="8.8" width="0.5" height="0.8" fill="#120b22" />
      <rect x="12.2" y="9.6" width="2" height="2.6" fill="#ffd93c" stroke="#120b22" strokeWidth="0.5" />
      <rect x="12.9" y="10.3" width="0.6" height="1.2" fill="#ff9a3c" />
    </svg>
  );
}

/**
 * A small speech bubble from the desktop's resident ghost. It points at the
 * element marked data-guide="<target>" and never takes focus; it is dismissed
 * with "Close guide" and can be reopened from the Start menu.
 */
export function GuideGhost({ step, onNext, onClose, layoutKey }: { step: number; onNext: () => void; onClose: () => void; layoutKey: string }) {
  const tip = GUIDE_TIPS[step] ?? GUIDE_TIPS[0]!;
  const last = step >= GUIDE_TIPS.length - 1;
  const [place, setPlace] = useState<Place | null>(null);

  useLayoutEffect(() => {
    function measure() {
      const el = document.querySelector<HTMLElement>(`[data-guide="${tip.target}"]`);
      if (!el || el.getClientRects().length === 0) { setPlace(null); return; }
      const vw = window.innerWidth;
      if (vw < 900) { setPlace({ mode: 'dock' }); return; }
      const r = el.getBoundingClientRect();
      const win = (el.closest('.win') as HTMLElement | null)?.getBoundingClientRect() ?? r;
      const cy = r.top + r.height / 2;
      if (win.right + 18 + WIDTH <= vw - 8) {
        const top = Math.max(8, Math.round(cy - 46));
        setPlace({ mode: 'side', left: Math.round(win.right + 18), top, tail: Math.round(cy - top) });
      } else {
        setPlace({ mode: 'below', left: Math.round(Math.min(Math.max(8, r.left), vw - WIDTH - 8)), top: Math.round(r.bottom + 12) });
      }
    }
    measure();
    // The window may still be settling (fonts, layout); measure again shortly after.
    const t = setTimeout(measure, 120);
    window.addEventListener('resize', measure);
    return () => { clearTimeout(t); window.removeEventListener('resize', measure); };
  }, [tip.target, layoutKey]);

  if (!place) return null;
  const style =
    place.mode === 'dock' ? undefined
    : { left: place.left, top: place.top, width: WIDTH, ...(place.mode === 'side' ? { ['--tail' as string]: `${place.tail}px` } : {}) };

  return (
    <div className="guide" data-mode={place.mode} style={style} data-testid="guide">
      <LanternGhost />
      <div className="guide-bubble">
        <p className="guide-count">Tip {step + 1} of {GUIDE_TIPS.length}</p>
        <p className="guide-title">{tip.title}</p>
        <p className="guide-body">{tip.body}</p>
        <div className="guide-actions">
          <button type="button" className="btn" onClick={last ? onClose : onNext}>{last ? 'Done' : 'Next tip'}</button>
          {!last && <button type="button" className="btn" onClick={onClose}>Close guide</button>}
        </div>
      </div>
    </div>
  );
}
