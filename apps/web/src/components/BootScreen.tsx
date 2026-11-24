'use client';

import { useEffect, useState } from 'react';
import { BOOT_KEY, BOOT_MS } from '@/lib/boot';

/**
 * A short power-on moment: about a second, skipped by any key or click.
 * Decorative only (hidden from screen readers, nothing focusable): the
 * desktop underneath is already there and usable.
 */
export function BootScreen() {
  const [on, setOn] = useState(true);

  useEffect(() => {
    const root = document.documentElement;
    if (root.getAttribute('data-boot') !== 'on') {
      setOn(false);
      return;
    }
    try { window.sessionStorage.setItem(BOOT_KEY, '1'); } catch { /* storage blocked: it shows once per load */ }
    const end = () => {
      root.removeAttribute('data-boot');
      setOn(false);
    };
    const t = setTimeout(end, BOOT_MS);
    window.addEventListener('keydown', end);
    window.addEventListener('pointerdown', end);
    return () => {
      clearTimeout(t);
      window.removeEventListener('keydown', end);
      window.removeEventListener('pointerdown', end);
    };
  }, []);

  if (!on) return null;
  return (
    <div className="boot" aria-hidden="true" data-testid="boot-screen">
      <div className="boot-inner">
        <svg className="boot-ghost" width="72" height="72" viewBox="0 0 16 16" shapeRendering="crispEdges" focusable="false">
          <path d="M3 14V7a5 5 0 0 1 10 0v7l-1.7-1.8L9.6 14 8 12.2 6.4 14l-1.7-1.8z" fill="#f4f0fa" stroke="#120b22" strokeWidth="0.8" />
          <rect x="5.5" y="6" width="1.6" height="2.4" fill="#120b22" />
          <rect x="9" y="6" width="1.6" height="2.4" fill="#120b22" />
          <rect x="7" y="9.5" width="2" height="1.2" fill="#8a3fb0" />
        </svg>
        <p className="boot-title">EXORCIST 98</p>
        <p className="boot-tag">Antivirus for AI agents</p>
        <div className="boot-lines">
          <p>&gt; Loading virus definitions ...... OK</p>
          <p>&gt; Waking the Real-Time Shield ..... OK</p>
          <p>&gt; Checking for possessions ........ READY</p>
        </div>
        <div className="boot-bar"><div className="boot-fill" /></div>
        <p className="boot-skip">Press any key to skip</p>
      </div>
    </div>
  );
}
