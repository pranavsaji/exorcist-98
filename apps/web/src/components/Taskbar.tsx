'use client';

import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';

export type TaskbarWindow = { id: string; title: string; icon: ReactNode; active: boolean; minimized: boolean };

export type StartItem = { label: string; icon: ReactNode; onSelect?: () => void; href?: string };

type Props = {
  windows:  TaskbarWindow[];
  items:    StartItem[];
  onToggle: (id: string) => void;
};

function useClock(): string {
  const [now, setNow] = useState('');
  useEffect(() => {
    const tick = () =>
      setNow(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    tick();
    const t = setInterval(tick, 15_000);
    return () => clearInterval(t);
  }, []);
  return now;
}

export function Taskbar({ windows, items, onToggle }: Props) {
  const [menuOpen, setMenuOpen] = useState(false);
  const clock = useClock();

  return (
    <nav
      aria-label="Taskbar"
      className="bevel-out fixed inset-x-0 bottom-0 z-[9999] flex h-11 items-center gap-2 px-2"
      onKeyDown={(e) => {
        if (e.key === 'Escape') setMenuOpen(false);
      }}
    >
      <div className="relative">
        <button
          type="button"
          className="btn font-extrabold"
          aria-haspopup="menu"
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen((o) => !o)}
        >
          <span aria-hidden="true">&#9776;</span> Start
        </button>
        {menuOpen && (
          <ul
            role="menu"
            aria-label="Start menu"
            className="bevel-out absolute bottom-full left-0 mb-1 min-w-[15rem] list-none p-1"
          >
            {items.map((item) => (
              <li key={item.label} role="none">
                {item.href ? (
                  <a
                    role="menuitem"
                    href={item.href}
                    className="flex items-center gap-2 px-2 py-2 text-sm font-semibold hover:bg-title hover:text-white"
                  >
                    {item.icon} {item.label}
                  </a>
                ) : (
                  <button
                    type="button"
                    role="menuitem"
                    className="flex w-full items-center gap-2 px-2 py-2 text-left text-sm font-semibold hover:bg-title hover:text-white"
                    onClick={() => {
                      setMenuOpen(false);
                      item.onSelect?.();
                    }}
                  >
                    {item.icon} {item.label}
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      <ul className="m-0 flex min-w-0 flex-1 list-none gap-1 p-0" aria-label="Open windows">
        {windows.map((w) => (
          <li key={w.id} className="min-w-0">
            <button
              type="button"
              className="btn max-w-[11rem] truncate"
              aria-pressed={w.active && !w.minimized}
              onClick={() => onToggle(w.id)}
            >
              {w.icon}
              <span className="truncate">{w.title}</span>
              {w.minimized && <span className="sr-only"> (minimized)</span>}
            </button>
          </li>
        ))}
      </ul>

      <div className="bevel-in px-3 py-1 font-mono text-sm" aria-label="Clock" suppressHydrationWarning>
        {clock}
      </div>
    </nav>
  );
}
