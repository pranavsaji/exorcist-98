'use client';

import { useEffect, useRef } from 'react';
import type { KeyboardEvent, PointerEvent, ReactNode } from 'react';

export type WindowProps = {
  id:         string;
  title:      string;
  icon?:      ReactNode;
  x:          number;
  y:          number;
  width:      number;
  z:          number;
  active:     boolean;
  minimized:  boolean;
  onFocus:    (id: string) => void;
  onClose:    (id: string) => void;
  onMinimize: (id: string) => void;
  onMove:     (id: string, x: number, y: number) => void;
  children:   ReactNode;
};

export function Window(props: WindowProps) {
  const { id, title, icon, x, y, width, z, active, minimized, onFocus, onClose, onMinimize, onMove, children } = props;
  const ref = useRef<HTMLElement>(null);
  const drag = useRef<{ dx: number; dy: number } | null>(null);
  const titleId = `win-${id}-title`;

  // Move keyboard focus into a window when it becomes active.
  useEffect(() => {
    if (active && !minimized) ref.current?.focus({ preventScroll: true });
  }, [active, minimized]);

  function onPointerDown(e: PointerEvent<HTMLDivElement>) {
    if ((e.target as HTMLElement).closest('button')) return;
    onFocus(id);
    drag.current = { dx: e.clientX - x, dy: e.clientY - y };
    e.currentTarget.setPointerCapture(e.pointerId);
  }
  function onPointerMove(e: PointerEvent<HTMLDivElement>) {
    if (!drag.current) return;
    onMove(id, Math.max(0, e.clientX - drag.current.dx), Math.max(0, e.clientY - drag.current.dy));
  }
  function onPointerUp() {
    drag.current = null;
  }
  function onKeyDown(e: KeyboardEvent<HTMLElement>) {
    if (e.key === 'Escape') {
      e.stopPropagation();
      onClose(id);
      return;
    }
    // Alt + arrow keys move the window (Shift moves further), so dragging is not mouse-only.
    if (e.altKey && e.key.startsWith('Arrow')) {
      e.preventDefault();
      const step = e.shiftKey ? 60 : 20;
      const dx = e.key === 'ArrowLeft' ? -step : e.key === 'ArrowRight' ? step : 0;
      const dy = e.key === 'ArrowUp' ? -step : e.key === 'ArrowDown' ? step : 0;
      onMove(id, Math.max(0, x + dx), Math.max(0, y + dy));
    }
  }

  return (
    <section
      ref={ref}
      role="dialog"
      aria-labelledby={titleId}
      aria-describedby={`${titleId}-keys`}
      tabIndex={-1}
      hidden={minimized}
      className="win"
      style={{ left: x, top: y, width, zIndex: z }}
      onMouseDown={() => onFocus(id)}
      onKeyDown={onKeyDown}
    >
      <div
        className="titlebar"
        data-active={active ? 'true' : 'false'}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
      >
        {icon}
        <h2 id={titleId} className="m-0 flex-1 truncate text-sm font-bold">
          {title}
        </h2>
        <button type="button" className="btn" aria-label={`Minimize ${title}`} onClick={() => onMinimize(id)}>
          <span aria-hidden="true">_</span>
        </button>
        <button type="button" className="btn" aria-label={`Close ${title}`} onClick={() => onClose(id)}>
          <span aria-hidden="true">x</span>
        </button>
      </div>
      <p id={`${titleId}-keys`} className="sr-only">Press Escape to close. Alt and the arrow keys move this window.</p>
      <div className="min-h-0 flex-1 overflow-auto p-2">{children}</div>
    </section>
  );
}
