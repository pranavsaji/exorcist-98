import type { ReactNode } from 'react';
import type { Shape } from '@/lib/severity';

// Original pixel-style icons. Decorative: always aria-hidden.
type IconProps = { size?: number };

function Svg({ size = 32, children }: IconProps & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      aria-hidden="true"
      focusable="false"
      shapeRendering="crispEdges"
    >
      {children}
    </svg>
  );
}

export function GhostIcon(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M3 14V7a5 5 0 0 1 10 0v7l-1.7-1.8L9.6 14 8 12.2 6.4 14l-1.7-1.8z" fill="#f4f0fa" stroke="#120b22" strokeWidth="1" />
      <rect x="5.5" y="6" width="1.6" height="2.4" fill="#120b22" />
      <rect x="9" y="6" width="1.6" height="2.4" fill="#120b22" />
      <rect x="7" y="9.5" width="2" height="1.2" fill="#8a3fb0" />
    </Svg>
  );
}

export function ShieldIcon(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M8 1.2 14 3v5c0 3-3 5-6 6.8C5 13 2 11 2 8V3z" fill="#39ff88" stroke="#120b22" strokeWidth="1" />
      <path d="M5 8l2 2 4-4" fill="none" stroke="#120b22" strokeWidth="1.6" />
    </Svg>
  );
}

export function BookIcon(p: IconProps) {
  return (
    <Svg {...p}>
      <rect x="2.5" y="2" width="11" height="12" fill="#f4f0fa" stroke="#120b22" strokeWidth="1" />
      <rect x="2.5" y="2" width="3" height="12" fill="#8a3fb0" stroke="#120b22" strokeWidth="1" />
      <rect x="7" y="5" width="5" height="1" fill="#120b22" />
      <rect x="7" y="8" width="5" height="1" fill="#120b22" />
    </Svg>
  );
}

export function InfoIcon(p: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="8" cy="8" r="6.5" fill="#6bd0ff" stroke="#120b22" strokeWidth="1" />
      <rect x="7.2" y="7" width="1.6" height="4.6" fill="#120b22" />
      <rect x="7.2" y="4" width="1.6" height="1.6" fill="#120b22" />
    </Svg>
  );
}

export function SkullIcon(p: IconProps) {
  return (
    <Svg {...p}>
      <path d="M3 7a5 5 0 0 1 10 0v3H3z" fill="#f4f0fa" stroke="#120b22" strokeWidth="1" />
      <rect x="4.5" y="10" width="7" height="3.5" fill="#f4f0fa" stroke="#120b22" strokeWidth="1" />
      <rect x="5" y="6" width="2" height="2.4" fill="#120b22" />
      <rect x="9" y="6" width="2" height="2.4" fill="#120b22" />
    </Svg>
  );
}

/** Severity shapes, so colour is never the only signal. */
export function ShapeIcon({ shape, size = 12 }: { shape: Shape; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      aria-hidden="true"
      focusable="false"
      data-shape={shape}
    >
      {shape === 'diamond' && <polygon points="8,1 15,8 8,15 1,8" fill="currentColor" />}
      {shape === 'triangle' && <polygon points="8,2 15,14 1,14" fill="currentColor" />}
      {shape === 'square' && <rect x="2.5" y="2.5" width="11" height="11" fill="currentColor" />}
      {shape === 'circle' && <circle cx="8" cy="8" r="6" fill="currentColor" />}
    </svg>
  );
}
