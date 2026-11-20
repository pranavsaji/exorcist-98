import type { ReactNode } from 'react';

type Props = { label: string; icon: ReactNode; onOpen?: () => void; href?: string };

const cls =
  'on-desk flex w-24 flex-col items-center gap-1 p-2 text-center text-xs font-semibold text-white hover:bg-white/10';

export function DesktopIcon({ label, icon, onOpen, href }: Props) {
  if (href) {
    return (
      // A new tab, so leaving the desktop never loses the current scan (W-012).
      <a href={href} className={cls} target="_blank" rel="noopener noreferrer">
        {icon}
        <span>{label}</span>
        <span className="sr-only"> (opens in a new tab)</span>
      </a>
    );
  }
  return (
    <button type="button" className={cls} onClick={onOpen}>
      {icon}
      <span>{label}</span>
    </button>
  );
}
