import type { ReactNode } from 'react';

type Props = { label: string; icon: ReactNode; onOpen?: () => void; href?: string };

const cls =
  'on-desk flex w-24 flex-col items-center gap-1 p-2 text-center text-xs font-semibold text-white hover:bg-white/10';

export function DesktopIcon({ label, icon, onOpen, href }: Props) {
  if (href) {
    return (
      <a href={href} className={cls}>
        {icon}
        <span>{label}</span>
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
