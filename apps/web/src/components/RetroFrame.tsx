import type { ReactNode } from 'react';
import { BookIcon } from './Icons';
import { SiteFooter } from './SiteFooter';

/** A static window for server-rendered pages (the Threat Encyclopedia). */
export function RetroFrame({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="mx-auto flex min-h-screen max-w-3xl flex-col gap-3 p-3">
      <nav aria-label="Site" className="on-desk flex flex-wrap gap-3 text-sm font-semibold text-white">
        <a className="underline" href="/">Back to the desktop</a>
        <a className="underline" href="/encyclopedia">All virus definitions</a>
      </nav>
      <main className="win relative !max-h-none !max-w-full">
        <div className="titlebar" data-active="true">
          <BookIcon size={18} />
          <h1 className="m-0 flex-1 truncate text-sm font-bold">{title}</h1>
        </div>
        <div className="p-3 text-sm">{children}</div>
      </main>
      <SiteFooter />
    </div>
  );
}
