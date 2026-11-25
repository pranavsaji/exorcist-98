import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { BookIcon, GhostIcon, ShieldIcon, SkullIcon } from '@/components/Icons';
import {
  CHECK_COMMANDS, HOW_KIRO_INTRO, HOW_KIRO_TITLE, SURFACES, SURPRISES, USER_SETUP,
} from '@/lib/how-kiro';

// Static content (apps/web/src/lib/how-kiro.ts, the same source as docs/HOW_KIRO.md):
// nothing is read from disk at run time.
export const metadata: Metadata = {
  title: 'How we used Kiro | Exorcist 98',
  description:
    'Each Kiro feature we used on Exorcist 98 (specs, steering, hooks, MCP, Powers, custom agents, Kiro CLI, Kiro Crew), the files, the evidence, and where Kiro surprised us.',
};

const REPO = 'https://github.com/pranavsaji/exorcist-98';
const CREW_REPO = 'https://github.com/pranavsaji/exorcist-98-crew';

/** Text with `backtick` spans shown as code. Content is our own, rendered as text only. */
function Rich({ text }: { text: string }) {
  const parts = text.split('`');
  return (
    <>
      {parts.map((p, i) => (i % 2 === 1
        ? <code key={i} className="break-words bg-hilite px-1 font-mono text-[0.85em] text-ink">{p}</code>
        : <span key={i}>{p}</span>))}
    </>
  );
}

function Panel({ id, title, icon, children }: { id: string; title: string; icon?: ReactNode; children: ReactNode }) {
  return (
    <section id={id} className="win relative !max-h-none !max-w-full scroll-mt-4" aria-labelledby={`h-${id}`}>
      <div className="titlebar" data-active="true">
        {icon}
        <h2 id={`h-${id}`} className="m-0 flex-1 truncate text-sm font-bold">{title}</h2>
      </div>
      <div className="p-3 text-sm">{children}</div>
    </section>
  );
}

function PathItem({ path }: { path: string }) {
  const crew = path.startsWith('exorcist-98-crew/');
  const rel = crew ? path.slice('exorcist-98-crew/'.length) : path;
  const href = `${crew ? CREW_REPO : REPO}/${rel.endsWith('/') ? 'tree' : 'blob'}/main/${rel}`;
  return (
    <li>
      <a className="underline underline-offset-4" href={href}>
        <code className="break-all font-mono text-xs">{path}</code>
      </a>
      {crew ? <span className="text-xs"> (Crew repository)</span> : null}
    </li>
  );
}

const ICONS = [<BookIcon key="b" size={18} />, <ShieldIcon key="s" size={18} />, <GhostIcon key="g" size={18} />, <SkullIcon key="k" size={18} />];

export default function HowKiroPage() {
  return (
    <div className="mx-auto flex min-h-screen max-w-4xl flex-col gap-4 p-3 pb-10">
      <nav aria-label="Site" className="on-desk flex flex-wrap gap-4 text-sm font-semibold text-white">
        <a className="underline" href="/">Open the desktop</a>
        <a className="underline" href="/product">Product</a>
        <a className="underline" href="/encyclopedia">Virus definitions</a>
        <a className="underline" href={REPO}>Source code</a>
      </nav>

      <main className="flex flex-col gap-4">
        <header className="on-desk flex flex-col gap-2 py-6 text-white">
          <p className="m-0 font-mono text-sm text-phosphor">C:\&gt; type HOW_KIRO.TXT</p>
          <h1 className="m-0 text-3xl font-extrabold leading-tight sm:text-4xl">{HOW_KIRO_TITLE}</h1>
          {HOW_KIRO_INTRO.map((p) => (
            <p key={p.slice(0, 24)} className="m-0 max-w-3xl text-base"><Rich text={p} /></p>
          ))}
        </header>

        <Panel id="glance" title="Kiro features at a glance" icon={<BookIcon size={18} />}>
          <ul className="m-0 flex list-none flex-col gap-2 p-0" aria-label="Kiro features">
            {SURFACES.map((s) => (
              <li key={s.id} className="bevel-in px-2 py-1">
                <a className="font-bold underline" href={`#${s.id}`}>{s.title}</a>
                <span className="block text-xs">
                  <span className="font-semibold">{s.tool}.</span> Status: {s.status}.
                </span>
              </li>
            ))}
          </ul>
        </Panel>

        {SURFACES.map((s, i) => (
          <Panel key={s.id} id={s.id} title={s.title} icon={ICONS[i % ICONS.length]}>
            <p className="mt-0 font-semibold">
              {s.tool}. <span className="font-normal">Status: {s.status}.</span>
            </p>
            <h3 className="mb-1 text-sm font-extrabold">What we did</h3>
            <ul className="mt-0 list-disc pl-5">
              {s.did.map((d) => <li key={d.slice(0, 40)} className="mb-1"><Rich text={d} /></li>)}
            </ul>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <h3 className="mb-1 text-sm font-extrabold">Files</h3>
                <ul className="m-0 list-disc pl-5">
                  {s.files.map((f) => <PathItem key={f} path={f} />)}
                </ul>
              </div>
              <div>
                <h3 className="mb-1 text-sm font-extrabold">Evidence</h3>
                <ul className="m-0 list-disc pl-5">
                  {s.evidence.map((e) => <li key={e}><Rich text={e} /></li>)}
                </ul>
              </div>
            </div>
          </Panel>
        ))}

        <Panel id="setup" title={USER_SETUP.title} icon={<ShieldIcon size={18} />}>
          <p className="mt-0"><Rich text={USER_SETUP.text} /></p>
          <pre className="log m-0 overflow-x-auto whitespace-pre-wrap break-all p-2 text-xs" tabIndex={0} aria-label="Example command">
            {'C:\\> exorcist init --kiro --shield .'}
          </pre>
          <ul className="mb-0 mt-2 list-disc pl-5">
            {USER_SETUP.files.map((f) => <PathItem key={f} path={f} />)}
          </ul>
        </Panel>

        <Panel id="surprises" title="Where Kiro surprised us" icon={<GhostIcon size={18} />}>
          <ol className="m-0 flex list-none flex-col gap-3 p-0">
            {SURPRISES.map((st, i) => (
              <li key={st.id} id={st.id} className="bevel-in p-3">
                <h3 className="m-0 text-base font-extrabold">
                  <span className="font-mono">{String(i + 1).padStart(2, '0')}.</span> {st.title}
                </h3>
                <p className="mb-1 mt-1"><Rich text={st.story} /></p>
                <ul className="m-0 list-disc pl-5 text-xs">
                  {st.evidence.map((e) => <li key={e}><Rich text={e} /></li>)}
                </ul>
              </li>
            ))}
          </ol>
        </Panel>


        <Panel id="check" title="Check it yourself" icon={<BookIcon size={18} />}>
          <p className="mt-0">Run these from a clone of the repository.</p>
          <pre className="log m-0 overflow-x-auto whitespace-pre-wrap break-all p-2 text-xs" tabIndex={0} aria-label="Commands to check the claims on this page">
            {CHECK_COMMANDS.map((c) => `$ ${c}`).join('\n')}
          </pre>
        </Panel>
      </main>
    </div>
  );
}
