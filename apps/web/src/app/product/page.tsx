import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { SiteFooter } from '@/components/SiteFooter';
import facts from '@/lib/facts.json';
import { BookIcon, GhostIcon, ShieldIcon, SkullIcon } from '@/components/Icons';

export const metadata: Metadata = {
  title: 'Exorcist 98: antivirus for AI coding agents',
  description:
    'Your AI agent reads text anyone can write. Exorcist 98 scans repos for hidden instructions and poisoned tools, and shields MCP servers in real time.',
};

const REPO = 'https://github.com/pranavsaji/exorcist-98';
const FOUNDER = { name: 'Pranav Saji', github: 'https://github.com/pranavsaji', linkedin: 'https://www.linkedin.com/in/pranav-saji' };

function Panel({ title, icon, children }: { title: string; icon?: ReactNode; children: ReactNode }) {
  return (
    <section className="win win-flow relative !max-h-none !max-w-full" aria-labelledby={`panel-${title}`}>
      <div className="titlebar" data-active="true">
        {icon}
        <h2 id={`panel-${title}`} className="m-0 flex-1 truncate text-sm font-bold">{title}</h2>
      </div>
      <div className="p-3 text-sm">{children}</div>
    </section>
  );
}

const PARTS = [
  {
    title: 'Full System Scan',
    icon: <SkullIcon size={28} />,
    text: 'Paste a public repository link. Every file your agent would read is checked: READMEs, steering and memory files, MCP configs, hooks and install scripts. Each finding shows the file, the line, the exact text and the fix.',
  },
  {
    title: 'Virus Definitions',
    icon: <BookIcon size={28} />,
    text: `${facts.definitions} open, readable signatures for hidden Unicode, instructions aimed at the agent, poisoned tool descriptions, remote code in hooks and leaky install scripts. Each maps to the OWASP lists for LLM, agentic and MCP risks.`,
  },
  {
    title: 'Real-Time Shield',
    icon: <ShieldIcon size={28} />,
    text: 'A small firewall between your agent and its MCP servers. It pins every tool, hides one that changes after you approved it, stops secrets leaving in tool calls, withholds tool results that try to give your agent orders, and holds data going out once a session has read untrusted text and a secret (the Session Guard). On macOS a held call is released in the system prompt (Touch ID or your login password), which only the Shield can answer.',
  },
  {
    title: 'Quarantine Vault',
    icon: <GhostIcon size={28} />,
    text: 'Disable an infected MCP server, hook or steering file with one command. A backup and a diff are kept, and restore puts back the original exactly.',
  },
];

export default function ProductPage() {
  return (
    <div className="mx-auto flex min-h-screen max-w-4xl flex-col gap-4 p-3 pb-10">
      <nav aria-label="Site" className="on-desk flex flex-wrap gap-4 text-sm font-semibold text-white">
        <a className="underline" href="/">Open the desktop</a>
        <a className="underline" href="/encyclopedia">Virus definitions</a>
        <a className="underline" href={REPO}>Source code</a>
      </nav>

      <main className="flex flex-col gap-4">
      <header className="on-desk flex flex-col gap-2 py-6 text-white">
        <p className="m-0 font-mono text-sm text-phosphor">C:\&gt; exorcist scan .</p>
        <h1 className="m-0 text-3xl font-extrabold leading-tight sm:text-4xl">Your AI agent has a virus.</h1>
        <p className="m-0 max-w-2xl text-base">
          Coding agents read READMEs, tool descriptions, steering files and pull requests, and anyone can write
          those. Exorcist 98 brings back the 90s antivirus, pointed at the files and tools your agent trusts.
        </p>
        <div className="mt-2 flex flex-wrap gap-2">
          <a className="btn" href="/">Scan a repository now</a>
          <a className="btn" href={REPO}>Get the CLI and the shield</a>
        </div>
      </header>

      <Panel title="The problem">
        <p className="mt-0">
          A prompt injection does not need to break into anything. It only needs to be read. One hidden line in a
          README, an invisible character in a steering file, or an MCP tool whose description quietly changes after
          you approved it, and your agent may send your keys somewhere or run a script you never saw.
        </p>
        <p className="mb-0">
          Classic scanners look for malware in code. These attacks are plain text addressed to your AI, so they
          pass straight through.
        </p>
      </Panel>

      <div className="grid gap-4 sm:grid-cols-2">
        {PARTS.map((p) => (
          <Panel key={p.title} title={p.title} icon={p.icon}>
            <p className="m-0">{p.text}</p>
          </Panel>
        ))}
      </div>

      <Panel title="Who it is for">
        <ul className="m-0 list-disc pl-5">
          <li>Developers who let an agent read repositories they did not write.</li>
          <li>Teams that connect agents to MCP servers from the open ecosystem.</li>
          <li>Maintainers who want a check on every pull request before an agent touches it.</li>
        </ul>
      </Panel>

      <Panel title="What is in the box">
        <ul className="m-0 list-disc pl-5">
          <li>
            <strong>Session Guard with OS release.</strong> Run the Lethal Trifecta demo and see an outgoing message held
            until you answer in the system prompt. macOS only. On Linux and Windows a held session is released with a typed
            code in a terminal, which is weaker.
          </li>
          <li>
            <strong>Shield console</strong> (<code>exorcist console</code>): a read-only local page that shows every call
            allowed, held or blocked as it happens. It is also the audit log you can read: each Shield writes its decisions
            to <code>events.jsonl</code> in its state folder.
          </li>
          <li>
            <strong>Editor extension</strong> for Kiro and VS Code (Open VSX): hidden characters drawn as markers, the hidden
            message decoded on hover, and an Exorcise quick fix.
          </li>
          <li>
            <strong>Kiro Power</strong> and an MCP server, so an agent can ask for a scan. <strong>Kiro Crew app</strong>:
            a nightly patrol of your folders.
          </li>
          <li>
            <strong>AI judge</strong> for reworded attacks no pattern catches. It needs your own AWS account, and on this
            site it is off unless the operator turns it on.
          </li>
        </ul>
      </Panel>
      <Panel title="Plans">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="bevel-in p-3">
            <h3 className="m-0 text-base font-extrabold">Free and open source</h3>
            <p className="m-0 text-xs font-semibold">Available today, Apache-2.0</p>
            <ul className="mb-0 mt-2 list-disc pl-5">
              <li>Full System Scan, web and command line</li>
              <li>Open virus definitions</li>
              <li>Real-Time Shield, Session Guard and Quarantine Vault</li>
              <li>GitHub Action with SARIF and pull-request comments</li>
              <li>A team lockfile (<code>exorcist.lock</code>) that shares approved tool fingerprints through git</li>
            </ul>
          </div>
          <div className="bevel-in p-3">
            <h3 className="m-0 text-base font-extrabold">Team</h3>
            <p className="m-0 text-xs font-semibold">Planned, not built yet</p>
            <ul className="mb-0 mt-2 list-disc pl-5">
              <li>A fleet view of every agent workspace and its infection level</li>
              <li>Shield policies managed in one place for a whole team</li>
              <li>A central audit log across machines (today each machine keeps its own)</li>
            </ul>
          </div>
        </div>
      </Panel>
      <Panel title="Built with Kiro">
        <p className="mt-0">
          Exorcist 98 was built for Kiroween 2026 with Kiro specs (one per milestone), steering, hooks and
          property-based tests. It ships as a Kiro Power, an MCP server and a command-line tool.
        </p>
        <p className="mb-0">
          Founded and built by {FOUNDER.name} (<a className="underline" href={FOUNDER.linkedin}>LinkedIn</a>,{' '}
          <a className="underline" href={FOUNDER.github}>GitHub</a>).
        </p>
      </Panel>
      </main>
      <SiteFooter />
    </div>
  );
}
