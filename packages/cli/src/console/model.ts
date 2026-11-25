/**
 * What the live console shows, built from the Shield state folder only:
 * the event log (events.jsonl, written by every Shield process) and the
 * Session Guard's shared records (sessions/<key>/<pid>.json). Read-only: it
 * never writes, renames or deletes anything in the state folder.
 */
import { lstatSync, readdirSync } from 'node:fs';
import type { CapabilityRule } from '@exorcist-98/core';
import { EventTail, FileSessionStore, SESSION_TTL_MS, assessSession, cleanText, isSessionKey, sessionsPath } from '@exorcist-98/shield';
import type { CallShieldEvent, Fact, ShieldEvent } from '@exorcist-98/shield';

/** Events kept in memory and sent to a newly opened page. */
export const BACKLOG = 400;
const MAX_SHIELDS = 64;
const MAX_SESSIONS = 16;
const MAX_FACTS_SHOWN = 12;
/** Times further ahead than this are not believed (as in session.ts). */
const MAX_SKEW_MS = 5 * 60 * 1000;

export type FactView = { kind: Fact['kind']; tool: string; server: string; ruleId: string; time: string; text: string };

export type SessionView = {
  key: string;
  /** Untrusted text and private data both seen since the last release from `exorcist approve session`. */
  armed: boolean;
  /** Part of the shared state could not be read and one half is known: Shields hold to be safe. */
  cautious: boolean;
  untrusted: FactView[];
  private: FactView[];
  /** When `exorcist approve session` last released this session, if it did. */
  releasedAt?: string;
  problems: string[];
  /** Calls held for an answer in the agent's approval prompt, not answered yet, from Shields still running. */
  waiting: CallShieldEvent[];
};

export type ShieldView = {
  pid: number;
  server: string;
  session?: string;
  mode: 'enforce' | 'monitor';
  guard: 'hold' | 'block' | 'monitor' | 'off';
  remote: boolean;
  started: string;
  lastSeen: string;
  /** The process is still alive (checked with signal 0; a reused pid would also look alive). */
  running: boolean;
};

export type Counts = { allowed: number; held: number; blocked: number; withheld: number; flagged: number; alerts: number };

export type ConsoleState = {
  stateDir: string;
  shields: ShieldView[];
  sessions: SessionView[];
  counts: Counts;
  /** Lines of the event log that were not valid events (damaged, edited, or from a newer version). */
  skipped: number;
};

export type Liveness = (pid: number) => boolean;

export const pidAlive: Liveness = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as { code?: string }).code === 'EPERM';
  }
};

const FACT_WORDS: Record<string, string> = {
  'EX-017': 'returned a secret',
  'EX-022': 'returned a canary token',
  'EX-011': 'read a file that usually holds secrets, or one outside the project',
};

function factText(f: Fact, rules: readonly CapabilityRule[]): string {
  const label = f.ruleId.startsWith('CAP-') ? rules.find((r) => r.id === f.ruleId)?.label : undefined;
  return label ?? FACT_WORDS[f.ruleId] ?? (f.kind === 'untrusted' ? 'returned text that may be instructions for your AI' : 'returned private data');
}

export class ConsoleModel {
  private readonly tail: EventTail;
  private readonly backlog: ShieldEvent[] = [];
  private readonly shields = new Map<string, ShieldView>();
  /** Held calls by `pid:prompt`, until an answer arrives. */
  private readonly held = new Map<string, CallShieldEvent>();
  readonly counts: Counts = { allowed: 0, held: 0, blocked: 0, withheld: 0, flagged: 0, alerts: 0 };

  constructor(
    readonly dir: string,
    private readonly o: { rules?: readonly CapabilityRule[]; alive?: Liveness; now?: () => Date } = {},
  ) {
    this.tail = new EventTail(dir);
  }

  private now(): Date {
    return this.o.now ? this.o.now() : new Date();
  }

  /** Read new events from the log. Returns only the new ones. */
  poll(): ShieldEvent[] {
    const fresh = this.tail.read();
    for (const e of fresh) this.take(e);
    this.backlog.push(...fresh);
    if (this.backlog.length > BACKLOG) this.backlog.splice(0, this.backlog.length - BACKLOG);
    return fresh;
  }

  events(): ShieldEvent[] {
    return [...this.backlog];
  }

  private take(e: ShieldEvent): void {
    const id = `${e.pid}:${e.server}`;
    if (e.kind === 'start') {
      this.shields.set(id, { pid: e.pid, server: e.server, ...(e.session ? { session: e.session } : {}), mode: e.mode, guard: e.guard, remote: e.remote, started: e.time, lastSeen: e.time, running: true });
      while (this.shields.size > MAX_SHIELDS) this.shields.delete(this.shields.keys().next().value as string);
    } else {
      const s = this.shields.get(id);
      if (s) s.lastSeen = e.time;
    }
    if (e.kind === 'call') {
      this.counts[e.decision]++;
      const key = e.prompt !== undefined ? `${e.pid}:${e.prompt}` : null;
      if (key && e.decision === 'held') this.held.set(key, e);
      else if (key && e.by === 'user') this.held.delete(key);
      while (this.held.size > 256) this.held.delete(this.held.keys().next().value as string);
    } else if (e.kind === 'result') {
      this.counts[e.decision]++;
    } else if (e.kind === 'alert') {
      this.counts.alerts++;
    }
  }

  state(): ConsoleState {
    const alive = this.o.alive ?? pidAlive;
    const running = new Map<number, boolean>();
    const isAlive = (pid: number): boolean => {
      let r = running.get(pid);
      if (r === undefined) { r = alive(pid); running.set(pid, r); }
      return r;
    };
    const shields = [...this.shields.values()]
      .map((s) => ({ ...s, running: isAlive(s.pid) }))
      .sort((a, b) => Number(b.running) - Number(a.running) || b.lastSeen.localeCompare(a.lastSeen));
    const waiting = [...this.held.values()].filter((e) => isAlive(e.pid));
    return {
      stateDir: this.dir,
      shields,
      sessions: this.sessions(waiting),
      counts: { ...this.counts },
      skipped: this.tail.skipped,
    };
  }

  /** Every session with live facts or a held call, newest first. */
  private sessions(waiting: CallShieldEvent[]): SessionView[] {
    const now = this.now();
    const n = now.getTime();
    const rules = this.o.rules ?? [];
    const root = sessionsPath(this.dir);
    let names: string[] = [];
    try { names = readdirSync(root).filter((k) => isSessionKey(k)); } catch { names = []; }
    const keys = new Set([...names, ...waiting.flatMap((w) => (w.session ? [w.session] : []))]);
    const views: Array<SessionView & { newest: number }> = [];
    for (const key of [...keys].slice(0, 256)) {
      let isDir = false;
      try { isDir = lstatSync(`${root}/${key}`).isDirectory(); } catch { isDir = false; }
      const view = isDir ? new FileSessionStore(this.dir, key).read(now) : { records: [], problems: [] };
      const a = assessSession(view.records, view.problems, now);
      const live = view.records.flatMap((r) => r.facts).filter((f) => {
        const t = Date.parse(f.time);
        return t <= n + MAX_SKEW_MS && n - t <= SESSION_TTL_MS;
      });
      // The same fact noted by several Shields (or again later) is shown once, with its newest time.
      const byId = new Map<string, Fact>();
      for (const f of live) {
        const id = `${f.kind}\u0000${f.server}\u0000${f.tool}\u0000${f.ruleId}`;
        const had = byId.get(id);
        if (!had || Date.parse(f.time) > Date.parse(had.time)) byId.set(id, f);
      }
      const facts = [...byId.values()].sort((x, y) => Date.parse(y.time) - Date.parse(x.time));
      const show = (f: Fact): FactView => ({ kind: f.kind, tool: cleanText(f.tool, 80), server: cleanText(f.server, 80), ruleId: f.ruleId, time: f.time, text: factText(f, rules) });
      const released = view.records.find((r) => r.writer === 'cli')?.grants.map((g) => g.time).filter((t) => Date.parse(t) <= n + MAX_SKEW_MS).sort().pop();
      const held = waiting.filter((w) => w.session === key);
      if (facts.length === 0 && held.length === 0 && a.problems.length === 0) continue;
      views.push({
        key,
        armed: a.armed,
        cautious: a.cautious,
        untrusted: facts.filter((f) => f.kind === 'untrusted').slice(0, MAX_FACTS_SHOWN).map(show),
        private: facts.filter((f) => f.kind === 'private').slice(0, MAX_FACTS_SHOWN).map(show),
        ...(released ? { releasedAt: released } : {}),
        problems: a.problems.slice(0, 5).map((p) => cleanText(p, 300)),
        waiting: held,
        newest: Math.max(0, ...facts.map((f) => Date.parse(f.time)), ...held.map((h) => Date.parse(h.time))),
      });
    }
    return views
      .sort((x, y) => y.newest - x.newest)
      .slice(0, MAX_SESSIONS)
      .map(({ newest: _n, ...v }) => v);
  }
}
