/**
 * Possession Origin: which commit introduced a threat.
 *
 * Every piece of text git prints here (commit subjects, author names, emails,
 * dates) is attacker-controlled: a hostile repository can put terminal escape
 * sequences, bidi overrides or other hidden Unicode in them. So:
 *
 * - git runs through execFile with argument arrays, never a shell;
 * - every path goes after a `--` separator and is matched literally
 *   (`--literal-pathspecs`), the pickaxe string is passed stuck to its flag
 *   (`-S<span>`) and revisions are checked to be hex object names, so nothing
 *   from the repository can be read as a git option;
 * - every git call has a time limit, and each finding has a total budget;
 * - commit text is only ever passed through sanitizeGitText and returned as
 *   data. It is never interpreted, and never put into a prompt.
 */

import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { z } from 'zod';

/** 10 s per finding, as the spec requires (all git calls for one finding together). */
export const ORIGIN_TIMEOUT_MS = 10_000;
/** The default cap for tracing every finding of one run. */
export const ORIGIN_TOTAL_TIMEOUT_MS = 120_000;
/** Longest commit subject / author name kept after sanitising. */
export const MAX_GIT_TEXT = 200;
/** Longest pickaxe needle passed to git (spans are at most 120 chars; this is a backstop). */
const MAX_NEEDLE = 1_000;

// ── Sanitising attacker-controlled text ──────────────────────────────────────

/**
 * Whole terminal escape sequences: CSI (ESC [ ... final), OSC / DCS / SOS /
 * PM / APC strings (ESC ] ... BEL or ST), the 8-bit CSI and OSC forms, and
 * two-character ESC sequences. Removed as a unit, so no "[31m" debris is left.
 */
const ESCAPE_SEQUENCE = new RegExp(
  [
    '\\u001b\\[[0-?]*[ -/]*[@-~]', // CSI
    '\\u009b[0-?]*[ -/]*[@-~]', // 8-bit CSI
    '\\u001b[\\]PX^_][^\\u0007\\u001b\\u009c]*(?:\\u0007|\\u001b\\\\|\\u009c)?', // OSC, DCS, SOS, PM, APC
    '[\\u009d\\u0090\\u0098\\u009e\\u009f][^\\u0007\\u001b\\u009c]*(?:\\u0007|\\u001b\\\\|\\u009c)?', // 8-bit forms
    '\\u001b[ -/]*[0-~]', // other ESC sequences (charset, keypad, RIS ...)
  ].join('|'),
  'g',
);

/**
 * Control, format and invisible code points: C0/C1 controls and DEL (Cc);
 * zero-width, bidi, soft hyphen, word joiner, BOM, interlinear annotation and
 * the Unicode tag block (Cf); line and paragraph separators; variation
 * selectors; the invisible fillers and the combining grapheme joiner;
 * unassigned tag-block and non-character code points.
 */
const HIDDEN = /[\p{Cc}\p{Cf}\u2028\u2029\uFE00-\uFE0F\u{E0100}-\u{E01EF}\u{E0000}-\u{E007F}\u034F\u115F\u1160\u17B4\u17B5\u180B-\u180F\u3164\uFFA0\uFFFC\uFDD0-\uFDEF\uFFFE\uFFFF]/gu;

/**
 * Attacker-controlled git text made safe to print: escape sequences and
 * hidden characters removed, line breaks and tabs turned into spaces,
 * whitespace collapsed, and the result cut to `max` characters.
 */
export function sanitizeGitText(text: string, max = MAX_GIT_TEXT): string {
  const flat = text
    .replace(ESCAPE_SEQUENCE, '')
    .replace(/[\t\n\r\v\f\u0085\u2028\u2029]+/g, ' ')
    .replace(HIDDEN, '')
    .replace(/\s+/g, ' ')
    .trim();
  const chars = Array.from(flat);
  return chars.length <= max ? flat : `${chars.slice(0, max - 1).join('')}…`;
}

const ESCAPE_PROBE = new RegExp(ESCAPE_SEQUENCE.source);
const HIDDEN_PROBE = new RegExp(HIDDEN.source, 'u');

/** True when the text carries escape sequences or hidden characters (line breaks and tabs aside): a sign of tampering. */
export function hadHiddenText(raw: string): boolean {
  const probe = raw.replace(/[\t\n\r]/g, ' ');
  return ESCAPE_PROBE.test(probe) || HIDDEN_PROBE.test(probe);
}

// ── Bot detection ────────────────────────────────────────────────────────────

const BOT_NAMES = /^(dependabot|renovate|github-actions|greenkeeper|snyk-bot|semantic-release-bot|allcontributors|mergify|pre-commit-ci|imgbot|codecov|depfu|pyup-bot|whitesource|deepsource-autofix)(\[bot\]|-bot|\b)/i;
/** "name[bot]", "Some Bot", "release-bot", "ci_bot" (but not "Talbot" or "Abbot"). */
const BOT_SUFFIX = /(\[bot\]|(?:^|[\s_.-])bot)$/i;
/** GitHub app accounts: 1234+name[bot]@users.noreply.github.com. */
const BOT_EMAIL = /\[bot\]@|^(?:bot|noreply-bot|ci-bot)@|(?:^|[+._-])bot@/i;

/** True when the author looks like an automation account. */
export function isBotAuthor(name: string, email: string): boolean {
  const n = name.trim();
  const e = email.trim();
  return BOT_NAMES.test(n) || BOT_SUFFIX.test(n) || BOT_EMAIL.test(e);
}

// ── Git plumbing ─────────────────────────────────────────────────────────────

export type GitError = { kind: 'timeout' | 'missing' | 'failed'; message: string };
type GitResult = { ok: true; stdout: string } | { ok: false; error: GitError };

/** Options in front of every git call: no pager, literal paths, nothing from repo config that runs commands or changes output. */
const GIT_PREFIX = [
  '--no-pager',
  '--literal-pathspecs',
  '-c', 'core.fsmonitor=false',
  '-c', 'log.showSignature=false',
  '-c', 'color.ui=never',
];

/** Environment variables that would point git at a different repository than the one asked for. */
const GIT_LOCATION_VARS = [
  'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_COMMON_DIR', 'GIT_NAMESPACE', 'GIT_CEILING_DIRECTORIES', 'GIT_EXTERNAL_DIFF', 'GIT_PAGER', 'GIT_TRACE',
];

function gitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const k of GIT_LOCATION_VARS) delete env[k];
  return { ...env, GIT_PAGER: 'cat', PAGER: 'cat', GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0', LC_ALL: 'C' };
}

/**
 * Run git with an argument array (never a shell). Errors are typed and carry
 * only our own wording: git's message can quote paths and the pickaxe span,
 * which are attacker-controlled.
 */
export function runGit(cwd: string, args: readonly string[], timeoutMs: number): Promise<GitResult> {
  if (timeoutMs <= 0) return Promise.resolve({ ok: false, error: { kind: 'timeout', message: 'time limit reached' } });
  return new Promise((done) => {
    execFile(
      'git',
      [...GIT_PREFIX, ...args],
      { cwd, encoding: 'utf8', timeout: Math.ceil(timeoutMs), killSignal: 'SIGKILL', maxBuffer: 8 * 1024 * 1024, env: gitEnv(), windowsHide: true },
      (err, stdout) => {
        if (!err) { done({ ok: true, stdout }); return; }
        const e = err as NodeJS.ErrnoException & { killed?: boolean; signal?: string | null; code?: unknown };
        if (e.code === 'ENOENT') done({ ok: false, error: { kind: 'missing', message: 'git is not installed or not on PATH' } });
        else if (e.killed === true || e.signal) done({ ok: false, error: { kind: 'timeout', message: `git timed out after ${Math.round(timeoutMs / 100) / 10} s` } });
        else if (e.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') done({ ok: false, error: { kind: 'failed', message: 'git printed too much output' } });
        else done({ ok: false, error: { kind: 'failed', message: typeof e.code === 'number' ? `git exited with code ${e.code}` : 'git failed' } });
      },
    );
  });
}

/** The enclosing git work tree, or null when there is none (or git refuses to open it). */
export async function gitRepoRoot(cwd: string): Promise<string | null> {
  const r = await runGit(cwd, ['rev-parse', '--show-toplevel'], 5_000);
  const root = r.ok ? r.stdout.replace(/\n$/, '') : '';
  return root !== '' && isAbsolute(root) ? root : null;
}

/** True when the repository is a shallow clone (older history is missing). */
export async function isShallowClone(cwd: string): Promise<boolean> {
  const r = await runGit(cwd, ['rev-parse', '--is-shallow-repository'], 5_000);
  return r.ok && r.stdout.trim() === 'true';
}

const OBJECT_ID = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const ZERO_ID = /^0+$/;

/** The commits a shallow clone was cut at: history before them is missing. */
export async function shallowBoundaries(repoRoot: string): Promise<Set<string>> {
  const r = await runGit(repoRoot, ['rev-parse', '--git-path', 'shallow'], 5_000);
  if (!r.ok) return new Set();
  const rel = r.stdout.replace(/\n$/, '');
  const file = isAbsolute(rel) ? rel : join(repoRoot, rel);
  try {
    const text = await readFile(file, 'utf8');
    return new Set(text.split('\n').map((l) => l.trim()).filter((l) => OBJECT_ID.test(l)));
  } catch {
    return new Set();
  }
}

// ── The introducing commit ───────────────────────────────────────────────────

export type OriginCommit = {
  sha:     string;
  author:  string;   // sanitised
  email:   string;   // sanitised
  date:    string;   // author date, ISO 8601 (attacker-settable, like everything in a commit)
  subject: string;   // sanitised
  bot:     boolean;
  /** The author name or subject carried escape sequences or hidden characters (removed). */
  hiddenText: boolean;
  /** This is where a shallow clone was cut, so the threat may be older than this commit. */
  boundary: boolean;
};

export type OriginMethod = 'log-s' | 'blame';

export type OriginHit =
  | { status: 'found';       commit: OriginCommit; method: OriginMethod }
  | { status: 'uncommitted'; reason: string }
  | { status: 'not-found';   reason: string }
  | { status: 'timeout';     reason: string }
  | { status: 'error';       reason: string };

export type OriginOptions = {
  /** Budget for all git calls of this finding (default ORIGIN_TIMEOUT_MS). */
  timeoutMs?: number;
  /** Absolute time (Date.now()) after which no git call starts. */
  deadline?: number;
  /** Shallow-clone cut points, from shallowBoundaries(). */
  boundaries?: ReadonlySet<string>;
  /** Commit metadata cache shared across findings. */
  cache?: Map<string, OriginCommit | null>;
};

/** %an, %ae, %aI, %s separated by NUL (git idents and dates cannot contain NUL). */
const SHOW_FORMAT = '--format=%an%x00%ae%x00%aI%x00%s';
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$/;

/** Parse `git show -s` output for one commit. Exported for tests. */
export function parseCommitFields(sha: string, out: string, boundaries: ReadonlySet<string> = new Set()): OriginCommit | null {
  const parts = out.replace(/\n$/, '').split('\u0000');
  if (parts.length < 4) return null;
  const [rawAuthor = '', rawEmail = '', rawDate = '', ...rest] = parts;
  const rawSubject = rest.join(' ');
  const author = sanitizeGitText(rawAuthor);
  const email = sanitizeGitText(rawEmail);
  const date = rawDate.trim();
  return {
    sha,
    author,
    email,
    date: ISO_DATE.test(date) ? date : '',
    subject: sanitizeGitText(rawSubject),
    bot: isBotAuthor(author, email),
    hiddenText: hadHiddenText(rawAuthor) || hadHiddenText(rawSubject),
    boundary: boundaries.has(sha),
  };
}

type Budget = { left: () => number };

function budgetFor(opts: OriginOptions): Budget {
  const end = Math.min(Date.now() + (opts.timeoutMs ?? ORIGIN_TIMEOUT_MS), opts.deadline ?? Number.POSITIVE_INFINITY);
  return { left: () => end - Date.now() };
}

async function commitInfo(repoRoot: string, sha: string, budget: Budget, opts: OriginOptions): Promise<OriginCommit | GitError> {
  const cached = opts.cache?.get(sha);
  if (cached) return cached;
  // `sha` is a validated hex object id, so it cannot be read as an option;
  // --end-of-options says so to git as well.
  const r = await runGit(repoRoot, ['show', '-s', '--no-color', SHOW_FORMAT, '--end-of-options', sha], budget.left());
  if (!r.ok) return r.error;
  const parsed = parseCommitFields(sha, r.stdout, opts.boundaries);
  if (!parsed) return { kind: 'failed', message: 'could not read the commit' };
  opts.cache?.set(sha, parsed);
  return parsed;
}

function failure(e: GitError): OriginHit {
  return e.kind === 'timeout' ? { status: 'timeout', reason: e.message } : { status: 'error', reason: e.message };
}

type Pick = { sha: string; time: number };

/**
 * Find the commit that introduced a finding.
 *
 * 1. `git log -S<span> -- <file>` (pickaxe) lists the commits, newest first,
 *    where the number of occurrences of the exact quoted span in that file
 *    changed.
 * 2. `git blame -L <line>,<line> -- <file>` names the commit that last
 *    touched the finding's line in the working tree.
 *
 * When the blamed commit is also a pickaxe commit it introduced the span.
 * When it is not (the line was edited later without touching the span), the
 * span is older: the newest pickaxe commit no later than the blamed one is
 * the origin. With no pickaxe hit (the span was normalised or cut), the
 * blamed commit is used. A line that is not committed yet is reported as such.
 */
export async function findOriginCommit(
  repoRoot: string,
  relFile:  string,
  line:     number,
  span:     string,
  opts:     OriginOptions = {},
): Promise<OriginHit> {
  if (relFile === '' || relFile.includes('\u0000')) return { status: 'error', reason: 'invalid file path' };
  if (!Number.isInteger(line) || line < 1) return { status: 'error', reason: 'invalid line number' };
  const budget = budgetFor(opts);

  // 1. Pickaxe. The needle is stuck to -S so it can never become an option.
  const needle = span.length > MAX_NEEDLE ? span.slice(0, MAX_NEEDLE) : span;
  let picks: Pick[] = [];
  if (needle.trim() !== '' && !needle.includes('\u0000')) {
    const log = await runGit(
      repoRoot,
      ['log', '--no-color', '--no-ext-diff', '--no-textconv', '--format=%H %ct', `-S${needle}`, '--', relFile],
      budget.left(),
    );
    if (!log.ok) {
      // An empty repository has no HEAD: not an error, just no history.
      if (log.error.kind !== 'failed') return failure(log.error);
    } else {
      picks = log.stdout.split('\n').flatMap((l) => {
        const [sha = '', t = ''] = l.trim().split(' ');
        return OBJECT_ID.test(sha) ? [{ sha, time: Number(t) || 0 }] : [];
      });
    }
  }

  // 2. Blame the line in the working tree.
  const blame = await runGit(repoRoot, ['blame', '--porcelain', '--no-textconv', '-L', `${line},${line}`, '--', relFile], budget.left());
  let blamed: Pick | null = null;
  if (blame.ok) {
    const lines = blame.stdout.split('\n');
    const sha = (lines[0] ?? '').split(' ')[0] ?? '';
    if (ZERO_ID.test(sha)) return { status: 'uncommitted', reason: 'this line is not committed yet' };
    const time = Number(lines.find((l) => l.startsWith('committer-time '))?.slice(15) ?? 0) || 0;
    if (OBJECT_ID.test(sha)) blamed = { sha, time };
  } else if (blame.error.kind !== 'failed') {
    return failure(blame.error);
  }

  let chosen: Pick | undefined;
  let method: OriginMethod = 'log-s';
  if (picks.length > 0) {
    const b = blamed;
    chosen = b
      ? picks.find((p) => p.sha === b.sha) ?? picks.find((p) => p.time <= b.time) ?? picks[0]
      : picks[0];
  } else if (blamed) {
    chosen = blamed;
    method = 'blame';
  }
  if (!chosen) {
    return blame.ok
      ? { status: 'not-found', reason: 'no commit in the history added this text' }
      : { status: 'not-found', reason: 'the file is not tracked by git' };
  }

  const info = await commitInfo(repoRoot, chosen.sha, budget, opts);
  if ('kind' in info) return failure(info);
  return { status: 'found', commit: info, method };
}

// ── Tracing many findings, with an overall cap ───────────────────────────────

export type OriginQuery = { file: string; line: number; span: string };

export type TraceOptions = {
  perFindingMs?: number;
  totalMs?: number;
  boundaries?: ReadonlySet<string>;
};

/**
 * Trace each query in turn. Each finding gets at most `perFindingMs`; once
 * `totalMs` has passed the rest are reported as timeouts without running git.
 * Repeated (file, line, span) queries are answered once. Results are in the
 * same order as the queries.
 */
export async function traceOrigins(repoRoot: string, queries: readonly OriginQuery[], opts: TraceOptions = {}): Promise<OriginHit[]> {
  const deadline = Date.now() + (opts.totalMs ?? ORIGIN_TOTAL_TIMEOUT_MS);
  const cache = new Map<string, OriginCommit | null>();
  const seen = new Map<string, OriginHit>();
  const out: OriginHit[] = [];
  for (const q of queries) {
    const key = `${q.file}\u0000${q.line}\u0000${q.span}`;
    let hit = seen.get(key);
    if (!hit) {
      hit = Date.now() >= deadline
        ? { status: 'timeout', reason: 'overall time limit reached before this finding was traced' }
        : await findOriginCommit(repoRoot, q.file, q.line, q.span, {
          timeoutMs: opts.perFindingMs ?? ORIGIN_TIMEOUT_MS,
          deadline,
          cache,
          ...(opts.boundaries ? { boundaries: opts.boundaries } : {}),
        });
      seen.set(key, hit);
    }
    out.push(hit);
  }
  return out;
}

// ── The report ───────────────────────────────────────────────────────────────

export const OriginStatusSchema = z.enum(['log-s', 'blame', 'uncommitted', 'not-found', 'timeout', 'error']);

/** One threat on the timeline, as it is reported. */
export const TimelineThreatSchema = z.object({
  ruleId:   z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  file:     z.string(),
  line:     z.number().int().positive(),
  title:    z.string(),
  span:     z.string(),
  origin:   OriginStatusSchema,
  reason:   z.string().optional(),
});
export type TimelineThreat = z.infer<typeof TimelineThreatSchema>;

/** One commit group on the timeline. */
export const TimelineCommitSchema = z.object({
  sha:        z.string().regex(OBJECT_ID),
  author:     z.string(),
  email:      z.string(),
  bot:        z.boolean(),
  date:       z.string(),
  subject:    z.string(),
  hiddenText: z.boolean(),
  boundary:   z.boolean(),
  threats:    z.array(TimelineThreatSchema).min(1),
});
export type TimelineCommit = z.infer<typeof TimelineCommitSchema>;

export const OriginReportSchema = z.object({
  tool:          z.literal('exorcist-origin'),
  target:        z.string(),
  repoRoot:      z.string(),
  shallowClone:  z.boolean(),
  notes:         z.array(z.string()),
  limits:        z.object({ perFindingMs: z.number().int().positive(), totalMs: z.number().int().positive() }),
  commits:       z.array(TimelineCommitSchema),
  unknown:       z.array(TimelineThreatSchema),
  filesScanned:  z.number().int().nonnegative(),
  findingsTotal: z.number().int().nonnegative(),
});
export type OriginReport = z.infer<typeof OriginReportSchema>;

/** A short sha for display. */
export const shortSha = (sha: string): string => sha.slice(0, 7);

/** Oldest first by author date (commits with no readable date last), then by sha. */
export function sortCommitsByDate(commits: readonly TimelineCommit[]): TimelineCommit[] {
  const t = (c: TimelineCommit): number => (c.date ? Date.parse(c.date) : Number.POSITIVE_INFINITY);
  return [...commits].sort((a, b) => t(a) - t(b) || a.sha.localeCompare(b.sha));
}

export type TracedThreat = { threat: Omit<TimelineThreat, 'origin' | 'reason'>; hit: OriginHit };

/** Group traced threats by introducing commit, oldest first; the rest go to `unknown`. Pure. */
export function buildTimeline(traced: readonly TracedThreat[]): { commits: TimelineCommit[]; unknown: TimelineThreat[] } {
  const bySha = new Map<string, TimelineCommit>();
  const unknown: TimelineThreat[] = [];
  for (const { threat, hit } of traced) {
    if (hit.status === 'found') {
      const t: TimelineThreat = { ...threat, origin: hit.method };
      const group = bySha.get(hit.commit.sha);
      if (group) group.threats.push(t);
      else bySha.set(hit.commit.sha, { ...hit.commit, threats: [t] });
    } else {
      unknown.push({ ...threat, origin: hit.status, reason: hit.reason });
    }
  }
  return { commits: sortCommitsByDate([...bySha.values()]), unknown };
}
