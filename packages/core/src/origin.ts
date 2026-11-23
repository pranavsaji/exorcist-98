/**
 * Possession Origin: which commit introduced a threat.
 *
 * Every piece of text git prints here (commit subjects, author names,
 * emails) is attacker-controlled: a hostile repository can put terminal
 * control sequences or hidden Unicode in them. Everything is read through
 * execFile with argument arrays (never a shell) and passed through
 * sanitizeGitText before it is shown anywhere.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { z } from 'zod';

const execFileAsync = promisify(execFile);

/** 10 s per finding, as the spec requires. */
export const ORIGIN_TIMEOUT_MS = 10_000;

// ── Sanitising attacker-controlled text ──────────────────────────────────────

/**
 * Control and hidden code points that are stripped from git output:
 * C0 and C1 controls, DEL, soft hyphen, zero-width and bidi characters,
 * interlinear annotation, the Unicode tag block and non-characters.
 */
function isHiddenCodePoint(cp: number): boolean {
  return (
    (cp >= 0x00 && cp <= 0x1f) || // C0
    cp === 0x7f || // DELETE
    (cp >= 0x80 && cp <= 0x9f) || // C1
    cp === 0xad || // soft hyphen
    (cp >= 0x200b && cp <= 0x200f) || // zero-width + LRM/RLM marks
    (cp >= 0x202a && cp <= 0x202e) || // bidi overrides
    (cp >= 0x2060 && cp <= 0x2064) || // word joiner, invisible operators
    (cp >= 0x2066 && cp <= 0x2069) || // bidi isolates
    (cp === 0x180e) || // mongolian vowel separator
    (cp >= 0xfeff && cp <= 0xfeff) || // BOM / zero-width no-break space
    (cp >= 0xfff9 && cp <= 0xfffb) || // interlinear annotation
    (cp >= 0xe0000 && cp <= 0xe007f) || // Unicode tag block
    (cp >= 0xfdd0 && cp <= 0xfdef) || // non-characters
    (cp & 0xfffe) === 0xfffe // non-characters at plane ends
  );
}

/** Remove control and hidden characters, collapse whitespace, trim. */
export function sanitizeGitText(text: string): string {
  const kept = Array.from(text).filter((ch) => {
    const cp = ch.codePointAt(0) ?? 0;
    return !isHiddenCodePoint(cp);
  });
  return kept.join('').replace(/[ \t]+/g, ' ').trim();
}

// ── Bot detection ────────────────────────────────────────────────────────────

const BOT_NAME = /^\s*(dependabot|renovate|github-actions|copilot|semantic-release|greenkeeper|allcontributors|mergify)\b/i;
const BOT_TRAIL = /bot\]?\s*$/i;
const BOT_EMAIL = /(^|@)[^\s@]*bot[^\s@]*@|[\\[]bot[\]]|[^\s@]*\.noreply\.(github|gitlab)\.com$/i;

/** True when the author looks like an automation account. */
export function isBotAuthor(name: string, email: string): boolean {
  const n = name.toLowerCase();
  return BOT_NAME.test(n) || BOT_TRAIL.test(n) || BOT_EMAIL.test(email.toLowerCase());
}

// ── Git plumbing ─────────────────────────────────────────────────────────────

type GitResult = { ok: true; stdout: string } | { ok: false; error: string };

async function git(cwd: string, args: string[], timeoutMs: number): Promise<GitResult> {
  try {
    const { stdout } = await execFileAsync('git', args, {
      cwd,
      encoding: 'utf8',
      timeout: timeoutMs,
      maxBuffer: 8 * 1024 * 1024,
      // No environment variables the attacker controls; keep the essentials.
      env: { ...process.env, GIT_PAGER: 'cat', PAGER: 'cat', LC_ALL: 'C.UTF-8' },
    });
    return { ok: true, stdout };
  } catch (err) {
    const e = err as { code?: unknown; message?: string; stdout?: string };
    const why = typeof e.code === 'number' ? `git exited with code ${e.code}` : (e.message ?? 'git failed');
    return { ok: false, error: why.split('\n')[0] ?? why };
  }
}

/** The enclosing git repository, or null when there is none. */
export async function gitRepoRoot(cwd: string): Promise<string | null> {
  const r = await git(cwd, ['rev-parse', '--show-toplevel'], 5_000);
  return r.ok ? r.stdout.trim() : null;
}

/** True when the repository is a shallow clone (history is missing). */
export async function isShallowClone(cwd: string): Promise<boolean> {
  // --is-shallow-repository is the supported spelling; --is-shallow-clone
  // is a newer alias that older gits echo back verbatim.
  const r = await git(cwd, ['rev-parse', '--is-shallow-repository'], 5_000);
  return r.ok && r.stdout.trim() === 'true';
}

// ── The introducing commit ───────────────────────────────────────────────────

export type OriginCommit = {
  sha:     string;
  author:  string;
  email:   string;
  date:    string;  // ISO 8601 from git (%aI)
  subject: string; // sanitised
  bot:     boolean;
};

export type OriginHit =
  | { status: 'found';     commit: OriginCommit; method: 'log-s' | 'blame' }
  | { status: 'not-found'; reason: string }
  | { status: 'error';     reason: string };

const FIELD_SEP = '\u001f';
const LOG_FORMAT = ['%H', '%an', '%ae', '%aI', '%s'].join(FIELD_SEP);

function parseLogLine(line: string, method: 'log-s' | 'blame'): OriginHit | null {
  const [sha, author, email, date, subject] = line.split(FIELD_SEP);
  if (!sha || author === undefined || email === undefined || date === undefined || subject === undefined) return null;
  const cleanAuthor = sanitizeGitText(author);
  const cleanSubject = sanitizeGitText(subject);
  return {
    status: 'found',
    method,
    commit: {
      sha: /^[0-9a-f]{7,40}$/i.test(sha) ? sha : '',
      author: cleanAuthor,
      email: sanitizeGitText(email),
      date,
      subject: cleanSubject,
      bot: isBotAuthor(cleanAuthor, email),
    },
  };
}

/**
 * Find the commit that introduced a finding.
 *
 * First `git log -S` (pickaxe) with the exact quoted span: the oldest commit
 * where the span's occurrence count changed is the introducing commit.
 * When pickaxe finds nothing (the span predates history, or the file was
 * moved), fall back to `git blame -L` on the finding's line.
 */
export async function findOriginCommit(
  repoRoot: string,
  relFile: string,
  line:    number,
  span:    string,
  timeoutMs = ORIGIN_TIMEOUT_MS,
): Promise<OriginHit> {
  if (span.length === 0) return { status: 'not-found', reason: 'empty span' };

  const log = await git(
    repoRoot,
    ['log', '--no-color', '--no-decorate', `--format=${LOG_FORMAT}`, '--reverse', '-S', span, '--', relFile],
    timeoutMs,
  );
  if (log.ok) {
    const first = log.stdout.split('\n').map((l) => l.trim()).filter(Boolean)[0];
    if (first) {
      const hit = parseLogLine(first, 'log-s');
      if (hit) return hit;
    }
  } else if (!/does not have any commits|bad object|unknown revision/i.test(log.error)) {
    // A genuine failure (timeout, lock, disk): report it, do not silently
    // fall through to blame.
    return { status: 'error', reason: log.error };
  }

  // Fallback: blame the line the finding sits on.
  const blame = await git(
    repoRoot,
    ['blame', '--porcelain', '-L', `${line},${line}`, '--', relFile],
    timeoutMs,
  );
  if (!blame.ok) return { status: 'not-found', reason: 'no commit introduced this span' };
  const header = blame.stdout.split('\n')[0] ?? '';
  const sha = header.split(' ')[0] ?? '';
  if (!/^[0-9a-f]{7,40}$/i.test(sha)) return { status: 'not-found', reason: 'blame produced no commit' };

  const show = await git(repoRoot, ['show', '-s', '--no-color', `--format=${LOG_FORMAT}`, sha], timeoutMs);
  if (!show.ok) return { status: 'error', reason: show.error };
  const parsed = parseLogLine((show.stdout.split('\n').map((l) => l.trim()).filter(Boolean)[0]) ?? '', 'blame');
  return parsed ?? { status: 'not-found', reason: 'could not read the commit' };
}

// ── Timeline grouping ────────────────────────────────────────────────────────

/** One threat on the timeline, as it is reported. */
export const TimelineThreatSchema = z.object({
  ruleId:   z.string(),
  severity: z.string(),
  file:     z.string(),
  line:     z.number().int().nonnegative(),
  title:    z.string().optional(),
  span:     z.string(),
  origin:   z.enum(['log-s', 'blame', 'not-found', 'error']),
  reason:   z.string().optional(),
});
export type TimelineThreat = z.infer<typeof TimelineThreatSchema>;

/** One commit group on the timeline. */
export const TimelineCommitSchema = z.object({
  sha:      z.string(),
  author:   z.string(),
  email:    z.string(),
  bot:      z.boolean(),
  date:     z.string(),
  subject:  z.string(),
  method:   z.enum(['log-s', 'blame']),
  threats:  z.array(TimelineThreatSchema),
});
export type TimelineCommit = z.infer<typeof TimelineCommitSchema>;

export const OriginReportSchema = z.object({
  tool:         z.literal('exorcist-origin'),
  target:       z.string(),
  repoRoot:     z.string(),
  shallowClone: z.boolean(),
  commits:      z.array(TimelineCommitSchema),
  unknown:      z.array(TimelineThreatSchema),
  filesScanned: z.number().int().nonnegative(),
  findingsTotal: z.number().int().nonnegative(),
});
export type OriginReport = z.infer<typeof OriginReportSchema>;

/** A short sha for display. */
export const shortSha = (sha: string): string => sha.slice(0, 7);

/** Sort commits oldest first; `before` sorts as a plain string compare of ISO dates. */
export function sortCommitsByDate(commits: TimelineCommit[]): TimelineCommit[] {
  return [...commits].sort((a, b) => a.date.localeCompare(b.date) || a.sha.localeCompare(b.sha));
}

