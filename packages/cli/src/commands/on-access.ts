import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { EventLog, macOsAuth, sanitizeReason, cleanText } from '@exorcist-98/shield';
import type { OsAuth } from '@exorcist-98/shield';
import { addAllowedRead, decideRead, loadDefinitions, readAllowedReads, realPath, sha256File, shownName } from '@exorcist-98/core';
import type { VirusDefinition } from '@exorcist-98/core';
import { findDefinitionsDir, parse, stateDir } from '../util.js';
import type { Io } from '../util.js';

export const ON_ACCESS_HELP = `Usage: exorcist on-access   (Kiro hook helper)

Reads a Kiro PreToolUse hook event from stdin and decides whether the agent
may read the file the tool names. Exit code 2 blocks the read and the reason
is written to stderr. Used by the on-access hook written by "exorcist init";
run it yourself only to try it out.

Exit codes: 0 allow the read, 2 block it. Anything it cannot read or
understand is allowed: the hook must never stop the agent from working.
`;

export const ALLOW_READ_HELP = `Usage: exorcist allow-read <file>

Allow one file for on-access scanning: its real path and current SHA-256 are
recorded, and the next read of exactly these bytes at that path passes
without a scan. Edit the file and it is checked again.

The list is kept outside the project, per user:
  $EXORCIST_DIR/allowed-reads/<project id>.json  (default ~/.exorcist/...)
A list inside the project folder is never used: the project could plant it.

Only a person can allow a file. The command runs only in an interactive
terminal. On a Mac with Touch ID or a login password it then asks the system
(LocalAuthentication), which no other program can answer; without that it uses
a native dialog you click (Deny is the default), which an agent's shell tool
cannot answer. Elsewhere it shows a
random code to type back: that stops ordinary non-interactive agent tools, but
an agent that fully drives a terminal could still read it.
`;

/** The terminal allow-read talks to. Production uses the process's own (see processTerminal). */
export type DialogAnswer = 'allow' | 'deny' | 'unavailable';

export type Terminal = {
  /** True only when both stdin and stdout are a TTY. */
  interactive: boolean;
  /** Show `prompt` on the terminal and read one line typed there. */
  ask: (prompt: string) => Promise<string>;
  /**
   * Ask through a channel an agent's shell tool cannot answer: a native OS
   * dialog the person has to click (macOS). 'unavailable' falls back to a
   * typed code.
   */
  dialog?: (message: string) => Promise<DialogAnswer>;
  /** A fresh random confirmation code (injectable for tests). */
  nonce?: () => string;
  /** The clock for code expiry (injectable for tests). Default: the system clock. */
  now?: () => Date;
  /**
   * The operating system's own verification (Touch ID or login password).
   * Tried before `dialog`. Default: macOsAuth(), which is never available
   * under VITEST or CI. Injectable for tests.
   */
  osAuth?: OsAuth;
};

/** Dialog text: no control, hidden or direction characters, bounded. Passed as an argument, never as script source. */
export function dialogText(s: string): string {
  return s.replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, ' ').slice(0, 600);
}

/** The script is fixed: the message arrives as argv, so no file name can change it. */
const DIALOG_SCRIPT = [
  'on run argv',
  '  display dialog (item 1 of argv) with title "Exorcist 98" buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny" with icon caution giving up after 120',
  'end run',
];

/**
 * A native macOS dialog, answered by a click (Deny by default, gives up after
 * two minutes). On macOS any failure counts as Deny, never as "no dialog": a
 * crafted file name must not be able to push allow-read onto the weaker
 * typed code.
 */
export async function macDialog(message: string): Promise<DialogAnswer> {
  if (process.platform !== 'darwin') return 'unavailable';
  const args = DIALOG_SCRIPT.flatMap((line) => ['-e', line]);
  return new Promise((done) => {
    execFile('/usr/bin/osascript', [...args, dialogText(message)], { timeout: 130_000 }, (err, stdout) => {
      if (err) { done('deny'); return; }
      const out = String(stdout);
      done(out.includes('button returned:Allow') && !out.includes('gave up:true') ? 'allow' : 'deny');
    });
  });
}

export const processTerminal = (): Terminal => ({
  interactive: process.stdin.isTTY === true && process.stdout.isTTY === true,
  ask: (prompt) => new Promise((done) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl.question(prompt, (answer) => { rl.close(); done(answer); });
  }),
  dialog: macDialog,
  nonce: () => randomBytes(4).toString('hex').slice(0, 6),
});

/**
 * The typed fallback: a random code shown once, never derived from the file,
 * so it cannot be computed ahead of time.
 */
export type ApprovalCode = { code: string; issuedAt: number }; // issuedAt: epoch ms
export type CodeVerdict = 'ok' | 'mismatch' | 'expired' | 'used';

/** How long a typed code stays valid (AC-25). A literal on purpose: a policy file in the state folder is not trusted. */
export const CODE_TTL_MS = 15 * 60 * 1000;

/**
 * Pure check of a typed answer against an issued code. A wrong answer is
 * always 'mismatch' (it never reveals whether the code was used or expired).
 * A right answer is 'used' once accepted before, 'expired' once more than
 * `ttlMs` have passed since it was issued, otherwise 'ok'.
 */
export function checkCode(answer: string, ticket: ApprovalCode, nowMs: number, usedAlready: boolean, ttlMs: number = CODE_TTL_MS): CodeVerdict {
  if (ticket.code.length < 6 || answer.trim().toLowerCase() !== ticket.code.toLowerCase()) return 'mismatch';
  if (usedAlready) return 'used';
  if (nowMs - ticket.issuedAt > ttlMs) return 'expired';
  return 'ok';
}

/**
 * Where a CLI-side approval outcome is recorded (AC-29): the state folder the
 * Shield writes to, and what was being approved. `subject` is a fixed command
 * name; `detail` is a short label such as a session key (never a file's
 * content and never the confirmation code).
 */
export type ApprovalAudit = { dir: string; subject: 'approve session' | 'allow-read' | 'guard-mcp-write'; detail?: string };
export type ApprovalOutcome = 'accepted' | 'declined' | 'expired' | 'used';
const OUTCOME_WHY: Record<ApprovalOutcome, string> = {
  accepted: 'The person approved it in their own terminal or system prompt.',
  declined: 'The person declined, or the confirmation did not match. Nothing was allowed.',
  expired: 'The confirmation code was typed after it expired. Nothing was allowed.',
  used: 'The confirmation code had already been used. Nothing was allowed.',
};
/**
 * Best-effort: append exactly one chained event for an approval outcome.
 * Same contract as EventLog.write: it never throws and never blocks the
 * approval. No file text, no code, no reason text is written.
 */
export function recordApproval(audit: ApprovalAudit | undefined, outcome: ApprovalOutcome, now?: () => Date): boolean {
  if (!audit) return false;
  try {
    const log = new EventLog(audit.dir, { server: 'exorcist-cli', ...(now ? { now } : {}) });
    const detail = audit.detail ? ` (${cleanText(audit.detail, 60)})` : '';
    return log.write({
      kind: 'call',
      tool: audit.subject,
      decision: outcome === 'accepted' ? 'allowed' : 'blocked',
      ruleId: audit.subject === 'approve session' ? 'EX-027' : 'SHIELD',
      by: 'user',
      why: `${OUTCOME_WHY[outcome]}${detail}`,
    });
  } catch {
    return false;
  }
}
/** The event's `cwd`, so the state folder is the project the agent works in, not the hook's own cwd. */
function eventCwd(stdin: string): string {
  try {
    const parsed = JSON.parse(stdin) as { cwd?: unknown };
    if (typeof parsed?.cwd === 'string' && parsed.cwd) return parsed.cwd;
  } catch { /* not JSON: fall back to the process cwd */ }
  return process.cwd();
}

/**
 * The on-access hook helper. Fail-open everywhere (REQ-01.6): no definitions,
 * an unreadable state folder or a broken event all allow the read.
 */
export async function onAccessCommand(stdin: string, io: Io): Promise<number> {
  const cwd = eventCwd(stdin);
  let defs: VirusDefinition[] = [];
  const defsDir = findDefinitionsDir();
  if (defsDir) {
    try {
      defs = await loadDefinitions(defsDir);
    } catch (err) {
      io.err(`Exorcist 98 on-access: the virus definitions could not be loaded, so the read was allowed. ${String(err).split('\n')[0]}`);
      return 0;
    }
  } else {
    io.err('Exorcist 98 on-access: no virus definitions were found, so the read was allowed.');
    return 0;
  }

  let allowed: ReadonlySet<string> = new Set();
  try {
    allowed = readAllowedReads(cwd);
  } catch {
    allowed = new Set();
  }

  const decision = decideRead(stdin, defs, { cwd, allowed });
  if (decision.message) io.err(decision.message);
  return decision.exitCode;
}

/**
 * Ask through the strongest channel that exists, without a typed code.
 * 1. The operating system's verification (Touch ID or login password): another
 *    program cannot click it. `reason` is the short prompt text.
 * 2. A native dialog the person clicks (can be clicked by other software).
 * 'unavailable' means neither exists. Once the OS prompt has been shown, a
 * deny, an error or a timeout is a 'deny': it never falls back to a weaker channel.
 */
export async function askOwner(term: Terminal, dialogMessage: string, reason: string, audit?: ApprovalAudit): Promise<DialogAnswer> {
  const auth = term.osAuth ?? macOsAuth();
  let available = false;
  try { available = await auth.available(); } catch { available = false; }
  if (available) {
    let verdict: string = 'error';
    try { verdict = await auth.verify(sanitizeReason(reason)); } catch { verdict = 'error'; }
    recordApproval(audit, verdict === 'ok' ? 'accepted' : 'declined', term.now);
    return verdict === 'ok' ? 'allow' : 'deny';
  }
  const answer = term.dialog ? await term.dialog(dialogMessage) : 'unavailable';
  if (answer !== 'unavailable') recordApproval(audit, answer === 'allow' ? 'accepted' : 'declined', term.now);
  return answer;
}
/**
 * Ask the person at the keyboard, through channels an agent's shell tool
 * cannot answer: first the OS verification (Touch ID or login password), then a
 * native dialog they click; without either, a random code shown once and typed
 * back. The caller has already checked `interactive`. `reason` is the short
 * text of the OS prompt and says what is being approved.
 * Prints why on refusal. Used by allow-read and approve session.
 */
export async function personConfirms(term: Terminal, io: Io, dialogMessage: string, reason: string = dialogMessage, audit?: ApprovalAudit): Promise<boolean> {
  const viaOwner = await askOwner(term, dialogMessage, reason, audit);
  if (viaOwner === 'deny') { io.err('Denied in the verification prompt. Nothing was allowed.'); return false; }
  if (viaOwner === 'unavailable') {
    const now = term.now ?? (() => new Date());
    const ticket: ApprovalCode = { code: (term.nonce ?? (() => randomBytes(4).toString('hex').slice(0, 6)))(), issuedAt: now().getTime() };
    // The code lives only in this process: it is never written to the state folder,
    // so there is nothing for a later call to reuse. `used` makes one-shot structural.
    let used = false;
    io.out(`Confirmation code: ${ticket.code}`);
    const answer = await term.ask('Type the confirmation code above to allow it: ');
    const verdict = checkCode(answer, ticket, now().getTime(), used);
    if (verdict === 'ok') used = true;
    recordApproval(audit, verdict === 'ok' ? 'accepted' : verdict === 'mismatch' ? 'declined' : verdict, term.now);
    if (verdict === 'expired') { io.err('That code has expired (it is valid for 15 minutes). Nothing was allowed. Run the command again.'); return false; }
    if (verdict === 'used') { io.err('That code was already used. Nothing was allowed.'); return false; }
    if (verdict !== 'ok') { io.err('That does not match. Nothing was allowed.'); return false; }
  }
  return true;
}
export async function allowReadCommand(argv: string[], io: Io, term: Terminal = processTerminal()): Promise<number> {
  const p = parse(argv, { help: { type: 'boolean', short: 'h' } });
  if (!p.ok) { io.err(`${p.error}\n\n${ALLOW_READ_HELP}`); return 2; }
  if (p.values['help']) { io.out(ALLOW_READ_HELP); return 0; }
  const target = p.positionals[0];
  if (!target || p.positionals.length > 1) { io.err(`Give exactly one file to allow.\n\n${ALLOW_READ_HELP}`); return 2; }
  // Before anything else: an agent's shell tool or a script never gets here.
  if (!term.interactive) {
    io.err('exorcist allow-read only runs in an interactive terminal: the user must review the file and run it themselves. Nothing was allowed.');
    return 1;
  }
  const file = resolve(target);
  if (!existsSync(file) || !statSync(file).isFile()) { io.err(`Not a readable file: ${shownName(target)}`); return 1; }
  const hash = sha256File(file);
  if (hash === null) { io.err(`Cannot read ${shownName(target)}.`); return 1; }

  const shown = shownName(realPath(file));
  io.out(`File:    ${shown}`);
  io.out(`SHA-256: ${hash}`);
  io.out('Allow only a file you have reviewed: Exorcist 98 will let your agent read exactly these bytes at this path.');
  if (!(await personConfirms(term, io, `Allow your AI agent to read this file?\n\n${shown}\nSHA-256 ${hash.slice(0, 12)}...\n\nOnly allow a file you have reviewed.`, `Allow your AI agent to read ${shown} (SHA-256 ${hash.slice(0, 12)}...)`, { dir: stateDir(), subject: 'allow-read' }))) return 1;

  // Only the bytes the user confirmed: if the file changed meanwhile, nothing is written.
  const result = addAllowedRead(process.cwd(), file, process.env, hash);
  if (!result.ok) { io.err(result.error); return 1; }
  io.out(`Allowed. Recorded in ${result.store}`);
  io.out('The next read of exactly these bytes at this path passes; any edit checks the file again.');
  return 0;
}
