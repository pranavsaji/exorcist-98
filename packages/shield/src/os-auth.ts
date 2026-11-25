/**
 * Release of a held call by the operating system (EX-027, m6-os-release).
 * This file holds the types and the pure helpers. The reason text is untrusted
 * (server and tool names come from the server), so it is always cleaned here.
 */
import { describeFact } from './session.js';
import type { Fact } from './session.js';

export type OsVerdict = 'ok' | 'denied' | 'error' | 'timeout';

/** Never throws across the package boundary: failures are verdicts. */
export interface OsAuth {
  available(): Promise<boolean>;
  verify(reason: string): Promise<OsVerdict>;
}

export const REASON_MAX_CHARS = 200;

/**
 * Plain-language cause why the real OS call must not run, or null when it may.
 * Checked before any spawn, on every call.
 */
export function blockedReason(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string | null {
  if (platform !== 'darwin') return 'this is not a Mac, so the system prompt (Touch ID or login password) is not available';
  if (env['VITEST']) return 'this is a test run, so no system prompt is shown';
  if (env['CI']) return 'this is a CI run, so no system prompt is shown';
  if (env['EXORCIST_OS_AUTH'] === 'off') return 'OS verification was turned off with EXORCIST_OS_AUTH=off';
  return null;
}

// Control (C0, DEL, C1), zero-width and format marks U+200B-U+200F, bidi U+202A-U+202E,
// U+2060-U+206F (word joiner, invisible operators, isolates), BOM, and tag characters U+E0000-U+E007F.
const REMOVED = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u{e0000}-\u{e007f}]/gu;

/** Strip hidden characters, collapse whitespace, cap at 200 characters (a cut ends in an ellipsis). Idempotent. */
export function sanitizeReason(text: string): string {
  // Whitespace first, so a newline or tab becomes a space instead of being deleted.
  const cleaned = text
    .replace(/\s+/gu, ' ')
    .replace(REMOVED, '')
    .replace(/\s+/gu, ' ')
    .trim();
  if (cleaned.length <= REASON_MAX_CHARS) return cleaned;
  let cut = cleaned.slice(0, REASON_MAX_CHARS - 1);
  const last = cut.charCodeAt(cut.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) cut = cut.slice(0, -1); // do not split a surrogate pair
  return `${cut.trimEnd()}…`;
}

/** The text of the OS prompt: names the tool, the server and the facts that armed the guard. */
export function buildReason(server: string, tool: string, facts: readonly Fact[], hosts: readonly string[] = []): string {
  const what = facts.map((f) => describeFact(f)).join('; ');
  const quote = (s: string): string => `"${s.replace(/"/gu, "'")}"`;
  const to = hosts.length === 0 ? '' : ` (also to ${hosts.slice(0, 3).map((h) => quote(h.slice(0, 40))).join(', ')}${hosts.length > 3 ? ' and more' : ''}, not on the allowed list)`;
  const head = `Exorcist 98 holds ${quote(tool)} on ${quote(server)}${to}`;
  const body = what === '' ? '' : `: ${what}`;
  return sanitizeReason(`${head}${body}. Verify to release this one call.`);
}

// ---------------------------------------------------------------------------
// The real implementation: /usr/bin/osascript with a fixed JavaScript-for-Automation script.
// The scripts are constants. The reason never enters the script source or the argument list;
// it travels in the environment variable EXORCIST_REASON and is read inside the script.
// ---------------------------------------------------------------------------

/** One word on stdout: yes or no. (JXA prints return values to stderr, so write to stdout directly.) */
export const AVAILABLE_SCRIPT = [
  "ObjC.import('LocalAuthentication');",
  "ObjC.import('Foundation');",
  "function out(s) { $.NSFileHandle.fileHandleWithStandardOutput.writeData($(s + '\\n').dataUsingEncoding($.NSUTF8StringEncoding)); }",
  'const ctx = $.LAContext.alloc.init;',
  'const err = Ref();',
  "out(ctx.canEvaluatePolicyError(2, err) ? 'yes' : 'no');",
].join('\n');

/** One word on stdout: ok, denied or error. Policy 2 is LAPolicyDeviceOwnerAuthentication. */
export const VERIFY_SCRIPT = [
  "ObjC.import('LocalAuthentication');",
  "ObjC.import('Foundation');",
  "function out(s) { $.NSFileHandle.fileHandleWithStandardOutput.writeData($(s + '\\n').dataUsingEncoding($.NSUTF8StringEncoding)); }",
  "const raw = $.NSProcessInfo.processInfo.environment.objectForKey('EXORCIST_REASON');",
  "const reason = ObjC.unwrap(raw) || 'Release one held call';",
  'let result = null;',
  'const ctx = $.LAContext.alloc.init;',
  'const err = Ref();',
  "if (!ctx.canEvaluatePolicyError(2, err)) {",
  "  out('error');",
  '} else {',
  '  ctx.evaluatePolicyLocalizedReasonReply(2, $(reason), function (success, error) {',
  "    if (success) { result = 'ok'; return; }",
  '    let code = 0;',
  '    try { code = error.code; } catch (e) { code = 0; }',
  "    result = [-1, -2, -4, -9].indexOf(code) >= 0 ? 'denied' : 'error';",
  '  });',
  '  while (result === null) {',
  '    $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.1));',
  '  }',
  '  out(result);',
  '}',
].join('\n');

export type Spawner = typeof import('node:child_process').spawn;

export interface MacOsAuthOptions {
  spawn?: Spawner;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  timeoutMs?: number;
}

export const OS_PROMPT_TIMEOUT_MS = 60_000;
const OSASCRIPT = '/usr/bin/osascript';
const STDOUT_CAP = 256;

type RunResult = { kind: 'out'; text: string } | { kind: 'timeout' } | { kind: 'fail' };

/** Real OS verification. Never throws and never spawns in a blocked environment. */
export function macOsAuth(o: MacOsAuthOptions = {}): OsAuth {
  const timeoutMs = o.timeoutMs ?? OS_PROMPT_TIMEOUT_MS;
  const blocked = (): string | null => blockedReason(o.env ?? process.env, o.platform ?? process.platform);

  const run = async (script: string, reason: string | null): Promise<RunResult> => {
    // Resolve the spawner lazily so a blocked environment never touches child_process.
    let spawnFn: Spawner;
    try {
      spawnFn = o.spawn ?? (await import('node:child_process')).spawn;
    } catch {
      return { kind: 'fail' };
    }
    return new Promise<RunResult>((resolve) => {
      let settled = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let child: ReturnType<Spawner> | undefined;
      const finish = (r: RunResult): void => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        resolve(r);
      };
      try {
        const base = o.env ?? process.env;
        const childEnv: Record<string, string> = {
          PATH: '/usr/bin:/bin',
          HOME: base['HOME'] ?? '',
        };
        if (reason !== null) childEnv['EXORCIST_REASON'] = reason;
        const proc = spawnFn(OSASCRIPT, ['-l', 'JavaScript', '-e', script], {
          env: childEnv as NodeJS.ProcessEnv,
          stdio: ['ignore', 'pipe', 'ignore'],
        });
        child = proc;
        let text = '';
        proc.stdout?.on('data', (chunk: Buffer | string) => {
          if (text.length < STDOUT_CAP) text += chunk.toString();
        });
        proc.on('error', () => finish({ kind: 'fail' }));
        proc.on('close', (code: number | null) => {
          finish(code === 0 ? { kind: 'out', text: text.slice(0, STDOUT_CAP).trim() } : { kind: 'fail' });
        });
        timer = setTimeout(() => {
          try {
            proc.kill('SIGKILL');
          } catch {
            // already gone
          }
          finish({ kind: 'timeout' });
        }, timeoutMs);
      } catch {
        try {
          child?.kill('SIGKILL');
        } catch {
          // ignore
        }
        finish({ kind: 'fail' });
      }
    });
  };

  return {
    async available(): Promise<boolean> {
      if (blocked() !== null) return false;
      try {
        const r = await run(AVAILABLE_SCRIPT, null);
        return r.kind === 'out' && r.text === 'yes';
      } catch {
        return false;
      }
    },
    async verify(reason: string): Promise<OsVerdict> {
      if (blocked() !== null) return 'error';
      try {
        const r = await run(VERIFY_SCRIPT, reason);
        if (r.kind === 'timeout') return 'timeout';
        if (r.kind === 'fail') return 'error';
        if (r.text === 'ok') return 'ok';
        if (r.text === 'denied') return 'denied';
        return 'error';
      } catch {
        return 'error';
      }
    },
  };
}

export type Release = { mode: 'os' | 'terminal'; note?: string };

/** Choose the release mode once. `terminal` never asks the OS; otherwise fall back with a plain note. */
export async function resolveRelease(policyValue: 'os' | 'terminal' | undefined, osAuth: OsAuth): Promise<Release> {
  if (policyValue === 'terminal') return { mode: 'terminal' };
  let ok = false;
  let threw = false;
  try {
    ok = await osAuth.available();
  } catch {
    threw = true;
  }
  if (ok) return { mode: 'os' };
  const why = threw
    ? 'the check for the system prompt failed'
    : (blockedReason() ?? 'macOS LocalAuthentication is not available here');
  return { mode: 'terminal', note: why };
}
