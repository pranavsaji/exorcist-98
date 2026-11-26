/**
 * Kiro session evidence extractor (m13-kiro-evidence).
 *
 * RESEARCH NOTES: the real Kiro session format, observed in Kiro IDE on
 * 27 sessions of this project (workspace folders `exorcist-98` and
 * `exorcist-98-wt-*`) holding about 19,000 event lines. Only field names and
 * event types are recorded here, never conversation contents.
 *
 * Layout under ~/.kiro/sessions/
 *   <workspace-hash>/                 16-hex folder. NOT one workspace: sessions
 *                                     of different workspaces share a hash
 *                                     folder, so the workspace must be read per
 *                                     session (see below).
 *   <workspace-hash>/.index/index.json   a cache, not a source of truth:
 *                                     { schemaVersion, walkedAtMs, dirMtimeMs,
 *                                       dirNamesHash, stamps, entries[] }.
 *                                     entries[] has id, title, agentMode,
 *                                     createdAt, lastModifiedAt, workspacePaths[],
 *                                     rootPaths[], status, workflowsEnabled, _meta.
 *                                     Also holds .lock. Prefer walking the
 *                                     session folders and reading session.json.
 *   <workspace-hash>/sess_<uuid>/     one session folder (id is `sess_<uuid>`).
 *     session.json
 *     messages.jsonl
 *     tool-outputs/                   only in some sessions (9 of 27)
 *     snapshots/                      file checkpoints (only some sessions); never export
 *     sub-executions/<uuid>.jsonl     sub-agent transcripts (only some sessions);
 *                                     same envelope as messages.jsonl
 *
 * session.json (every session): schemaVersion, dataModelVersion, id, title,
 *   agentMode ('vibe' | 'spec' | 'bug-fix'), workspacePaths[] and rootPaths[]
 *   (ABSOLUTE paths, contain the home folder), createdAt, lastModifiedAt (ISO
 *   strings), semanticReviewEnabled, disableAutoCompaction, ftaEnabled,
 *   workflowsEnabled, specPlanEnabled, specWorkflow, specSkipClarificationEnabled,
 *   memoryConfig {mode, reflection}, memoryConfigSource, _meta.
 *   Optional (absent on older sessions): modelId, contextSnapshotModelDisplay
 *   {modelId, display}, status ('idle' | 'failed' | 'in_progress'), autopilot
 *   (boolean), approveForMe (boolean), workflowLaunch, memoryToolProfile,
 *   universalBackgroundTool, description.
 *   Differences from the design's guess: the keys are `createdAt` and
 *   `lastModifiedAt` (not startTime/endTime), `modelId` (not model),
 *   `workspacePaths` is an ARRAY (not a single `workspacePath`), and
 *   autopilot, approveForMe and modelId can be missing (record them as null).
 *   The "this project" test must therefore look at the final segment of each
 *   entry of workspacePaths.
 *
 * messages.jsonl: one JSON object per line, ENVELOPE { id, timestamp, payload }.
 *   id is a string, timestamp an ISO string with milliseconds (UTC, `Z`). The
 *   event type is `payload.type`, NOT a top-level field. No malformed lines
 *   were seen, but parsing must still tolerate them (KE-6).
 *   payload.type values seen, with their other fields:
 *     user                   content, documents, images, _meta
 *     assistant              content, executionId, turnId, responseMessageId,
 *                            operationType, reasoningModelId, reasoningSignature,
 *                            summaryReasoning, _meta
 *     tool_call              toolCallId, toolName, args, title, kind, actionType,
 *                            status, filePath, originalArgs, modelToolUseId,
 *                            responseMessageId, executionId, turnId, _meta
 *     tool_result            toolCallId, content, success, status, title, kind,
 *                            actionType, operationId, filePath, images,
 *                            dispatchedArgs, durationMs, executionId, turnId, _meta
 *     ContextualHookInvoked  hookId, name, hookActionType, status, operationId,
 *                            executionId, turnId
 *     usage_summary          promptTurnSummaries[], elapsedTime, status,
 *                            requestIds[], executionId, turnId
 *     session_metadata       key, value, executionId. keys seen: creditSplit
 *                            ({main, delegated, auxiliary}), contextUsage,
 *                            displayError
 *     pending_interaction    interactionType, question, options, consentRound,
 *                            toolCallId, modelToolUseId, executionId, _meta
 *     interaction_resolved   outcome, selectedOption, consentRound, toolCallId,
 *                            modelToolUseId, executionId, _meta
 *     turn_start             boundarySource, userMessageTag, executionId, turnId
 *     turn_end               boundarySource, stopReason, executionId, turnId
 *     session_event          category ('session_pause'), context
 *     session_start          agentType, backgroundExecution, composition,
 *                            content, forcedRole, messageId, steeringDocuments
 *     steering_inclusion     documents, executionId, turnId
 *     sub_agent_start        subAgentName, subSessionId, parentExecutionId,
 *                            prompt, explanation, toolName, toolArgs
 *     sub_agent_complete     subSessionId, parentExecutionId, status, response
 *     agent_note             content
 *     tombstone              kind, effectiveFromMessageId, metadata
 *   `_meta.kiro` on tool and assistant events may hold agentMode, toolOrigin,
 *   checkpoint, classifierApproved, resources, serverName, policyDenial.
 *
 * Tool calls: exactly one `tool_call` line per toolCallId (3199 lines, 3199
 *   distinct ids) and exactly one `tool_result` per id. tool_call.status is a
 *   snapshot ('pending' | 'approved' | 'completed' | 'failed' | 'denied'), not
 *   a series of events, so count tool calls by lines, grouped by toolName.
 *   toolName `tool_call` (94 lines) is itself a tool name used for deferred
 *   tools; count it under that name.
 *
 * Credits: usage_summary.promptTurnSummaries[] items are
 *   { unit: 'credit', unitPlural: 'credits', usage: <float>, usedTools: [] }.
 *   Session credits = the sum of `usage` over all usage_summary events. The
 *   session_metadata `creditSplit` value ({main, delegated, auxiliary}) is a
 *   second, running breakdown and must not be added on top of the sum.
 *   usage_summary.status can be 'success' or 'aborted'.
 *
 * Image and binary fields to drop (KE-3): `images` on user and tool_result
 *   lines is an array of { data: <base64 string>, mimeType }. `documents` on
 *   user lines too.
 *
 * Large outputs: tool_result.content is a plain string. When it was spilled to
 *   tool-outputs/, the string carries the ABSOLUTE path
 *   `<home>/.kiro/sessions/<hash>/sess_<uuid>/tool-outputs/<toolName>-<toolUseId>.txt`
 *   (file sizes of 30 KB and more seen). Export only the (truncated) string in
 *   messages.jsonl; the path must go through redactHomePath. Never open the
 *   tool-outputs files.
 *
 * HOOKS (what Requirement 3 relies on)
 *   - A hook run is ONE `ContextualHookInvoked` line, for command hooks
 *     (hookActionType 'runCommand') and agent hooks ('askAgent') alike. The
 *     design's guess of a tool_call/tool_result pair for command hooks is WRONG:
 *     hook commands leave no tool_call. The hook's name is `name` (a short id
 *     such as the file name without .json); `hookId` is a second identifier.
 *     status was always 'completed', including for hooks that blocked.
 *   - The line does NOT carry the trigger (PreToolUse, Stop, ...) and does NOT
 *     carry the exit code or stderr. The exit code is never recorded.
 *   - A BLOCKED PreToolUse hook shows up as a `tool_result` with
 *       status: 'denied', success: false, kind of the blocked tool
 *       (e.g. 'edit' or 'read'), and `content` beginning with the sentence
 *       `Tool "<toolName>" was intercepted by PreToolUse hooks before execution.`
 *       followed by one or more <HOOK_INSTRUCTION> blocks carrying the hook's
 *       stderr text. The tool_result has NO hook name and NO exit-code field.
 *     The hook that blocked is the `ContextualHookInvoked` line directly
 *     before that tool_result (same turnId, adjacent in the file, timestamps
 *     within about 3 ms), and the matching tool_call comes earlier in the same
 *     turn. isHookBlock therefore has to look at the PREVIOUS ContextualHookInvoked
 *     line(s), not the next event, and needs a "previous hook line" argument
 *     instead of the design's `nextEvent`. When several hook lines sit
 *     directly before the result, the blocker cannot be told apart; attribute
 *     the block to the last one and document it.
 *   - Observed: 3 such blocks (2 by `on-access-scan` on read_file, 1 by
 *     `mcp-config-write-guard` on fs_write).
 *   - NOT a hook block: a `tool_result` with status 'denied' whose content
 *     starts with `Kiro blocked this action:` and whose `_meta.kiro` has
 *     `policyDenial` (capability, effect, matchedRule, resource, scope, source,
 *     triggeringResource). That is Kiro's own permission policy, not a hook.
 *     Stop hooks that fire after the turn (e.g. exorcist-gate) cannot block a
 *     tool and never produce 'denied'.
 *   - A hook that was only counted as a run is any ContextualHookInvoked line;
 *     hooks seen: runCommand 1590, askAgent 15.
 *   - Hook "exit 2" must be inferred from the 'denied' result above. Do not
 *     promise to detect other exit codes.
 */

import { z } from 'zod';
import { redactSecretText, containsSecret } from './redact-secrets.js';

/** One line of messages.jsonl: the envelope seen in real sessions. Extra fields pass through. */
export const KiroEventSchema = z
  .object({
    id: z.string(),
    timestamp: z.string(),
    payload: z.object({ type: z.string() }).passthrough(),
  })
  .passthrough();
export type KiroEvent = z.infer<typeof KiroEventSchema>;

const WT_NAME = /^exorcist-98-wt-.+$/;

/** True when the final segment of `workspacePath` is `exorcist-98` or `exorcist-98-wt-<name>`. (KE-2) */
export function isThisProjectWorkspace(workspacePath: string): boolean {
  const segments = workspacePath.split(/[\\/]+/).filter((s) => s.length > 0);
  const last = segments[segments.length - 1];
  if (last === undefined) return false;
  return last === 'exorcist-98' || WT_NAME.test(last);
}

/** Characters that end a path segment: a match followed by one of these (or by the end of the string) is the whole home path. */
const HOME_END = /[\\/\s'"`:;,)\]}>|*?<(\[{]/;

/**
 * Replace every occurrence of `home` with `~` where it is a whole path, not the prefix of a longer segment
 * (`/R` inside `/Ra` stays). An empty or root `home` changes nothing. (KE-8)
 */
export function redactHomePath(value: string, home: string): string {
  const base = home.length > 1 ? home.replace(/[\\/]+$/, '') : home;
  if (base.length === 0 || base === '/' || base === '\\') return value;
  let out = '';
  let i = 0;
  for (;;) {
    const at = value.indexOf(base, i);
    if (at === -1) return out + value.slice(i);
    const end = at + base.length;
    const next = value.charAt(end);
    out += value.slice(i, at);
    if (end >= value.length || base.endsWith('/') || base.endsWith('\\') || HOME_END.test(next)) {
      out += '~';
    } else {
      out += base;
    }
    i = end;
  }
}

// ---- Requirement 11: JWTs, AWS account IDs, emails, sign-in output (KE-48 to KE-52) ----
// Export-only: none of these go into the shared redact-secrets patterns, so scanner output,
// the haunted-repo and the benchmark numbers cannot change.

const JWT_SOURCE = 'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+';
// `arn:aws[-a-z]*:<service>:<region>:<12 digits>` (the region may be empty, as in IAM ARNs).
const ARN_ACCOUNT_SOURCE = '(arn:aws[-a-z]*:[a-z0-9-]+:[a-z0-9-]*:)(\\d{12})(?!\\d)';
// `Account` then 12 digits: JSON (`"Account": "..."`, also with escaped quotes), `Account: ...`, `| Account | ... |`.
const ACCOUNT_FIELD_SOURCE = '(?<![A-Za-z])(Account(?:Id)?(?:\\\\*")?\\s*[:=|]\\s*(?:\\\\*")?)(\\d{12})(?!\\d)';
const EMAIL_SOURCE = '[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}';

export const JWT_MARKER = '[redacted jwt]';
export const ACCOUNT_MARKER = '[redacted account]';
export const EMAIL_MARKER = '[redacted email]';
export const SIGN_IN_OMITTED = '[omitted: sign-in output]';

const EXAMPLE_DOMAINS = ['example.com', 'example.org', 'example.net', 'example.invalid'];

/** Addresses that are kept: `.invalid`, the example domains and their subdomains. `git@` SSH remotes hold no personal data. */
function keepEmail(address: string): boolean {
  const at = address.lastIndexOf('@');
  const local = address.slice(0, at);
  const domain = address.slice(at + 1).toLowerCase();
  if (local === 'git') return true;
  // `pkg@1.2.tgz`: a version, not a host.
  if (/^\d+$/.test(domain.split('.')[0] ?? '')) return true;
  if (domain.endsWith('.invalid')) return true;
  return EXAMPLE_DOMAINS.some((d) => domain === d || domain.endsWith(`.${d}`));
}

/**
 * Apply the extra export redactions to one string. `serialized` is true for a whole JSON line:
 * an email match that begins right after a backslash would swallow the escape letter of `\n`
 * or `\u003c`, so that escape is kept and the line still parses.
 */
function redactExtras(text: string, serialized: boolean): string {
  if (text.length === 0) return text;
  let out = text.replace(new RegExp(JWT_SOURCE, 'g'), JWT_MARKER);
  out = out.replace(new RegExp(ARN_ACCOUNT_SOURCE, 'g'), (_m, head: string) => `${head}${ACCOUNT_MARKER}`);
  out = out.replace(new RegExp(ACCOUNT_FIELD_SOURCE, 'gi'), (_m, head: string) => `${head}${ACCOUNT_MARKER}`);
  out = out.replace(new RegExp(EMAIL_SOURCE, 'g'), (m: string, offset: number, whole: string) => {
    if (keepEmail(m)) return m;
    if (serialized && offset > 0 && whole[offset - 1] === '\\') {
      const keep = /^u[0-9a-fA-F]{4}/.test(m) ? 5 : 1;
      return `${m.slice(0, keep)}${EMAIL_MARKER}`;
    }
    return EMAIL_MARKER;
  });
  return out;
}

// A URL from its scheme up to the first whitespace, quote, `<`, `>` or backslash-escape. The escapes
// `\u0026` and `\/` that a serialized JSON line uses inside a URL are part of it. (KE-54)
// (one or two backslashes, for a string that was escaped once or twice).
const URL_SOURCE = '[A-Za-z][A-Za-z0-9+.-]*:(?:\\\\{0,2}\\/){2}(?:[^\\s"\'<>\\\\]|\\\\{1,2}u0026|\\\\{1,2}\\/)+';
// A parameter name after `?` or `&` (also `&amp;` and `\u0026`) followed by `=`.
const SIGN_IN_PARAM = /(?:\?|&|&amp;|\\{1,2}u0026)(?:code_challenge|state|code|client_id|redirect_uri)=/i;
export const SIGN_IN_URL_MARKER = '[redacted sign-in url]';

/** True when `url` has a query string holding a sign-in parameter. */
function isSignInUrl(url: string): boolean {
  const i = url.indexOf('?');
  return i >= 0 && SIGN_IN_PARAM.test(url.slice(i));
}

/** Replace every URL whose query has `code_challenge`, `state`, `code`, `client_id` or `redirect_uri`. (KE-54) */
export function redactSignInUrls(text: string): string {
  if (!text.includes('//') && !text.includes('\\/')) return text;
  return text.replace(new RegExp(URL_SOURCE, 'g'), (m) => (isSignInUrl(m) ? SIGN_IN_URL_MARKER : m));
}

/** Redact a sign-in URL, JWT, AWS account ID or email in `text` (a plain string). (KE-48, KE-49, KE-50, KE-54) */
export function redactExportText(text: string): string {
  return redactExtras(redactSignInUrls(text), false);
}

/** Counts of the shapes the rescan adds: JWTs, AWS account IDs and sign-in URLs. Never returns the values. (KE-52, KE-56) */
export function extraSecretShapeCounts(text: string): { jwt: number; account: number; signInUrl: number } {
  const jwt = text.match(new RegExp(JWT_SOURCE, 'g'))?.length ?? 0;
  const account =
    (text.match(new RegExp(ARN_ACCOUNT_SOURCE, 'g'))?.length ?? 0) +
    (text.match(new RegExp(ACCOUNT_FIELD_SOURCE, 'gi'))?.length ?? 0);
  const signInUrl = (text.match(new RegExp(URL_SOURCE, 'g')) ?? []).filter(isSignInUrl).length;
  return { jwt, account, signInUrl };
}

function commandsOf(p: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const key of ['args', 'originalArgs', 'input']) {
    const v = p[key];
    if (typeof v === 'string') out.push(v);
    else if (typeof v === 'object' && v !== null) {
      const c = (v as Record<string, unknown>)['command'];
      if (typeof c === 'string') out.push(c);
    }
  }
  return out;
}

const HOME_OUT_FILE = /(?:~|\$\{?HOME\}?|\/Users\/[^/\s'"]+|\/home\/[^/\s'"]+|\/root)\/\.[^\s/'"]*\.out(?![A-Za-z0-9_])/;

/** True for a command that signs in: contains `aws ` or `login`, or reads a `~/.*.out` file. (KE-51) */
export function isSignInCommand(command: string): boolean {
  return /\baws /i.test(command) || /login/i.test(command) || HOME_OUT_FILE.test(command);
}

/**
 * Replace the output of every sign-in `execute_bash` call with `[omitted: sign-in output]`.
 * Each call has exactly one `tool_call` and one `tool_result`; they are paired by `toolCallId`.
 * Spilled `tool-outputs/` files are never opened or copied by the exporter, so only the
 * `content` string in messages.jsonl needs this. (KE-51)
 */
export function omitSignInOutputs(events: KiroEvent[]): KiroEvent[] {
  const ids = new Set<string>();
  for (const e of events) {
    const p = payloadOf(e);
    if (p['type'] === 'tool_call' && p['toolName'] === 'execute_bash' && typeof p['toolCallId'] === 'string'
      && commandsOf(p).some(isSignInCommand)) ids.add(p['toolCallId']);
  }
  if (ids.size === 0) return events;
  return events.map((e) => {
    const p = payloadOf(e);
    if (p['type'] !== 'tool_result' || typeof p['toolCallId'] !== 'string' || !ids.has(p['toolCallId'])) return e;
    const next = { ...p, type: 'tool_result', content: SIGN_IN_OMITTED } as KiroEvent['payload'];
    if ('output' in next) (next as Record<string, unknown>)['output'] = SIGN_IN_OMITTED;
    return { ...e, payload: next };
  });
}

export const OUTSIDE_WORKSPACE_OMITTED = '[omitted: file outside the workspace]';
const READ_TOOLS = new Set(['read_file', 'fs_read']);
const PATH_KEYS = new Set(['path', 'filePath', 'file_path']);

/** Every file path a read call names: its `filePath`, and path keys in `args`, `originalArgs`, `input` (nested, `paths[]`, `operations[]`). */
function readPathsOf(p: Record<string, unknown>): string[] {
  const out: string[] = [];
  const walk = (v: unknown, depth: number): void => {
    if (depth > 4) return;
    if (typeof v === 'string') {
      if (depth === 0) {
        try { walk(JSON.parse(v) as unknown, 1); } catch { /* not JSON */ }
      }
    } else if (Array.isArray(v)) {
      for (const x of v) walk(x, depth + 1);
    } else if (typeof v === 'object' && v !== null) {
      for (const [k, x] of Object.entries(v)) {
        if (PATH_KEYS.has(k) && typeof x === 'string') out.push(x);
        else if (k === 'paths' && Array.isArray(x)) for (const s of x) { if (typeof s === 'string') out.push(s); }
        else walk(x, depth + 1);
      }
    }
  };
  if (typeof p['filePath'] === 'string') out.push(p['filePath']);
  for (const key of ['args', 'originalArgs', 'input']) walk(p[key], 0);
  return out;
}

function cleanAbs(path: string): string {
  const parts: string[] = [];
  for (const seg of path.split(/[\\/]+/)) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  return `/${parts.join('/')}`;
}

/** Expand `~`, `$HOME` and `${HOME}` to `home`; anything else is returned unchanged. */
function expandHome(path: string, home: string): string {
  const m = /^(?:~|\$HOME|\$\{HOME\})(?=[\\/]|$)/.exec(path);
  return m ? home + path.slice(m[0].length) : path;
}

/** True when `path` is under `home` and not inside any of `workspacePaths`. A relative path is inside the workspace. */
function isOutsideWorkspaceHomePath(path: string, workspacePaths: string[], home: string): boolean {
  const expanded = expandHome(path, home);
  if (!/^[\\/]/.test(expanded)) return false;
  const abs = cleanAbs(expanded);
  const homeAbs = cleanAbs(home);
  if (homeAbs === '/' || !abs.startsWith(`${homeAbs}/`)) return false;
  return !workspacePaths.some((w) => {
    const root = cleanAbs(w);
    return abs === root || abs.startsWith(`${root}/`);
  });
}

/**
 * Replace the result of every `read_file` or `fs_read` call for a file under the home folder but
 * outside the session's `workspacePaths` with `[omitted: file outside the workspace]`. Call and
 * result are paired by `toolCallId`, as in `omitSignInOutputs`. Relative paths count as inside. (KE-55)
 */
export function omitOutsideWorkspaceReads(events: KiroEvent[], workspacePaths: string[], home: string): KiroEvent[] {
  if (home.length === 0) return events;
  const ids = new Set<string>();
  for (const e of events) {
    const p = payloadOf(e);
    if (p['type'] === 'tool_call' && typeof p['toolName'] === 'string' && READ_TOOLS.has(p['toolName'])
      && typeof p['toolCallId'] === 'string'
      && readPathsOf(p).some((x) => isOutsideWorkspaceHomePath(x, workspacePaths, home))) ids.add(p['toolCallId']);
  }
  if (ids.size === 0) return events;
  return events.map((e) => {
    const p = payloadOf(e);
    if (p['type'] !== 'tool_result' || typeof p['toolCallId'] !== 'string' || !ids.has(p['toolCallId'])) return e;
    const next = { ...p, type: 'tool_result', content: OUTSIDE_WORKSPACE_OMITTED } as KiroEvent['payload'];
    if ('output' in next) (next as Record<string, unknown>)['output'] = OUTSIDE_WORKSPACE_OMITTED;
    return { ...e, payload: next };
  });
}

function redactNode(value: unknown): unknown {
  if (typeof value === 'string') return redactExtras(redactSecretText(redactSignInUrls(value)), false);
  if (Array.isArray(value)) return value.map(redactNode);
  if (typeof value === 'object' && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactNode(v);
    return out;
  }
  return value;
}

/** Run every string value in a JSON-shaped value through `redact-secrets`. Keys are kept. (KE-9) */
export function redactSecretsDeep<T>(value: T): T {
  return redactNode(value) as T;
}

export const TRUNCATION_SUFFIX = '…(truncated)';
const DROP_KEYS = new Set(['images', 'documents', 'image', 'imageData']);
/** Model signature fields, dropped at any depth by exact key name only. (KE-58) */
const SIGNATURE_KEYS = new Set(['reasoningSignature', 'signature']);
const DATA_URL = /^data:[^;,]*;base64,/i;
const DROP = Symbol('drop');

function truncateString(text: string, maxBytes: number): string {
  if (Buffer.byteLength(text, 'utf8') <= maxBytes) return text;
  const room = Math.max(0, maxBytes - Buffer.byteLength(TRUNCATION_SUFFIX, 'utf8'));
  let used = 0;
  let out = '';
  for (const ch of text) {
    const n = Buffer.byteLength(ch, 'utf8');
    if (used + n > room) break;
    used += n;
    out += ch;
  }
  const result = out + TRUNCATION_SUFFIX;
  return Buffer.byteLength(result, 'utf8') <= maxBytes ? result : out;
}

function isImageMime(v: unknown): boolean {
  return typeof v === 'string' && v.toLowerCase().startsWith('image/');
}

function cleanNode(value: unknown, maxBytes: number): unknown {
  if (typeof value === 'string') return DATA_URL.test(value) ? DROP : truncateString(value, maxBytes);
  if (Array.isArray(value)) {
    const kept: unknown[] = [];
    for (const item of value) {
      const c = cleanNode(item, maxBytes);
      if (c !== DROP) kept.push(c);
    }
    return kept;
  }
  if (typeof value === 'object' && value !== null) {
    const rec = value as Record<string, unknown>;
    if (isImageMime(rec['mimeType'])) return DROP;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(rec)) {
      if (DROP_KEYS.has(k) || SIGNATURE_KEYS.has(k)) continue;
      const c = cleanNode(v, maxBytes);
      if (c !== DROP) out[k] = c;
    }
    return out;
  }
  return value;
}

/**
 * Cut every string to `maxBytes` of UTF-8 (suffix included) and remove image or
 * binary attachments: `images`, `documents`, `image`, `imageData` keys, objects
 * whose `mimeType` starts with `image/`, and base64 data-URL strings. (KE-3)
 * Keys named exactly `reasoningSignature` or `signature` are removed at any depth. (KE-58)
 */
export function truncateToolPayload(value: unknown, maxBytes = 2048): unknown {
  const c = cleanNode(value, maxBytes);
  return c === DROP ? undefined : c;
}

/** Parse one messages.jsonl line. Malformed JSON or a line without the envelope gives null. (KE-6) */
export function parseEventLine(line: string): KiroEvent | null {
  let raw: unknown;
  try {
    raw = JSON.parse(line);
  } catch {
    return null;
  }
  const parsed = KiroEventSchema.safeParse(raw);
  return parsed.success ? parsed.data : null;
}

/** The hook a `ContextualHookInvoked` line stands for. */
export type HookRef = { hookName: string };

function payloadOf(event: KiroEvent): Record<string, unknown> {
  return event.payload as Record<string, unknown>;
}

function nonEmptyString(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

/** A `ContextualHookInvoked` line gives the hook's `name` (else its `hookId`, else "unknown"). Any other event gives null. (KE-12) */
export function isHookRun(event: KiroEvent): HookRef | null {
  const p = payloadOf(event);
  if (p['type'] !== 'ContextualHookInvoked') return null;
  return { hookName: nonEmptyString(p['name']) ?? nonEmptyString(p['hookId']) ?? 'unknown' };
}

const HOOK_BLOCK_PREFIX = /^Tool "[^"\n]*" was intercepted by PreToolUse hooks before execution\./;

/**
 * A hook block is a `tool_result` with status `denied` whose content starts with
 * `Tool "<tool>" was intercepted by PreToolUse hooks before execution.`. The result
 * names no hook, so the block goes to `previousHook`, the hook line directly before
 * it. When several hook lines precede the result the caller passes the last one;
 * the blocker cannot be told apart. With no previous hook line the name is
 * "unknown". Kiro's own policy denials ("Kiro blocked this action:") are not blocks. (KE-13)
 */
export function isHookBlock(event: KiroEvent, previousHook: HookRef | null): HookRef | null {
  const p = payloadOf(event);
  if (p['type'] !== 'tool_result' || p['status'] !== 'denied') return null;
  const content = p['content'];
  if (typeof content !== 'string' || !HOOK_BLOCK_PREFIX.test(content)) return null;
  return previousHook ?? { hookName: 'unknown' };
}

/** One recorded hook block, for the evidence document's narration (KE-17). */
export type HookBlockRecord = { hookName: string; toolName: string | null; timestamp: string };

export type SessionRecord = {
  id: string;
  title: string | null;
  agentMode: string | null;
  startTime: string | null;
  endTime: string | null;
  model: string | null;
  autopilot: boolean | null;
  approveForMe: boolean | null;
  credits: number;
  toolCalls: Record<string, number>;
  hookRuns: Record<string, number>;
  hookBlocks: Record<string, number>;
  hookBlockEvents: HookBlockRecord[];
  commits: string[];
  /** Events left out because the final redaction pass left a line that was not valid JSON. */
  eventsDroppedUnparseable: number;
};

export type Totals = {
  sessionsKept: number;
  sessionsSkipped: number;
  credits: number;
  toolCalls: Record<string, number>;
  hookRuns: Record<string, number>;
  hookBlocks: Record<string, number>;
  eventsDroppedUnparseable: number;
};

const SessionJsonSchema = z
  .object({
    id: z.string().optional(),
    title: z.string().optional(),
    agentMode: z.string().optional(),
    createdAt: z.string().optional(),
    lastModifiedAt: z.string().optional(),
    modelId: z.string().optional(),
    autopilot: z.boolean().optional(),
    approveForMe: z.boolean().optional(),
  })
  .passthrough();

function bump(map: Record<string, number>, key: string, by = 1): void {
  map[key] = (map[key] ?? 0) + by;
}

// `[main abc1234] message` or `[main (root-commit) abc1234] message`, as `git commit` prints it.
const COMMIT_LINE = /^\[[^\]\s]+(?: \(root-commit\))? ([0-9a-f]{7,40})\]/gm;

function creditsOf(p: Record<string, unknown>): number {
  const turns = p['promptTurnSummaries'];
  if (!Array.isArray(turns)) return 0;
  let sum = 0;
  for (const t of turns) {
    const usage = typeof t === 'object' && t !== null ? (t as Record<string, unknown>)['usage'] : undefined;
    if (typeof usage === 'number' && Number.isFinite(usage)) sum += usage;
  }
  return sum;
}

/**
 * Build the `index.json` entry of one session from its `session.json` and parsed events. (KE-4)
 * Credits are the sum of `usage` over every `usage_summary`; `session_metadata creditSplit`
 * is ignored so nothing is counted twice. Tool calls are counted per `tool_call` line by
 * `toolName`. Hook blocks go to the hook line directly before the denied `tool_result`.
 */
export function extractSessionRecord(sessionJson: unknown, events: KiroEvent[]): SessionRecord {
  const s = SessionJsonSchema.safeParse(sessionJson);
  const meta = s.success ? s.data : {};
  const record: SessionRecord = {
    id: meta.id ?? '',
    title: meta.title ?? null,
    agentMode: meta.agentMode ?? null,
    startTime: meta.createdAt ?? null,
    endTime: meta.lastModifiedAt ?? null,
    model: meta.modelId ?? null,
    autopilot: meta.autopilot ?? null,
    approveForMe: meta.approveForMe ?? null,
    credits: 0,
    toolCalls: {},
    hookRuns: {},
    hookBlocks: {},
    hookBlockEvents: [],
    commits: [],
    eventsDroppedUnparseable: 0,
  };
  const commits = new Set<string>();
  const toolNameById = new Map<string, string>();
  let previousHook: HookRef | null = null;

  for (const event of events) {
    const p = payloadOf(event);
    const run = isHookRun(event);
    if (run) {
      bump(record.hookRuns, run.hookName);
      previousHook = run;
      continue;
    }
    const type = p['type'];
    if (type === 'tool_call') {
      const name = nonEmptyString(p['toolName']) ?? 'unknown';
      bump(record.toolCalls, name);
      const callId = nonEmptyString(p['toolCallId']);
      if (callId) toolNameById.set(callId, name);
    } else if (type === 'usage_summary') {
      record.credits += creditsOf(p);
    } else if (type === 'tool_result') {
      const block = isHookBlock(event, previousHook);
      if (block) {
        bump(record.hookBlocks, block.hookName);
        const callId = nonEmptyString(p['toolCallId']);
        record.hookBlockEvents.push({
          hookName: block.hookName,
          toolName: callId ? (toolNameById.get(callId) ?? null) : null,
          timestamp: event.timestamp,
        });
      } else if (typeof p['content'] === 'string') {
        for (const m of p['content'].matchAll(COMMIT_LINE)) if (m[1] !== undefined) commits.add(m[1]);
      }
    }
    previousHook = null;
  }
  record.commits = [...commits];
  return record;
}

function addInto(target: Record<string, number>, source: Record<string, number>): void {
  for (const [k, v] of Object.entries(source)) bump(target, k, v);
}

/** Sum every numeric and per-key field across `records`; `sessionsSkipped` is `skippedCount`. (KE-5, KE-14) */
export function aggregateTotals(records: SessionRecord[], skippedCount: number): Totals {
  const totals: Totals = {
    sessionsKept: records.length,
    sessionsSkipped: skippedCount,
    credits: 0,
    toolCalls: {},
    hookRuns: {},
    hookBlocks: {},
    eventsDroppedUnparseable: 0,
  };
  for (const r of records) {
    totals.credits += r.credits;
    totals.eventsDroppedUnparseable += r.eventsDroppedUnparseable;
    addInto(totals.toolCalls, r.toolCalls);
    addInto(totals.hookRuns, r.hookRuns);
    addInto(totals.hookBlocks, r.hookBlocks);
  }
  return totals;
}

export type EventLineResult = { ok: true; line: string } | { ok: false };

/**
 * Serialize one event as a JSON line and run `redact-secrets` over the serialized text as a final
 * pass. Per-string redaction sees raw values, but a value that starts with an escaped quote only
 * takes a secret shape in the serialized text (the rescan reads that text). The result must still
 * parse as JSON; if it does not, the event is not written. (KE-9, KE-10)
 */
export function finalizeEventLine(event: unknown): EventLineResult {
  const serialized = JSON.stringify(event);
  if (typeof serialized !== 'string') return { ok: false };
  const line = redactExtras(redactSecretText(redactSignInUrls(serialized)), true);
  try {
    JSON.parse(line);
  } catch {
    return { ok: false };
  }
  return { ok: true, line };
}

/** True when `text` holds anything `redact-secrets` would replace: the post-write rescan. (KE-10) */
export function containsSecretShape(text: string): boolean {
  if (containsSecret(text)) return true;
  const extra = extraSecretShapeCounts(text);
  return extra.jwt > 0 || extra.account > 0 || extra.signInUrl > 0;
}
