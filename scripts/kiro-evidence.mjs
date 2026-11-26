#!/usr/bin/env node
// Exports the Kiro sessions that built this project into evidence/kiro-sessions/
// (m13-kiro-evidence, KE-1 to KE-14).
//
//   node scripts/kiro-evidence.mjs
//   node scripts/kiro-evidence.mjs --sessions <dir> --home <dir> --out <dir>
//
// Options (flag, then environment variable, then default):
//   --sessions  EXORCIST_KIRO_SESSIONS  the sessions folder          <home>/.kiro/sessions
//   --home      EXORCIST_KIRO_HOME      the home folder to replace with ~   the current user's
//   --out       EXORCIST_KIRO_OUT       where the output goes        <repo>/evidence/kiro-sessions
//
// It writes <out>/<session id>.jsonl.gz for each session of this project and
// <out>/index.json. Sessions of any other workspace are counted, never written.
// It walks only the sessions folder: never ~/.kiro/settings, never a session's
// tool-outputs/, snapshots/ or sub-executions/ folders. Every string is cut,
// home-path-redacted and secret-redacted before it is written, then each
// written file is read back and scanned again. A hit deletes everything this
// run wrote, names the file and the pattern type (never the text) on stderr
// and exits 1. It prints counts only, never conversation contents.
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { gunzipSync, gzipSync } from 'node:zlib';
import { register } from 'tsx/esm/api';

register();
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const core = await import(pathToFileURL(join(ROOT, 'packages/core/src/kiro-evidence.ts')).href);
const { redactSecretText } = await import(pathToFileURL(join(ROOT, 'packages/core/src/redact-secrets.ts')).href);
const {
  isThisProjectWorkspace, redactHomePath, redactSecretsDeep, truncateToolPayload, parseEventLine,
  extractSessionRecord, aggregateTotals, containsSecretShape, finalizeEventLine,
  omitSignInOutputs, omitOutsideWorkspaceReads, extraSecretShapeCounts,
} = core;

const { values } = parseArgs({
  options: { sessions: { type: 'string' }, home: { type: 'string' }, out: { type: 'string' } },
  strict: true,
});
const HOME = resolve(values.home ?? process.env.EXORCIST_KIRO_HOME ?? homedir());
const SESSIONS = resolve(values.sessions ?? process.env.EXORCIST_KIRO_SESSIONS ?? join(HOME, '.kiro', 'sessions'));
const OUT = resolve(values.out ?? process.env.EXORCIST_KIRO_OUT ?? join(ROOT, 'evidence', 'kiro-sessions'));

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
// Folders that are never opened: Kiro's settings (KE-11) and a session's bulky or private parts.
const NEVER_OPEN = new Set(['settings', '.index', 'tool-outputs', 'snapshots', 'sub-executions']);

const note = (msg) => process.stderr.write(`kiro-evidence: ${msg}\n`);

function homeDeep(value) {
  if (typeof value === 'string') return redactHomePath(value, HOME);
  if (Array.isArray(value)) return value.map(homeDeep);
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, homeDeep(v)]));
  }
  return value;
}
/** Cut, then home path, then secrets: the order the design gives. */
const redactAll = (value) => redactSecretsDeep(homeDeep(truncateToolPayload(value)));

function readJson(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return null; }
}
function subdirs(dir) {
  let names;
  try { names = readdirSync(dir); } catch { return []; }
  return names.filter((n) => !NEVER_OPEN.has(n) && statSync(join(dir, n)).isDirectory()).sort();
}
function workspacePathsOf(sessionJson) {
  const p = sessionJson?.workspacePaths;
  return Array.isArray(p) ? p.filter((x) => typeof x === 'string') : [];
}

/** Count of each secret kind in `text`, read from the redaction markers. Never the secret itself. */
function secretKindCounts(text) {
  const counts = new Map();
  for (const m of redactSecretText(text).matchAll(/\[redacted ([a-z-]+)(?::| line)/g)) {
    counts.set(m[1], (counts.get(m[1]) ?? 0) + 1);
  }
  const extra = extraSecretShapeCounts(text);
  if (extra.jwt > 0) counts.set('jwt', (counts.get('jwt') ?? 0) + extra.jwt);
  if (extra.account > 0) counts.set('aws-account', (counts.get('aws-account') ?? 0) + extra.account);
  if (extra.signInUrl > 0) counts.set('sign-in-url', (counts.get('sign-in-url') ?? 0) + extra.signInUrl);
  return counts;
}
function stringValues(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const v of value) stringValues(v, out);
  else if (typeof value === 'object' && value !== null) {
    for (const [k, v] of Object.entries(value)) { out.push(k); stringValues(v, out); }
  }
  return out;
}
/**
 * Scan the raw text, and every string value and key parsed from each JSON line of it.
 * Returns a Map of secret kind to count (the larger of the two views, so nothing is counted twice).
 */
function rescan(text) {
  const raw = containsSecretShape(text) ? secretKindCounts(text) : new Map();
  const parsedCounts = new Map();
  for (const line of text.split('\n')) {
    if (line.length === 0) continue;
    let parsed;
    try { parsed = JSON.parse(line); } catch { continue; }
    for (const s of stringValues(parsed)) {
      if (!containsSecretShape(s)) continue;
      for (const [k, n] of secretKindCounts(s)) parsedCounts.set(k, (parsedCounts.get(k) ?? 0) + n);
    }
  }
  const out = new Map(raw);
  for (const [k, n] of parsedCounts) out.set(k, Math.max(out.get(k) ?? 0, n));
  return out;
}

const written = [];
const hits = []; // { file, counts }
function writeChecked(path, buffer, readBack) {
  writeFileSync(path, buffer);
  written.push(path);
  const counts = rescan(readBack(readFileSync(path)));
  if (counts.size > 0) hits.push({ file: path, counts });
}
/** Delete this run's output and report, per file, only the secret kinds and counts. Exits 1. */
function failAndClean() {
  for (const f of written) rmSync(f, { force: true });
  note("secret shape found; deleted this run's output, nothing kept");
  for (const { file, counts } of hits) {
    const kinds = [...counts].sort((a, b) => a[0].localeCompare(b[0])).map(([k, n]) => `${k} x${n}`).join(', ');
    note(`${basename(file)}: ${kinds}`);
  }
  process.exit(1);
}

mkdirSync(OUT, { recursive: true });

const records = [];
let skipped = 0;
if (!existsSync(SESSIONS)) {
  process.stdout.write('kiro-evidence: no Kiro sessions found\n');
} else {
  for (const hash of subdirs(SESSIONS)) {
    for (const folder of subdirs(join(SESSIONS, hash))) {
      const dir = join(SESSIONS, hash, folder);
      const sessionPath = join(dir, 'session.json');
      const messagesPath = join(dir, 'messages.jsonl');
      if (!existsSync(sessionPath) || !existsSync(messagesPath)) {
        note('a session folder without session.json or messages.jsonl was skipped');
        continue;
      }
      const sessionJson = readJson(sessionPath);
      if (sessionJson === null) { note('a session.json that is not JSON was skipped'); continue; }
      // KE-2, KE-7: any workspace that is not this project is counted, never written.
      if (!workspacePathsOf(sessionJson).some(isThisProjectWorkspace)) { skipped += 1; continue; }
      const id = typeof sessionJson.id === 'string' && SAFE_ID.test(sessionJson.id) ? sessionJson.id : folder;
      if (!SAFE_ID.test(id)) { note('a session with an unusable id was skipped'); continue; }

      const parsedEvents = [];
      for (const line of readFileSync(messagesPath, 'utf8').split('\n')) {
        if (line.trim().length === 0) continue;
        const event = parseEventLine(line);
        if (event) parsedEvents.push(event); // KE-6: a malformed line is dropped
      }
      // KE-51: sign-in tool output is replaced before anything else reads it.
      // KE-55: a home-folder file read outside this session's workspace is omitted the same way.
      const events = omitOutsideWorkspaceReads(omitSignInOutputs(parsedEvents), workspacePathsOf(sessionJson), HOME);
      const record = redactAll(extractSessionRecord({ ...sessionJson, id }, events));
      // Final pass: redact the serialized line itself, then prove it still parses (KE-9, KE-10).
      const lines = [];
      for (const e of events) {
        const r = finalizeEventLine(redactAll(e));
        if (r.ok) lines.push(r.line);
        else record.eventsDroppedUnparseable += 1;
      }
      const body = lines.join('\n') + (lines.length > 0 ? '\n' : '');
      writeChecked(join(OUT, `${id}.jsonl.gz`), gzipSync(body), (buf) => gunzipSync(buf).toString('utf8'));
      records.push(record);
    }
  }
}

records.sort((a, b) => String(a.startTime ?? '').localeCompare(String(b.startTime ?? '')) || a.id.localeCompare(b.id));
const index = { sessions: records, totals: aggregateTotals(records, skipped) };
writeChecked(join(OUT, 'index.json'), JSON.stringify(index, null, 2) + '\n', (buf) => buf.toString('utf8'));

if (hits.length > 0) failAndClean();
process.stdout.write(`kiro-evidence: kept ${records.length}, skipped ${skipped}, credits ${index.totals.credits.toFixed(2)}, dropped unparseable ${index.totals.eventsDroppedUnparseable}\n`);
