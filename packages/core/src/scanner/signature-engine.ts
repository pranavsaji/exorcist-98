import vm from 'node:vm';
import { JSONPath } from 'jsonpath-plus';
import type { RepoFile, SignatureFinding, Severity } from '../types.js';
import type { NormalizedText, UnicodeHit } from '../normalizer.js';
import type { VirusDefinition } from '../definitions/schema.js';
import { decodeHidden, MAX_HIDDEN_RUNS } from '../ouija.js';
import { findHiddenText } from '../hidden-text.js';
import { lowersSeverity } from '../severity-paths.js';
import { typosquatOf } from '../known-packages.js';
import { benignPayloadKind, COMMAND_LIKE, decodeBlob, embeddedDocumentKind, fencedRanges, inExecContext, inMarkdownCode, isCredibleSecret, isNegated, isQuotedExample } from './context.js';

const MAX_SPAN = 120;

// Cache compiled regexes keyed by flags + pattern (not by rule id, so two
// rules, or a rule edited between runs, can never share a stale regex).
const regexCache = new Map<string, RegExp>();

function getRegex(pattern: string, flags: string): RegExp {
  const key = `${flags}/${pattern}`;
  const cached = regexCache.get(key);
  if (cached) return cached;
  const re = new RegExp(pattern, flags);
  regexCache.set(key, re);
  return re;
}

function offsetToPosition(text: string, offset: number): { line: number; col: number } {
  const before = text.slice(0, offset);
  const line = (before.match(/\n/g) ?? []).length + 1;
  const lastNl = before.lastIndexOf('\n');
  const col = lastNl === -1 ? offset + 1 : offset - lastNl;
  return { line, col };
}

function escapeCodePoint(hit: UnicodeHit): string {
  const hex = hit.codePoint.toString(16).toUpperCase();
  return hit.codePoint > 0xFFFF ? `\\u{${hex}}` : `\\u${hex.padStart(4, '0')}`;
}

/** Join escapes for a run of hidden characters, cutting only between escapes. */
function joinEscapes(run: UnicodeHit[]): string {
  let out = '';
  for (const hit of run) {
    const e = escapeCodePoint(hit);
    if (out.length + e.length > MAX_SPAN) return `${out}…`;
    out += e;
  }
  return out;
}

/**
 * The message a run of hidden characters carries, when it decodes (Ouija
 * decoder, REQ-03.2): the tag characters of the run spell ASCII (other hidden
 * characters mixed into the run are skipped), and a run of variation
 * selectors carries bytes. The result is attacker text: it is shown to the
 * user, never prompted, and at most 500 characters (REQ-04).
 */
function decodedForRun(run: UnicodeHit[]): string | undefined {
  const tags = run.filter((h) => h.class === 'tag-block');
  const carrier = tags.length > 0 ? tags : run.filter((h) => h.class === 'variation-selector');
  const first = decodeHidden(carrier.map((h) => h.char).join(''))[0];
  return first && first.message.length > 0 ? first.message : undefined;
}

function truncateSpan(s: string): string {
  if (s.length <= MAX_SPAN) return s;
  return s.slice(0, MAX_SPAN) + '…';
}

/**
 * Locate a JSON string value in the raw file text so findings carry a real
 * line and column. Falls back to 1:1 if the value cannot be found verbatim.
 */
function locateJsonValue(original: string, value: string, occurrence = 0): { line: number; col: number } {
  const encoded = JSON.stringify(value);
  // L-011: the n-th time a value is reported, point at its n-th appearance.
  let idx = original.indexOf(encoded);
  for (let n = 0; n < occurrence && idx !== -1; n++) {
    const next = original.indexOf(encoded, idx + encoded.length);
    if (next === -1) break;
    idx = next;
  }
  if (idx === -1) return { line: 1, col: 1 };
  return offsetToPosition(original, idx);
}

/** Runner options whose next argument is their value, never the package (uvx, npx). */
const OPTIONS_WITH_VALUE = new Set([
  '--python', '--python-preference', '--with', '--with-editable', '--with-requirements', '--index', '--index-url',
  '--extra-index-url', '--default-index', '--directory', '--env-file', '--constraints', '--overrides', '--registry',
  '--cache', '--cache-dir', '--userconfig',
]);
/** `3`, `3.13`, `3.13.1`, `cpython-3.13`, `pypy3.10`: a Python version, not a package. */
const PYTHON_VERSION = /^(?:(?:cpython|pypy)[-@]?)?\d+(?:\.\d+){0,2}(?:t|-[a-z0-9_.-]+)?$/i;

/**
 * The package a runner (`npx`, `bunx`, `pnpx`, `uvx`) is told to run: the value
 * of `--package`/`-p`/`--from`, or else the first argument that is not a flag
 * (L-012). Null when there is none.
 */
export function packageArg(args: unknown[]): string | null {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (typeof a !== 'string') return null;
    if (a === '--package' || a === '-p' || a === '--from') {
      const v = args[i + 1];
      if (typeof v !== 'string') return null;
      // `uvx -p 3.13 pkg`: for uv, -p is the Python version, not the package.
      if (a === '-p' && PYTHON_VERSION.test(v)) { i++; continue; }
      return v;
    }
    // `uvx --python 3.13 pkg`: these options take a value, which is not the package.
    if (OPTIONS_WITH_VALUE.has(a)) { i++; continue; }
    const eq = /^--(?:package|from)=(.+)$/.exec(a);
    if (eq) return eq[1] ?? null;
    if (a.startsWith('-')) continue; // -y, --yes, --quiet and other flags
    return a;
  }
  return null;
}

/**
 * True when `s` is base64 that decodes to mostly readable text. Random hashes,
 * URL paths and identifiers decode to binary noise and are rejected, which is
 * what made EX-003 fire thousands of times on ordinary repositories.
 */
export function isBase64Text(s: string): boolean {
  const t = s.replace(/=+$/, '');
  if (t.length < 40 || /[^A-Za-z0-9+/]/.test(t)) return false;
  // Path-like runs (a/b/c) are not payloads.
  if (/^[A-Za-z0-9_.-]*(\/[A-Za-z0-9_.-]+){2,}\/?$/.test(s) && !s.includes('+')) return false;
  if (/^[0-9a-f]+$/i.test(t)) return false;
  if (t.length % 4 === 1) return false;
  return looksLikeText(Buffer.from(t, 'base64'));
}

/** True when `s` is hex (`6375726c...`, `\\x63\\x75...` or `0x...`) that decodes to readable text (L-018). */
export function isHexText(s: string): boolean {
  const t = s.replace(/\\x/gi, '').replace(/^0x/i, '');
  if (t.length < 48 || t.length % 2 !== 0 || /[^0-9a-f]/i.test(t)) return false;
  return looksLikeText(Buffer.from(t, 'hex'));
}

function looksLikeText(bytes: Buffer): boolean {
  if (bytes.length < 24) return false;
  let printable = 0;
  for (const b of bytes) if ((b >= 0x20 && b < 0x7f) || b === 0x0a || b === 0x0d || b === 0x09) printable++;
  if (printable / bytes.length < 0.95) return false;
  // A payload is words or a command. JSON (JWTs), IDs and keys are not.
  const text = bytes.toString('latin1');
  if (/^\s*[{[]/.test(text)) return false;
  const words = text.split(/\s+/).filter((w) => /[A-Za-z]{2,}/.test(w)).length;
  return words >= 4 || COMMAND_LIKE.test(text);
}

// ── Time limit for rule regexes (L-004) ────────────────────────────────────────
// Rules run on attacker-controlled text. A crafted file could make a regex
// backtrack for minutes, so all of a file's regex rules run inside one vm call
// with a time limit (one call per file keeps the overhead near 0.1 ms).
type RawMatch = [index: number, text: string];
type Job = { re: RegExp; text: string };
function rawMatches(re: RegExp, text: string): RawMatch[] {
  const out: RawMatch[] = [];
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) { re.lastIndex++; continue; } // avoid infinite loop on empty matches
    out.push([m.index, m[0]]);
  }
  return out;
}
const guardCtx = vm.createContext({ run: (jobs: Job[]) => jobs.map((j) => rawMatches(j.re, j.text)), jobs: null as Job[] | null, out: null as RawMatch[][] | null });
const guardScript = new vm.Script('out = run(jobs)');
/** The span of the finding a rule leaves when it runs out of time on a file (scanner text, never the file's). */
export const timeoutSpan = (ruleId: string): string => `${ruleId} ran out of time on this file`;
/** True for the medium finding a rule leaves when it could not finish on a file. */
export const isTimeoutFinding = (f: { ruleId: string; span: string; source?: string }): boolean =>
  f.source !== 'heuristic' && f.span === timeoutSpan(f.ruleId);
/** Time allowed for all regex rules on one file. */
export const REGEX_TIME_LIMIT_MS = 1500;
function guarded(jobs: Job[], ms: number): RawMatch[][] | null {
  guardCtx['jobs'] = jobs;
  try {
    guardScript.runInContext(guardCtx, { timeout: ms });
    return guardCtx['out'] as RawMatch[][];
  } catch (err) {
    if ((err as { code?: string }).code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') return null;
    throw err;
  } finally {
    guardCtx['jobs'] = null;
    guardCtx['out'] = null;
  }
}

/** Number of short zero-width runs in one file that counts as a hidden message (see EX-001 minor_run). */
export const MINOR_RUNS_ESCALATE = 5;

export function runSignatures(
  file: RepoFile,
  norm: NormalizedText,
  defs: VirusDefinition[],
  limitMs: number = REGEX_TIME_LIMIT_MS,
): SignatureFinding[] {
  const findings: SignatureFinding[] = [];
  type Active = { def: VirusDefinition; base: Omit<SignatureFinding, 'line' | 'col' | 'span'>; keep: (t: string) => boolean; jobs: number[] };
  const active: Active[] = [];
  const jobs: Job[] = [];
  const vis = norm.visible;
  const lowered = new Set<string>();
  const ctx = makeContext(file, norm, defs, limitMs);
  for (const def of defs) {
    if (def.enabled === false) continue;
    if (!def.applies_to.includes(file.role)) continue;
    if (def.skip_paths?.some((p) => getRegex(p, 'i').test(file.rel))) continue;
    // Test and eval folders: report at low severity instead of dropping (never for agent-facing files).
    if (lowersSeverity(def, file.rel, file.role)) lowered.add(def.id);
    const { match } = def;
    // A whole-config analysis (EX-023) is run by the orchestrator, not here.
    if (match.analysis) continue;
    // file_regex narrows generic config files only; MCP configs and tool
    // descriptions (the Shield scans those) always qualify.
    if (match.file_regex && file.role === 'config' && !getRegex(match.file_regex, 'i').test(norm.plain)) continue;
    const exclude = match.exclude_regex ? getRegex(match.exclude_regex, 'i') : null;
    // A merged rule validates whole blobs, after merging (see below).
    const validateLater = match.merge_adjacent === true;
    const keep = (text: string): boolean => {
      if (exclude && exclude.test(text)) return false;
      if (match.validate === 'typosquat' && typosquatOf(text) === null) return false;
      if (validateLater) return true;
      if (match.validate === 'base64-text' && !isBase64Text(text)) return false;
      if (match.validate === 'encoded-text' && !isBase64Text(text) && !isHexText(text)) return false;
      return true;
    };
    const base: Omit<SignatureFinding, 'line' | 'col' | 'span'> = {
      source:   'signature',
      ruleId:   def.id,
      title:    def.title,
      severity: def.severity as Severity,
      file:     file.rel,
      owasp:    def.owasp,
      fix:      def.fix,
    };
    const mine: number[] = [];
    if (match.regex) {
      const re = getRegex(match.regex, 'gi');
      mine.push(jobs.push({ re, text: norm.plain }) - 1);
      // L-005: the same text with hidden characters removed, mapped back.
      if (vis) mine.push(jobs.push({ re, text: vis.text }) - 1);
    }
    active.push({ def, base, keep, jobs: mine });
  }

  // Run every regex job for this file under one time limit. If the file runs
  // out of time, retry each job alone so only the slow rule is affected.
  let results: (RawMatch[][] | null) = jobs.length > 0 ? guarded(jobs, limitMs) : [];
  const timedOut = new Set<number>();
  if (results === null) {
    results = jobs.map((j, i) => {
      const r = guarded([j], Math.max(50, Math.floor(limitMs / 3)));
      if (r === null) { timedOut.add(i); return []; }
      return r[0] ?? [];
    });
  }

  for (const { def, base, keep, jobs: mine } of active) {
    const { match } = def;
    // ── regex ────────────────────────────────────────────────────────────────
    if (match.regex) {
      if (mine.some((i) => timedOut.has(i))) {
        // Never silently clean: the rule could not finish on this file.
        findings.push({
          ...base, severity: 'medium', line: 1, col: 1,
          span: timeoutSpan(def.id),
          fix: `This file made the ${def.id} check run too long, which can be a deliberate attack on the scanner. Review the file by hand. ${def.fix}`,
        });
      } else {
        const seen = new Set<number>();
        const cands: Candidate[] = [];
        mine.forEach((jobIndex, k) => {
          const src = k === 0 || !vis ? norm.plain : vis.text;
          const toPlain = k === 0 || !vis ? (i: number) => i : (i: number) => vis.map[i] ?? i;
          for (const [index, text] of results?.[jobIndex] ?? []) {
            if (!keep(text)) continue;
            const at = toPlain(index);
            if (seen.has(at)) continue;
            if (!ctx.allows(def, text, at, src, index)) continue;
            seen.add(at);
            cands.push({ at, text });
          }
        });
        cands.sort((a, b) => a.at - b.at);
        const groups = match.merge_adjacent ? mergeAdjacent(cands, norm.plain) : cands.map((c) => [c]);
        const mineOut: SignatureFinding[] = [];
        for (const group of groups) {
          if (match.merge_adjacent && !ctx.blobCounts(def, group)) continue;
          const first = group[0];
          if (!first) continue;
          // L-010: map the decoded-text index back to the original file.
          const { line, col } = offsetToPosition(norm.original, norm.plainMap?.[first.at] ?? first.at);
          mineOut.push({ ...base, line, col, span: truncateSpan(first.text) });
        }
        findings.push(...capPerFile(def, mineOut));
      }
    }
    // ── hidden_text (EX-028) ─────────────────────────────────────────────────
    if (match.hidden_text) {
      for (const h of findHiddenText(norm.plain)) {
        if (!ctx.allows(def, h.text, h.index, norm.plain, h.index)) continue;
        const { line, col } = offsetToPosition(norm.original, norm.plainMap?.[h.index] ?? h.index);
        findings.push({ ...base, line, col, span: truncateSpan(h.text) });
      }
    }
    // ── unicode_class ────────────────────────────────────────────────────────
    if (match.unicode_class && match.unicode_class.length > 0) {
      // Adjacent hidden characters are one finding: a payload of 37 tag
      // characters is one hidden message, not 37 problems.
      let run: UnicodeHit[] = [];
      const mineStart = findings.length;
      let minorRuns = 0;
      const guards = new Set<SignatureFinding>();
      // Decoding is bounded too: at most MAX_HIDDEN_RUNS runs per file (REQ-04.2).
      let decodedRuns = 0;
      const flush = (): void => {
        const first = run[0];
        if (!first) return;
        // A run shorter than the rule's minimum is not this rule's problem
        // at all (EX-021: one to three variation selectors are ordinary emoji or
        // CJK presentation; the normalizer already drops such runs).
        if (match.min_run !== undefined && run.length < match.min_run) { run = []; return; }
        const { line, col } = offsetToPosition(norm.original, first.offset);
        // A short run of zero-width characters cannot carry a message; it is
        // usually left over from translation or formatting. Long runs, tag
        // characters and bidi controls keep the rule's own severity.
        const minor = match.minor_run;
        const isMinor = Boolean(minor && run.length <= minor.max_length && run.every((h) => minor.classes.includes(h.class)));
        // A single U+200B between `@` and a name: the changelog trick that stops
        // GitHub from notifying the person. Low, and it does not count toward
        // the escalation below (m7-precision).
        const guard = match.mention_guard;
        const isGuard = Boolean(guard && run.length === 1 && first.codePoint === 0x200B
          && norm.original[first.offset - 1] === '@' && /[A-Za-z0-9_]/.test(norm.original[first.offset + 1] ?? ''));
        if (isMinor && !isGuard) minorRuns++;
        const severity = isGuard && guard ? guard.severity : isMinor && minor ? minor.severity : base.severity;
        const decoded = decodedRuns < MAX_HIDDEN_RUNS ? decodedForRun(run) : undefined;
        if (decoded !== undefined) decodedRuns += 1;
        const out: SignatureFinding = { ...base, severity, line, col, span: joinEscapes(run), ...(decoded !== undefined ? { decoded } : {}) };
        if (isGuard) guards.add(out);
        findings.push(out);
        run = [];
      };
      for (const hit of norm.hiddenUnicode) {
        if (!match.unicode_class.includes(hit.class)) {
          flush();
          continue;
        }
        const prev = run[run.length - 1];
        if (prev && hit.offset !== prev.offset + prev.char.length) flush();
        run.push(hit);
      }
      flush();
      // Many short runs spread through one file can spell out a message (one
      // or two bits per gap, zero-width steganography). Past a handful, every
      // run in the file is reported at the rule's full severity again.
      if (minorRuns >= MINOR_RUNS_ESCALATE) {
        for (let i = mineStart; i < findings.length; i++) {
          const f = findings[i];
          if (f && f.ruleId === def.id && !guards.has(f)) findings[i] = { ...f, severity: base.severity };
        }
      }
    }
    // ── json_path (+ optional value_regex filter) ────────────────────────────
    if (match.json_path) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(norm.original);
      } catch {
        continue; // not valid JSON: skip silently
      }
      // A bare JSON value (`false`, `0`, `"text"`) has no paths to match.
      if (parsed === null || typeof parsed !== 'object') continue;
      let results: unknown[];
      try {
        const found: unknown = JSONPath({ path: match.json_path, json: parsed });
        if (!Array.isArray(found)) continue;
        results = found;
      } catch {
        continue;
      }
      const valueFilter = match.value_regex
        ? new RegExp(match.value_regex, 'i')
        : null;

      const seenValues = new Map<string, number>();
      for (const raw of results) {
        if (raw === undefined || raw === null) continue;
        let val: unknown = raw;
        if (match.select === 'package-arg') {
          if (!Array.isArray(raw)) continue;
          val = packageArg(raw);
          if (val === null) continue;
        }
        const text = typeof val === 'string' ? val : JSON.stringify(val);
        if (valueFilter && !valueFilter.test(text)) continue;
        if (!keep(text)) continue;
        let pos = { line: 1, col: 1 };
        if (typeof val === 'string') {
          const n = seenValues.get(val) ?? 0;
          seenValues.set(val, n + 1);
          pos = locateJsonValue(norm.original, val, n);
        }
        findings.push({ ...base, line: pos.line, col: pos.col, span: truncateSpan(text) });
      }
    }
  }

  const out = lowered.size === 0 ? findings : findings.map((f) => (lowered.has(f.ruleId) ? { ...f, severity: 'low' as const } : f));
  return sameLineGroups(out, defs);
}

// ── Precision round 2 helpers ──────────────────────────────────────────────────

type Candidate = { at: number; text: string };
const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * Rules in one `same_line_group` (for example "remote code in hook" and
 * "shell in tool output") that report the same line are one problem: keep
 * only the most severe finding for that line.
 */
function sameLineGroups(findings: SignatureFinding[], defs: VirusDefinition[]): SignatureFinding[] {
  const groupOf = new Map(defs.filter((d) => d.same_line_group).map((d) => [d.id, d.same_line_group as string]));
  if (groupOf.size === 0) return findings;
  const best = new Map<string, SignatureFinding>();
  for (const f of findings) {
    const g = groupOf.get(f.ruleId);
    if (!g) continue;
    const k = `${g}|${f.file}|${f.line}`;
    const cur = best.get(k);
    if (!cur || SEVERITY_RANK[f.severity] > SEVERITY_RANK[cur.severity]) best.set(k, f);
  }
  return findings.filter((f) => {
    const g = groupOf.get(f.ruleId);
    return !g || best.get(`${g}|${f.file}|${f.line}`) === f;
  });
}

/**
 * Matches separated only by line breaks, quotes, commas, `+` or a string
 * continuation are pieces of one blob (a base64 file wrapped over many lines,
 * or split into concatenated string literals).
 */
function mergeAdjacent(cands: Candidate[], text: string): Candidate[][] {
  const out: Candidate[][] = [];
  let cur: Candidate[] = [];
  let end = -1;
  for (const c of cands) {
    const gap = end >= 0 ? text.slice(end, c.at) : null;
    if (gap !== null && gap.length <= 16 && /^[\s"'`+,\\]*$/.test(gap) && (gap.match(/\n/g) ?? []).length <= 2) cur.push(c);
    else { if (cur.length) out.push(cur); cur = [c]; }
    end = c.at + c.text.length;
  }
  if (cur.length) out.push(cur);
  return out;
}

/** At most `max_per_file` findings; the last one says how many more there were. */
function capPerFile(def: VirusDefinition, out: SignatureFinding[]): SignatureFinding[] {
  const max = def.match.max_per_file;
  if (!max || out.length <= max) return out;
  const kept = out.slice(0, max - 1);
  const rest = out.slice(max - 1);
  const first = rest[0] as SignatureFinding;
  const last = rest[rest.length - 1] as SignatureFinding;
  kept.push({
    ...first,
    span: `${rest.length} more ${def.title.toLowerCase()} findings in this file (lines ${first.line}-${last.line}); only the first ${max - 1} are listed`,
  });
  return kept;
}

/** Per-file context for the checks a regex cannot make on its own (see context.ts). */
function makeContext(file: RepoFile, norm: NormalizedText, defs: VirusDefinition[], limitMs: number) {
  let fences: Array<[number, number]> | null = null;
  // Rules whose phrases count as instructions when found inside a decoded file.
  let rescan: Array<{ re: RegExp; cues: RegExp | null; neg: RegExp | null }> | null = null;
  const rescanRules = (self: VirusDefinition): Array<{ re: RegExp; cues: RegExp | null; neg: RegExp | null }> => {
    rescan ??= defs
      .filter((d) => d.enabled !== false && d.id !== self.id && d.match.regex && !d.match.merge_adjacent
        && (d.applies_to.includes('instruction') || d.applies_to.includes('hook')))
      .map((d) => ({
        re: getRegex(d.match.regex as string, 'gi'),
        cues: d.match.quoted_example_cues ? getRegex(d.match.quoted_example_cues, 'i') : null,
        neg: d.match.negated_cues ? getRegex(d.match.negated_cues, 'i') : null,
      }));
    return rescan;
  };
  return {
    /** Context checks for one regex match. `src`/`index` are the text and offset it was found in. */
    allows(def: VirusDefinition, text: string, at: number, src: string, index: number): boolean {
      const m = def.match;
      if (m.validate === 'secret-value' && !isCredibleSecret(text, src.slice(index + text.length, index + text.length + 200))) return false;
      if (m.exec_context && file.role === 'config' && !inExecContext(file.rel, norm.plain, at, text)) return false;
      if (m.skip_in_code) {
        fences ??= fencedRanges(norm.plain);
        if (inMarkdownCode(norm.plain, at, fences)) return false;
      }
      if (m.quoted_example_cues && isQuotedExample(src, index, text.length, getRegex(m.quoted_example_cues, 'i'))) return false;
      // The passage forbids the phrase: a defence, not an attack.
      if (m.negated_cues && isNegated(src, index, getRegex(m.negated_cues, 'i'))) return false;
      return true;
    },
    /**
     * Whether a merged encoded blob is reported. It must decode to readable
     * text (as a whole, or one of its pieces). If it decodes to an embedded
     * file (SVG, XML, PDF, a Markdown document, a licence, anything starting
     * with a byte-order mark), it counts only when the decoded text contains
     * something the other rules flag, or one of `decoded_flag_regex`.
     */
    blobCounts(def: VirusDefinition, group: Candidate[]): boolean {
      const m = def.match;
      const ok = (t: string): boolean =>
        m.validate === 'base64-text' ? isBase64Text(t)
          : m.validate === 'encoded-text' ? isBase64Text(t) || isHexText(t)
            : true;
      const merged = group.map((c) => c.text).join('');
      const piece = ok(merged) ? merged : group.find((c) => ok(c.text))?.text;
      if (piece === undefined) return false;
      if (m.validate !== 'base64-text' && m.validate !== 'encoded-text') return true;
      const decoded = decodeBlob(merged) ?? decodeBlob(piece) ?? '';
      // An embedded file, or data that is not hidden words (a query, a model
      // definition, a minisign key, a declared InlineBase64 payload), counts
      // only when what it says is flagged by the other rules.
      const first = group[0];
      const around = first ? norm.plain.slice(Math.max(0, first.at - 300), first.at + merged.length + 300) : '';
      if (embeddedDocumentKind(decoded) === null && benignPayloadKind(decoded, around) === null) return true;
      const sample = decoded.slice(0, 200_000);
      if (m.decoded_flag_regex && getRegex(m.decoded_flag_regex, 'i').test(sample)) return true;
      const rules = rescanRules(def);
      const hits = guarded(rules.map(({ re }) => ({ re, text: sample })), Math.max(50, Math.floor(limitMs / 3)));
      if (hits === null) return true; // could not finish: report rather than stay silent
      // The same quoted-example exemption as in plain text.
      return hits.some((h, i) => h.some(([index, t]) => {
        const cues = rules[i]?.cues;
        const neg = rules[i]?.neg;
        return (!cues || !isQuotedExample(sample, index, t.length, cues)) && (!neg || !isNegated(sample, index, neg));
      }));
    },
  };
}
