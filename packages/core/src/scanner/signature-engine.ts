import vm from 'node:vm';
import { JSONPath } from 'jsonpath-plus';
import type { RepoFile, SignatureFinding, Severity } from '../types.js';
import type { NormalizedText, UnicodeHit } from '../normalizer.js';
import type { VirusDefinition } from '../definitions/schema.js';

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

function truncateSpan(s: string): string {
  if (s.length <= MAX_SPAN) return s;
  return s.slice(0, MAX_SPAN) + '…';
}

/**
 * Locate a JSON string value in the raw file text so findings carry a real
 * line and column. Falls back to 1:1 if the value cannot be found verbatim.
 */
function locateJsonValue(original: string, value: string): { line: number; col: number } {
  const encoded = JSON.stringify(value);
  const idx = original.indexOf(encoded);
  if (idx === -1) return { line: 1, col: 1 };
  return offsetToPosition(original, idx);
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
  const bytes = Buffer.from(t, 'base64');
  if (bytes.length < 24) return false;
  let printable = 0;
  for (const b of bytes) if ((b >= 0x20 && b < 0x7f) || b === 0x0a || b === 0x0d || b === 0x09) printable++;
  if (printable / bytes.length < 0.95) return false;
  // A payload is words or a command. JSON (JWTs), IDs and keys are not.
  const text = bytes.toString('latin1');
  if (/^\s*[{[]/.test(text)) return false;
  const words = text.split(/\s+/).filter((w) => /[A-Za-z]{2,}/.test(w)).length;
  return words >= 4 || /(https?:\/\/|\bcurl\b|\bwget\b|\|\s*(ba|z)?sh\b|powershell|\$\(|`)/i.test(text);
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
  for (const def of defs) {
    if (def.enabled === false) continue;
    if (!def.applies_to.includes(file.role)) continue;
    if (def.skip_paths?.some((p) => getRegex(p, 'i').test(file.rel))) continue;
    const { match } = def;
    // file_regex narrows generic config files only; MCP configs and tool
    // descriptions (the Shield scans those) always qualify.
    if (match.file_regex && file.role === 'config' && !getRegex(match.file_regex, 'i').test(norm.plain)) continue;
    const exclude = match.exclude_regex ? getRegex(match.exclude_regex, 'i') : null;
    const keep = (text: string): boolean => {
      if (exclude && exclude.test(text)) return false;
      if (match.validate === 'base64-text' && !isBase64Text(text)) return false;
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
          span: `${def.id} ran out of time on this file`,
          fix: `This file made the ${def.id} check run too long, which can be a deliberate attack on the scanner. Review the file by hand. ${def.fix}`,
        });
      } else {
        const seen = new Set<number>();
        mine.forEach((jobIndex, k) => {
          const toPlain = k === 0 || !vis ? (i: number) => i : (i: number) => vis.map[i] ?? i;
          for (const [index, text] of results?.[jobIndex] ?? []) {
            if (!keep(text)) continue;
            const at = toPlain(index);
            if (seen.has(at)) continue;
            seen.add(at);
            const { line, col } = offsetToPosition(norm.original, at);
            findings.push({ ...base, line, col, span: truncateSpan(text) });
          }
        });
      }
    }
    // ── unicode_class ────────────────────────────────────────────────────────
    if (match.unicode_class && match.unicode_class.length > 0) {
      // Adjacent hidden characters are one finding: a payload of 37 tag
      // characters is one hidden message, not 37 problems.
      let run: UnicodeHit[] = [];
      const flush = (): void => {
        const first = run[0];
        if (!first) return;
        const { line, col } = offsetToPosition(norm.original, first.offset);
        findings.push({ ...base, line, col, span: joinEscapes(run) });
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
    }
    // ── json_path (+ optional value_regex filter) ────────────────────────────
    if (match.json_path) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(norm.original);
      } catch {
        continue; // not valid JSON: skip silently
      }
      let results: unknown[];
      try {
        results = JSONPath({ path: match.json_path, json: parsed as object }) as unknown[];
      } catch {
        continue;
      }
      const valueFilter = match.value_regex
        ? new RegExp(match.value_regex, 'i')
        : null;

      for (const val of results) {
        if (val === undefined || val === null) continue;
        const text = typeof val === 'string' ? val : JSON.stringify(val);
        if (valueFilter && !valueFilter.test(text)) continue;
        if (!keep(text)) continue;
        const { line, col } =
          typeof val === 'string' ? locateJsonValue(norm.original, val) : { line: 1, col: 1 };
        findings.push({ ...base, line, col, span: truncateSpan(text) });
      }
    }
  }

  return findings;
}
