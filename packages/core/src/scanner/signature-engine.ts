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

export function runSignatures(
  file: RepoFile,
  norm: NormalizedText,
  defs: VirusDefinition[],
): SignatureFinding[] {
  const findings: SignatureFinding[] = [];

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

    // ── regex ────────────────────────────────────────────────────────────────
    if (match.regex) {
      const re = getRegex(match.regex, 'gi');
      const seen = new Set<number>();
      const scan = (text: string, toPlain: (i: number) => number): void => {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) {
          if (m[0].length === 0) { re.lastIndex++; continue; } // avoid infinite loop on empty matches
          if (!keep(m[0])) continue;
          const at = toPlain(m.index);
          if (seen.has(at)) continue;
          seen.add(at);
          const { line, col } = offsetToPosition(norm.original, at);
          findings.push({ ...base, line, col, span: truncateSpan(m[0]) });
        }
      };
      scan(norm.plain, (i) => i);
      // L-005: the same text with hidden characters removed, mapped back.
      const vis = norm.visible;
      if (vis) scan(vis.text, (i) => vis.map[i] ?? i);
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
