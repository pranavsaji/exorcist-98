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

export function runSignatures(
  file: RepoFile,
  norm: NormalizedText,
  defs: VirusDefinition[],
): SignatureFinding[] {
  const findings: SignatureFinding[] = [];

  for (const def of defs) {
    if (def.enabled === false) continue;
    if (!def.applies_to.includes(file.role)) continue;

    const { match } = def;
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
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(norm.plain)) !== null) {
        const { line, col } = offsetToPosition(norm.original, m.index);
        findings.push({ ...base, line, col, span: truncateSpan(m[0]) });
        if (m[0].length === 0) re.lastIndex++; // avoid infinite loop on empty matches
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
        const { line, col } =
          typeof val === 'string' ? locateJsonValue(norm.original, val) : { line: 1, col: 1 };
        findings.push({ ...base, line, col, span: truncateSpan(text) });
      }
    }
  }

  return findings;
}
