import { JSONPath } from 'jsonpath-plus';
import type { RepoFile, SignatureFinding, Severity } from '../types.js';
import type { NormalizedText } from '../normalizer.js';
import type { VirusDefinition } from '../definitions/schema.js';

const MAX_SPAN = 120;

// Cache compiled regexes to avoid recompilation per file
const regexCache = new Map<string, RegExp>();

function getRegex(ruleId: string, pattern: string): RegExp {
  const cached = regexCache.get(ruleId);
  if (cached) return cached;
  const re = new RegExp(pattern, 'gi');
  regexCache.set(ruleId, re);
  return re;
}

function offsetToPosition(text: string, offset: number): { line: number; col: number } {
  const before = text.slice(0, offset);
  const line = (before.match(/\n/g) ?? []).length + 1;
  const lastNl = before.lastIndexOf('\n');
  const col = lastNl === -1 ? offset + 1 : offset - lastNl;
  return { line, col };
}

function truncateSpan(s: string): string {
  if (s.length <= MAX_SPAN) return s;
  return s.slice(0, MAX_SPAN) + '…';
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
      const re = getRegex(def.id, match.regex);
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(norm.plain)) !== null) {
        const { line, col } = offsetToPosition(norm.original, m.index);
        findings.push({
          ...base,
          line,
          col,
          span: truncateSpan(m[0]),
        });
      }
    }

    // ── unicode_class ────────────────────────────────────────────────────────
    if (match.unicode_class && match.unicode_class.length > 0) {
      for (const hit of norm.hiddenUnicode) {
        if (match.unicode_class.includes(hit.class)) {
          const { line, col } = offsetToPosition(norm.original, hit.offset);
          const cpHex = hit.codePoint > 0xFFFF
            ? `\\u{${hit.codePoint.toString(16).toUpperCase()}}`
            : `\\u${hit.codePoint.toString(16).toUpperCase().padStart(4, '0')}`;
          findings.push({ ...base, line, col, span: cpHex });
        }
      }
    }

    // ── json_path ────────────────────────────────────────────────────────────
    if (match.json_path) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(norm.original);
      } catch {
        continue; // not valid JSON — skip silently
      }
      let results: unknown[];
      try {
        results = JSONPath({ path: match.json_path, json: parsed as object }) as unknown[];
      } catch {
        continue;
      }
      for (const val of results) {
        if (val !== undefined && val !== null) {
          findings.push({
            ...base,
            line: 1,
            col:  1,
            span: truncateSpan(String(val)),
          });
        }
      }
    }
  }

  return findings;
}
