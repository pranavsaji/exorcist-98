import { readFile } from 'node:fs/promises';
import { loadDefinitions } from '../definitions/loader.js';
import { canariesPath, findCanaryInText, lineColOf, loadCanariesFile } from '../canary.js';
import type { CanaryRecord } from '../canary.js';
import { walkRepo } from '../walker.js';
import { normalize } from '../normalizer.js';
import { runSignatures } from './signature-engine.js';
import { runHeuristics } from './heuristic-engine.js';
import type { RepoFile, Finding, ScanEvent, ScanOptions } from '../types.js';

export type { ScanOptions } from '../types.js';

function dedupeKey(f: Finding): string {
  return `${f.ruleId}:${f.file}:${f.line}:${f.col}`;
}

/**
 * One finding per rule and position, and no AI (heuristic) finding on a line a
 * signature already reported in the same file: the signature is exact and
 * explains itself, so the heuristic one would only repeat it (L-019).
 */
export function deduplicate(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const signatureLines = new Set(findings.filter((f) => f.source === 'signature').map((f) => `${f.file}:${f.line}`));
  return findings.filter(f => {
    if (f.source === 'heuristic' && signatureLines.has(`${f.file}:${f.line}`)) return false;
    const key = dedupeKey(f);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * A canary token found in a scanned file (EX-022). The tokens are unique per
 * install, so a copy outside `.exorcist/` was made by something that read the
 * trap: proof of an attempted leak.
 */
export function canaryFindings(text: string, rel: string, records: readonly CanaryRecord[]): Finding[] {
  return findCanaryInText(text, records).map((h) => {
    const { line, col } = lineColOf(text, h.index);
    const span = h.shape === 'raw' ? h.record.token : text.slice(h.index, h.index + 60).split(/[\n\r]/)[0] ?? h.record.token;
    return {
      source: 'signature' as const,
      ruleId: 'EX-022',
      title: 'Canary token out of its trap',
      severity: 'critical' as const,
      file: rel,
      line,
      col,
      span: span.slice(0, 120),
      owasp: ['LLM02:2025 Sensitive Information Disclosure', 'ASI05 Sensitive Data Leakage'],
      fix: `A trap token from ${h.record.file} has been copied out of its trap. Find what copied it (a prompt injection in a file, a tool result or a dependency) and remove the instruction, then replant fresh traps with: exorcist canary plant`,
    };
  });
}

export async function* scanRepo(
  root:    string,
  options: ScanOptions,
): AsyncIterable<ScanEvent> {
  const defs = await loadDefinitions(options.definitionsDir);
  const canaries = loadCanariesFile(canariesPath(root));
  if (!canaries.ok) {
    yield { type: 'error', file: '.exorcist/canaries.json', message: canaries.error };
  }
  const records: CanaryRecord[] = canaries.ok ? canaries.canaries : [];
  const start = Date.now();
  let filesScanned = 0;
  let filesSkipped = 0;
  let findingsTotal = 0;

  for await (const file of walkRepo(root, options.maxFileSizeBytes)) {
    yield { type: 'file', file };

    try {
      const text = await readFile(file.path, 'utf8');
      const norm = normalize(text, file.role);
      const sigs = runSignatures(file, norm, defs);
      const heurs = options.bedrockClient
        ? await runHeuristics(file, norm, sigs, options.bedrockClient)
        : [];
      const traps = file.rel.replace(/\\/g, '/').startsWith('.exorcist/') ? [] : canaryFindings(text, file.rel, records);

      const deduped = deduplicate([...sigs, ...heurs, ...traps]);

      for (const finding of deduped) {
        findingsTotal++;
        yield { type: 'finding', finding };
      }
      filesScanned++;
    } catch (err) {
      filesSkipped++;
      yield { type: 'error', file: file.rel, message: String(err) };
    }
  }

  yield {
    type: 'done',
    stats: {
      filesScanned,
      filesSkipped,
      findingsTotal,
      durationMs: Date.now() - start,
    },
  };
}
