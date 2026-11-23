import { readFile } from 'node:fs/promises';
import { loadDefinitions } from '../definitions/loader.js';
import { canariesPath, findCanaryInText, isCanaryHome, lineColOf, loadCanariesFile } from '../canary.js';
import type { Canary } from '../canary.js';
import type { VirusDefinition } from '../definitions/schema.js';
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

const EX022_DEFAULTS = {
  owasp: ['LLM02:2025 Sensitive Information Disclosure', 'ASI05 Sensitive Data Leakage'],
};

/**
 * EX-022: a canary token found in a scanned file. Each token is unique to one
 * install and lives only in its trap file and the records file, so a copy
 * anywhere else (raw or disguised) was made by something that read the trap.
 * The matching is in code, since only the records know the tokens; the
 * definition supplies the OWASP mapping and the encyclopedia text.
 */
export function canaryFindings(text: string, rel: string, canaries: readonly Canary[], def?: VirusDefinition): Finding[] {
  if (canaries.length === 0 || isCanaryHome(rel)) return [];
  return findCanaryInText(text, canaries).map((h) => {
    const { line, col } = lineColOf(text, h.index);
    return {
      source: 'signature' as const,
      ruleId: 'EX-022',
      title: 'Canary token copied out of its trap',
      severity: 'critical' as const,
      file: rel,
      line,
      col,
      // The exact text found, as it appears in the file.
      span: text.slice(h.index, Math.min(h.end, h.index + 120)),
      owasp: def?.owasp ?? EX022_DEFAULTS.owasp,
      fix:
        `A trap token has been copied out of its trap (${h.canary.file}${h.shape === 'raw' ? '' : `, ${h.shape}`}). ` +
        'Something that read the trap wrote it here: find the instruction that asked for it (a prompt injection in a file, a tool result or a dependency) and remove it, ' +
        'delete this copy, then replant fresh traps: exorcist canary --remove && exorcist canary plant',
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
  const records: Canary[] = canaries.ok ? canaries.canaries : [];
  const ex022 = defs.find((d) => d.id === 'EX-022');
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
      const traps = canaryFindings(text, file.rel, records, ex022);

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
