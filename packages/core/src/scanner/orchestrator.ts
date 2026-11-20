import { readFile } from 'node:fs/promises';
import { loadDefinitions } from '../definitions/loader.js';
import { walkRepo } from '../walker.js';
import { normalize } from '../normalizer.js';
import { runSignatures } from './signature-engine.js';
import { runHeuristics } from './heuristic-engine.js';
import type { RepoFile, Finding, ScanEvent, ScanOptions } from '../types.js';

export type { ScanOptions } from '../types.js';

function dedupeKey(f: Finding): string {
  return `${f.ruleId}:${f.file}:${f.line}:${f.col}`;
}

function deduplicate(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = dedupeKey(f);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function* scanRepo(
  root:    string,
  options: ScanOptions,
): AsyncIterable<ScanEvent> {
  const defs = await loadDefinitions(options.definitionsDir);
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

      const deduped = deduplicate([...sigs, ...heurs]);

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
