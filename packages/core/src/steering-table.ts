/**
 * m13-kiro-evidence (KE-36): the steering table lists every file under
 * `.kiro/steering/` and nothing else. Pure comparison only; the caller reads the
 * directory.
 */
export interface SteeringTableDiff {
  /** Files in the directory that the table does not list. */
  missing: string[];
  /** Files the table lists that are not in the directory. */
  extra: string[];
  /** Files the table lists more than once. */
  duplicated: string[];
  /** True only when `missing`, `extra` and `duplicated` are all empty. */
  complete: boolean;
}

/** Compare a directory listing with the file names a table claims, as sets, ignoring order. */
export function compareSteeringTable(directoryFiles: readonly string[], tableFiles: readonly string[]): SteeringTableDiff {
  const inDir = new Set(directoryFiles);
  const inTable = new Set(tableFiles);
  const seen = new Set<string>();
  const dup = new Set<string>();
  for (const f of tableFiles) {
    if (seen.has(f)) dup.add(f);
    seen.add(f);
  }
  const missing = [...inDir].filter((f) => !inTable.has(f)).sort();
  const extra = [...inTable].filter((f) => !inDir.has(f)).sort();
  const duplicated = [...dup].sort();
  return { missing, extra, duplicated, complete: missing.length + extra.length + duplicated.length === 0 };
}
