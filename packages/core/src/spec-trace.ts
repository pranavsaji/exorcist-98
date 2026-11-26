/**
 * m13-kiro-evidence (KE-22 to KE-24): trace requirement IDs to test names.
 * Pure functions only; scripts/spec-trace.mjs does the file reading.
 *
 * A requirement ID is `<PREFIX>-<n>` (PREFIX is 2 to 4 capital letters) at the
 * start of an acceptance-criterion line, after a list marker (`1.`, `-` or `*`).
 * Virus-rule IDs (`EX-001`) are never requirement IDs, so older specs are not traced. A test is traced to an ID when its name starts with it.
 */

export interface IdDiff {
  /** IDs the spec declares that no test name starts with. */
  missingTests: string[];
  /** IDs a test name starts with that the spec does not declare. */
  extraTests: string[];
}

/**
 * A criterion line: a list marker (`1.`, `-`, `*`), then `<PREFIX>-<n>` and a
 * space, as in m10 (`1. KG-1 WHEN ...`) and m13 (`1. KE-1 WHEN ...`). `n` has no
 * leading zero. `EX` is the virus-rule prefix (`EX-001`) and never a requirement ID.
 */
const LINE_ID = /^\s*(?:\d+\.|[-*])\s+(?!EX-)([A-Z]{2,4})-([1-9]\d*)\s/;

/** The prefix of the first line-start requirement ID in a requirements.md, or null when it has none. */
export function detectIdPrefix(requirementsMd: string): string | null {
  for (const line of requirementsMd.split(/\r?\n/)) {
    const m = LINE_ID.exec(line);
    if (m?.[1]) return m[1];
  }
  return null;
}

/** Every `<prefix>-<n>` that starts a line of the requirements document. */
export function extractRequirementIds(requirementsMd: string, prefix: string): Set<string> {
  const ids = new Set<string>();
  for (const line of requirementsMd.split(/\r?\n/)) {
    const m = LINE_ID.exec(line);
    if (m?.[1] === prefix && m[2] !== undefined) ids.add(`${prefix}-${m[2]}`);
  }
  return ids;
}

/**
 * Every `<prefix>-<n>` that a test name starts with. A name may start with
 * several IDs separated by spaces or commas (`KG-1 KG-5 title`); all count.
 */
export function extractTestedIds(testNames: readonly string[], prefix: string): Set<string> {
  const ids = new Set<string>();
  const lead = new RegExp(`^\\s*((?:${prefix}-\\d+(?!\\w)[\\s,:]*)+)`);
  for (const name of testNames) {
    const m = lead.exec(name);
    if (m?.[1] === undefined) continue;
    for (const id of m[1].matchAll(/\d+/g)) ids.add(`${prefix}-${id[0]}`);
  }
  return ids;
}

const byNumber = (a: string, b: string): number => {
  const na = Number(a.slice(a.lastIndexOf('-') + 1));
  const nb = Number(b.slice(b.lastIndexOf('-') + 1));
  return na - nb || (a < b ? -1 : a > b ? 1 : 0);
};

/** Set difference in both directions, each sorted by prefix then number, no duplicates. */
export function diffIds(specIds: ReadonlySet<string>, testIds: ReadonlySet<string>): IdDiff {
  return {
    missingTests: [...specIds].filter((id) => !testIds.has(id)).sort(byNumber),
    extraTests: [...testIds].filter((id) => !specIds.has(id)).sort(byNumber),
  };
}

/** 0 only when every diff is empty in both directions, otherwise 1. */
export function specTraceExitCode(diffs: readonly IdDiff[]): 0 | 1 {
  return diffs.every((d) => d.missingTests.length === 0 && d.extraTests.length === 0) ? 0 : 1;
}
