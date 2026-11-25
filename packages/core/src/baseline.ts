// Baseline: the findings a team has accepted for now (.exorcist-baseline.json).
// Pure apart from the sha256 call. Entries hold no span text and no secret.
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { redactFinding } from './redact-secrets.js';
import type { Finding } from './types.js';

export const BASELINE_VERSION = 1;

export const BaselineEntrySchema = z.object({
  ruleId:      z.string().min(1),
  file:        z.string().min(1),
  fingerprint: z.string().regex(/^[0-9a-f]{32}$/),
  line:        z.number().int().min(0),
}).strict();

export const BaselineSchema = z.object({
  version: z.literal(BASELINE_VERSION),
  entries: z.array(BaselineEntrySchema),
}).strict();

export type BaselineEntry = z.infer<typeof BaselineEntrySchema>;
export type Baseline = z.infer<typeof BaselineSchema>;
export type BaselineParse = { ok: true; baseline: Baseline } | { ok: false; error: string };

/** sha256 (first 32 hex) of ruleId, file and the redacted, whitespace-collapsed span. Line and column are not used. */
export function fingerprintOf(f: Finding): string {
  const span = redactFinding(f).span.replace(/\s+/g, ' ');
  return createHash('sha256').update(`${f.ruleId}\0${f.file}\0${span}`).digest('hex').slice(0, 32);
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** A baseline of the given findings, sorted so the same findings give the same file. No timestamp. */
export function buildBaseline(findings: readonly Finding[]): Baseline {
  const entries: BaselineEntry[] = findings.map(f => ({
    ruleId: f.ruleId, file: f.file, fingerprint: fingerprintOf(f), line: f.line,
  }));
  entries.sort((a, b) =>
    cmp(a.file, b.file) || cmp(a.ruleId, b.ruleId) || cmp(a.fingerprint, b.fingerprint) || a.line - b.line);
  return { version: BASELINE_VERSION, entries };
}

/** Parse and validate baseline file text. Never throws. */
export function parseBaseline(text: string): BaselineParse {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { ok: false, error: 'The baseline file is not valid JSON.' };
  }
  if (typeof raw === 'object' && raw !== null && !Array.isArray(raw) && 'version' in raw
      && (raw as { version: unknown }).version !== BASELINE_VERSION) {
    return { ok: false, error: `Unsupported baseline version (this build reads version ${BASELINE_VERSION}).` };
  }
  const parsed = BaselineSchema.safeParse(raw);
  if (!parsed.success) {
    return { ok: false, error: 'The baseline file does not have the expected shape.' };
  }
  return { ok: true, baseline: parsed.data };
}

/**
 * Split findings into active and baselined. Multiset match on ruleId, file and fingerprint:
 * each baseline entry covers one finding. Findings are consumed in (line, col) order; both
 * outputs keep the original order of the input.
 */
export function applyBaseline(
  findings: readonly Finding[],
  baseline: Baseline,
): { active: Finding[]; baselined: Finding[] } {
  const counts = new Map<string, number>();
  for (const e of baseline.entries) {
    const key = `${e.ruleId}\0${e.file}\0${e.fingerprint}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const order = findings.map((_, i) => i)
    .sort((a, b) => findings[a]!.line - findings[b]!.line || findings[a]!.col - findings[b]!.col || a - b);
  const covered = new Set<number>();
  for (const i of order) {
    const f = findings[i]!;
    const key = `${f.ruleId}\0${f.file}\0${fingerprintOf(f)}`;
    const left = counts.get(key) ?? 0;
    if (left > 0) {
      counts.set(key, left - 1);
      covered.add(i);
    }
  }
  const active: Finding[] = [];
  const baselined: Finding[] = [];
  findings.forEach((f, i) => (covered.has(i) ? baselined : active).push(f));
  return { active, baselined };
}
