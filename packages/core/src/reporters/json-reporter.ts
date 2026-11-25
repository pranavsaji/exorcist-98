import { z } from 'zod';
import type { Finding, ScanStats } from '../types.js';
import { SCANNER_VERSION } from '../version.js';
import { redactFindings } from '../redact-secrets.js';

const ScanStatsSchema = z.object({
  filesScanned:  z.number().int().nonnegative(),
  filesSkipped:  z.number().int().nonnegative(),
  findingsTotal: z.number().int().nonnegative(),
  durationMs:    z.number().nonnegative(),
});

const FindingSchema = z.object({
  source:   z.enum(['signature', 'heuristic']),
  ruleId:   z.string(),
  title:    z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  file:     z.string(),
  line:     z.number(),
  col:      z.number(),
  span:     z.string(),
  owasp:    z.array(z.string()),
  fix:      z.string(),
}).passthrough();

const SuppressedSchema = z.object({
  baseline: z.number().int().nonnegative(),
  inline:   z.array(z.object({ ruleId: z.string(), file: z.string(), line: z.number(), reason: z.string() })),
  rejected: z.array(z.object({ ruleId: z.string(), file: z.string(), line: z.number(), cause: z.string() })),
});
export type SuppressedSummary = z.infer<typeof SuppressedSchema>;
export const ScanReportSchema = z.object({
  version:   z.literal('1'),
  createdAt: z.string().datetime(),
  // Which scanner made the report and what it scanned (L-033). Optional, so
  // older reports still validate.
  scanner:   z.object({ name: z.string(), version: z.string() }).optional(),
  target:    z.string().optional(),
  stats:     ScanStatsSchema,
  findings:  z.array(FindingSchema),
  // Findings hidden by the baseline or inline directives. Optional (m9).
  suppressed: SuppressedSchema.optional(),
});

export type ScanReport = z.infer<typeof ScanReportSchema>;

export function toJson(findings: Finding[], stats: ScanStats, meta: { target?: string; suppressed?: SuppressedSummary } = {}): ScanReport {
  const report = {
    version:   '1' as const,
    createdAt: new Date().toISOString(),
    scanner:   { name: 'Exorcist 98', version: SCANNER_VERSION },
    ...(meta.target ? { target: meta.target } : {}),
    ...(meta.suppressed ? { suppressed: meta.suppressed } : {}),
    stats,
    // Secrets are never written in full (m7-precision).
    findings: redactFindings(findings),
  };
  // Validate at runtime — throws if our own output is malformed
  return ScanReportSchema.parse(report);
}
