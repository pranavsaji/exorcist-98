import { z } from 'zod';
import type { Finding, ScanStats } from '../types.js';

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

export const ScanReportSchema = z.object({
  version:   z.literal('1'),
  createdAt: z.string().datetime(),
  stats:     ScanStatsSchema,
  findings:  z.array(FindingSchema),
});

export type ScanReport = z.infer<typeof ScanReportSchema>;

export function toJson(findings: Finding[], stats: ScanStats): ScanReport {
  const report = {
    version:   '1' as const,
    createdAt: new Date().toISOString(),
    stats,
    findings,
  };
  // Validate at runtime — throws if our own output is malformed
  return ScanReportSchema.parse(report);
}
