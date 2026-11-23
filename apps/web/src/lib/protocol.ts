import { z } from 'zod';

// ── Request ───────────────────────────────────────────────────────────────────

export const ScanRequestSchema = z.union([
  z.object({ target: z.literal('haunted-repo') }).strict(),
  z.object({ repoUrl: z.string().max(200) }).strict(),
]);
export type ScanRequest = z.infer<typeof ScanRequestSchema>;

// ── Events (server to client, newline-delimited JSON) ─────────────────────────

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low']);
export type Severity = z.infer<typeof SeveritySchema>;

export const SnippetLineSchema = z.object({
  n:      z.number().int().positive(),
  before: z.string(),
  match:  z.string(),
  after:  z.string(),
});
export type SnippetLine = z.infer<typeof SnippetLineSchema>;

export const SnippetSchema = z.object({ lines: z.array(SnippetLineSchema) });
export type Snippet = z.infer<typeof SnippetSchema>;

export const WebFindingSchema = z.object({
  source:     z.enum(['signature', 'heuristic']),
  ruleId:     z.string(),
  title:      z.string(),
  severity:   SeveritySchema,
  file:       z.string(),
  line:       z.number().int().positive(),
  col:        z.number().int().positive(),
  span:       z.string(),
  owasp:      z.array(z.string()),
  fix:        z.string(),
  // Ouija decoder (m5-ouija): the message hidden in an invisible-text run,
  // at most 500 characters. Attacker text, displayed only.
  decoded:    z.string().optional(),
  rationale:  z.string().optional(),
  confidence: z.enum(['high', 'medium', 'low']).optional(),
});
export type WebFinding = z.infer<typeof WebFindingSchema>;

export const ScanStatsSchema = z.object({
  filesScanned:  z.number().int().nonnegative(),
  filesSkipped:  z.number().int().nonnegative(),
  findingsTotal: z.number().int().nonnegative(),
  durationMs:    z.number().nonnegative(),
});
export type WebScanStats = z.infer<typeof ScanStatsSchema>;

export const ScanEventSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('start'),   target: z.string() }),
  // How many files the scan will look at, sent once before the first file (W-010).
  z.object({ type: z.literal('total'),   files: z.number().int().nonnegative() }),
  z.object({ type: z.literal('file'),    rel: z.string(), role: z.string() }),
  z.object({ type: z.literal('finding'), finding: WebFindingSchema, snippet: SnippetSchema }),
  z.object({ type: z.literal('error'),   file: z.string(), message: z.string() }),
  z.object({ type: z.literal('done'),    stats: ScanStatsSchema }),
  z.object({ type: z.literal('fatal'),   message: z.string() }),
]);
export type ScanEventMsg = z.infer<typeof ScanEventSchema>;
