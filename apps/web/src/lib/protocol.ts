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
  decoded:    z.string().max(500).optional(),
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

// ── The Haunted House Map (EX-023, m5-trifecta) ───────────────────────────────

export const CapabilitySchema = z.enum(['private-data', 'untrusted-input', 'exfiltration']);
export type Capability = z.infer<typeof CapabilitySchema>;

export const MapGhostSchema = z.object({
  name:         z.string().max(200),
  kind:         z.enum(['server', 'ability']),
  capabilities: z.array(CapabilitySchema).max(3),
  reasons:      z.array(z.object({
    capability: CapabilitySchema,
    ruleId:     z.string().max(20),
    label:      z.string().max(200),
    evidence:   z.string().max(300),
  })).max(40),
  autoApproved: z.boolean(),
});
export type MapGhostMsg = z.infer<typeof MapGhostSchema>;

const LegNames = z.array(z.string().max(200)).max(100);
export const ConfigMapSchema = z.object({
  file:     z.string().max(1000),
  ghosts:   z.array(MapGhostSchema).max(100),
  legs:     z.object({ 'private-data': LegNames, 'untrusted-input': LegNames, exfiltration: LegNames }),
  trifecta: z.boolean(),
  severity: z.enum(['critical', 'high']).nullable(),
  /** Quiet servers left out of the drawing and list (the verdict covers them all). */
  omitted:  z.number().int().nonnegative().optional(),
});
export type ConfigMapMsg = z.infer<typeof ConfigMapSchema>;

export const HauntedMapSchema = z.object({ configs: z.array(ConfigMapSchema).max(50) });
export type HauntedMapMsg = z.infer<typeof HauntedMapSchema>;

/** Largest exorcism patch the server sends (bytes of UTF-8). */
export const PATCH_MAX_BYTES = 1_048_576;

/**
 * The exorcism patch: a unified diff of the safe, mechanical fixes for this
 * scan's findings, built on the server by the same code as `exorcist exorcise`.
 * Sent once, as the last event of a successful scan.
 */
export const PatchEventSchema = z.object({
  type:    z.literal('patch'),
  patch:   z.string().max(PATCH_MAX_BYTES),
  /** Files in the patch. */
  files:   z.number().int().nonnegative(),
  /** Fixes in the patch. */
  fixes:   z.number().int().nonnegative(),
  /** Changed files left out because the patch reached PATCH_MAX_BYTES. */
  omitted: z.number().int().nonnegative(),
  /** Fixable findings that were left for a human (e.g. a version that could not be looked up). */
  skipped: z.number().int().nonnegative(),
});
export type PatchEvent = z.infer<typeof PatchEventSchema>;

export const ScanEventSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('start'),   target: z.string() }),
  // How many files the scan will look at, sent once before the first file (W-010).
  z.object({ type: z.literal('total'),   files: z.number().int().nonnegative() }),
  z.object({ type: z.literal('file'),    rel: z.string(), role: z.string() }),
  z.object({ type: z.literal('finding'), finding: WebFindingSchema, snippet: SnippetSchema }),
  z.object({ type: z.literal('error'),   file: z.string(), message: z.string() }),
  // Sent once, just before `done`, when the scan found MCP configs. Optional:
  // a stream without it (an older server) is still valid.
  z.object({ type: z.literal('map'),     map: HauntedMapSchema }),
  z.object({ type: z.literal('done'),    stats: ScanStatsSchema }),
  z.object({ type: z.literal('fatal'),   message: z.string() }),
  PatchEventSchema,
]);
export type ScanEventMsg = z.infer<typeof ScanEventSchema>;
