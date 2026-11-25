// Browser-safe entry point: reporters and plain-language text with no Node
// imports, for use in web pages. Everything here is also exported from
// "@exorcist-98/core" for Node callers.
export { toSarif } from './reporters/sarif-reporter.js';
export type { SarifLog } from './reporters/sarif-reporter.js';
export { toMarkdown } from './reporters/markdown-reporter.js';
export { toBadgeSvg, badgeStatus } from './reporters/badge.js';
export type { BadgeStatus } from './reporters/badge.js';
export { redactSecretText, redactFinding, redactFindings, redactionMarker, containsSecret } from './redact-secrets.js';
export { plainFor, hasPlainEntry } from './plain.js';
export type { PlainEntry } from './plain.js';
export { decodeHidden, displayMessage, truncateMessage, encodeAsTags, encodeAsVariationSelectors, decodeVsBytes, MAX_HIDDEN_RUNS, MAX_DECODED_CHARS, MAX_VS_BYTES } from './ouija.js';
export type { HiddenMessage, HiddenMessageKind } from './ouija.js';
export type { Finding, ScanStats, Severity, Capability, CapabilityReason, MapGhost, ConfigMap, HauntedMap } from './types.js';
