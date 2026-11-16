// Public surface of @exorcist-98/core
// Internal modules (normalizer, walker, llm internals) are not re-exported.

export { scanRepo } from './scanner/orchestrator.js';
export { toJson, ScanReportSchema } from './reporters/json-reporter.js';
export { toSarif } from './reporters/sarif-reporter.js';
export { loadDefinitions } from './definitions/loader.js';
export { DefinitionLoadError } from './definitions/schema.js';

export type { ScanOptions, ScanEvent, ScanStats } from './types.js';
export type { Finding, SignatureFinding, HeuristicFinding, FileRole, Severity, RepoFile } from './types.js';
export type { VirusDefinition } from './definitions/schema.js';
export type { ScanReport } from './reporters/json-reporter.js';
export type { SarifLog } from './reporters/sarif-reporter.js';
