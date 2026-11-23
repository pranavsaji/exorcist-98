// Public surface of @exorcist-98/core
// Internal modules (walker, normalizer, llm internals) are not re-exported.

export { scanRepo, mapRepo, trifectaReport } from './scanner/orchestrator.js';
export type { MapRepoResult } from './scanner/orchestrator.js';
export { CAPABILITIES, classifyCapabilities, loadCapabilityRules, parseCapabilityRules, isOutsideProject, serverIdentities } from './capabilities.js';
export type { CapabilityRule, CapabilityRulesResult, ServerSpec, Classification } from './capabilities.js';
export { analyzeConfig, detectTrifecta, parseMcpConfig, parsePins, trifectaFinding, TRIFECTA_RULE_ID } from './trifecta.js';
export type { ConfigEntry, ParsedMcpConfig, TrifectaResult, ToolPins } from './trifecta.js';
export { scanText } from './scanner/scan-text.js';
export { toJson, ScanReportSchema } from './reporters/json-reporter.js';
export { toSarif } from './reporters/sarif-reporter.js';
export { toMarkdown } from './reporters/markdown-reporter.js';
export { toBadgeSvg, badgeStatus } from './reporters/badge.js';
export { loadDefinitions } from './definitions/loader.js';
export { DefinitionLoadError } from './definitions/schema.js';
export { findSecrets, findStagedSecrets, findPrivateKeyBlocks, redact } from './secrets-check.js';
export {
  newToken, isCanaryToken, canariesPath, loadCanariesFile, findCanaryInText, base64Needles, lineColOf, maskToken, isCanaryHome,
  findStagedCanaries, CanariesFileSchema, CanaryRecordSchema, CANARY_PREFIX, CANARY_TOKEN_RE_SOURCE, CANARY_TRAP_DIR, CANARY_RECORDS_FILE,
} from './canary.js';
export type { Canary, CanaryRecord, CanariesFile, CanaryHit, CanaryShape, CanariesResult, StagedCanaryHit, StagedCanaryResult } from './canary.js';
export { fetchGithubRepo, isSafeRef, readTar, safeRelativePath, writeEntries, DEFAULT_TAR_LIMITS } from './remote/tarball.js';
export type { TarLimits, TarEntry, ExtractResult, FetchLike } from './remote/tarball.js';
export { decodeHidden, displayMessage, truncateMessage, encodeAsTags, encodeAsVariationSelectors, decodeVsBytes, MAX_HIDDEN_RUNS, MAX_DECODED_CHARS, MAX_VS_BYTES } from './ouija.js';
export type { HiddenMessage, HiddenMessageKind } from './ouija.js';
export { plainFor, hasPlainEntry } from './plain.js';
export { decide as decideCommitGuard, isGitCommit } from './hook-guard.js';
export type { HookDecision } from './hook-guard.js';
export { extractReadPaths, decideRead, isReadTool, shownName, mustCheckFully, limitFor } from './on-access.js';
export type { OnAccessDecision, DecideReadOptions } from './on-access.js';
export { sha256File, sha256Bytes, readAllowedReads, addAllowedRead, allowedReadsLocation, allowKey, findProjectRoot, isInside, realPath } from './allowed-reads.js';
export type { AllowReadResult, AllowedRead, AllowedReadsLocation } from './allowed-reads.js';
export { isTimeoutFinding } from './scanner/signature-engine.js';

export type { ScanOptions, ScanEvent, ScanStats } from './types.js';
export type { Finding, SignatureFinding, HeuristicFinding, FileRole, Severity, RepoFile, Capability, CapabilityReason, MapGhost, ConfigMap, HauntedMap } from './types.js';
export type { VirusDefinition } from './definitions/schema.js';
export type { ScanReport } from './reporters/json-reporter.js';
export type { SarifLog } from './reporters/sarif-reporter.js';
export type { SecretHit, StagedHit, StagedResult } from './secrets-check.js';
export type { PlainEntry } from './plain.js';
export { SCANNER_VERSION } from './version.js';
export { walkRepo, classifyFile } from './walker.js';
export { readZip, DEFAULT_ZIP_LIMITS } from './remote/zip.js';
export type { ZipLimits, ZipResult } from './remote/zip.js';
export { BUNDLED_DEFINITIONS_VERSION, BUNDLED_DEFINITIONS_DATE } from './definitions/version.js';
export {
  DEFINITIONS_PUBLIC_KEY, DOWNLOAD_LIMIT_BYTES, DOWNLOAD_TIMEOUT_MS, MANIFEST_NAME, SIGNATURE_NAME,
  ManifestSchema, buildManifest, signManifest, buildTar, readBundleTar, checkBundle, validateDefinitionFiles,
  buildSignedBundle, collectDefinitionFiles, makeKeyPair, loadPrivateKey, publicKeyFingerprint,
  compareVersions, isValidVersion, versionDate, sha256,
  installedDefinitionsRoot, verifyInstalledSet, inspectInstalledSets, listInstalledSets, findActiveInstalledSet,
  activeDefinitions, installBundle, downloadBundle, readBundleFile, loadBundleSource, runLiveUpdate,
} from './liveupdate.js';
export type {
  Manifest, BundleFile, VerifiedBundle, InstalledSet, InspectedSet, ActiveDefinitions, LookupOptions,
  FetchLike as UpdateFetchLike, FetchResponse as UpdateFetchResponse,
} from './liveupdate.js';
