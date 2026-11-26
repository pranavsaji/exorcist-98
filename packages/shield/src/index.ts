export { canonicalJson, toolFingerprint } from './hash.js';
export type { ToolDef } from './hash.js';
export { LineSplitter, parseLine, errorResponse, toolErrorResult, JsonRpcMessageSchema } from './jsonrpc.js';
export type { JsonRpcMessage } from './jsonrpc.js';
export { PolicySchema, DEFAULT_POLICY, loadPolicy, hostAllowed } from './policy.js';
export type { Policy } from './policy.js';
export {
  StateSchema, emptyState, loadState, saveState, serverState, appendAlert, approveTool, approveHost, approveServer,
  statePath, policyPath, alertsPath, vaultPath,
} from './state.js';
export type { State, ServerState, Alert, ApproveResult } from './state.js';
export { inspectCall, inspectResult, inspectTool, collectStrings, hostsIn, extractResultText } from './inspect.js';
export { ShieldEngine, readsSensitivePath } from './engine.js';
export {
  SessionGuard, MemorySessionStore, FileSessionStore, SessionRecordSchema, assessSession, grantSession, liveSessions, sessionSummary, boundFacts,
  resolveSessionKey, psLookup, isLauncher, isSessionKey, sessionsPath, SESSION_RULE_ID, SESSION_TTL_MS,
} from './session.js';
export type { Fact, FactKind, Grant, SessionRecord, SessionRead, SessionStore, Assessment, ProcInfo, ProcLookup } from './session.js';
export type { Action, EngineOptions, StateIO } from './engine.js';
export { blockedReason, sanitizeReason, buildReason, macOsAuth, resolveRelease, AVAILABLE_SCRIPT, VERIFY_SCRIPT } from './os-auth.js';
export type { OsVerdict, OsAuth, Release, Spawner, MacOsAuthOptions } from './os-auth.js';
export { runProxy } from './proxy.js';
export { EventLog, EventTail, ShieldEventSchema, parseEventLines, eventsPath, oldEventsPath, MAX_EVENT_BYTES, MAX_LINE_BYTES } from './events.js';
export type { ShieldEvent, CallShieldEvent, EngineEvent, EventBody, EventLogOptions, ParsedLines } from './events.js';
export {
  HeadRecordSchema, canonicalize, eventHash, verifyChain, headPath, genesisPath, readGenesis, loadOrCreateGenesis, readHead, writeHeadAtomic, verifyLogDir,
} from './chain.js';
export type { Genesis, ChainFields, ChainedShieldEvent, HeadRecord, BreakReason, ChainStatus, VerifyOptions, ChainResult } from './chain.js';
export { AiReview, findingsFor } from './ai-review.js';
export type { AiJudge, AiLabel, AiFindings } from './ai-review.js';
export { launchFingerprint, checkLaunch, packageSpec, specIsPinned, launchEntryOf, loaderEnvKeys, configLabel, LOADER_ENV } from './launch.js';
export type { LaunchPin, LaunchCheck, LaunchEntry, LaunchEntryResult } from './launch.js';
export { detectParaphrase } from './paraphrase.js';
export type { ParaphraseVerdict, Signal } from './paraphrase.js';
export { runRemoteProxy, checkRemoteUrl, SseParser } from './remote.js';
export type { RemoteProxyOptions } from './remote.js';
export { desktopNotifier, notifyCommand, throttle, cleanText } from './notify.js';
export type { Notifier } from './notify.js';
export { findDefinitionsDir, findStateDir } from './locate.js';
export type { DefinitionsLookup } from './locate.js';
export type { ProxyOptions } from './proxy.js';
export { quarantineServer, quarantineFile, listEntries, getEntry, diffEntry, restoreEntry, backupAndRewrite } from './vault.js';
export type { VaultEntry, VaultResult, EditedFile } from './vault.js';
export { wrapConfig, unwrapConfig, isWrapped } from './wrap.js';
export type { McpConfig, WrapOptions } from './wrap.js';
export { newToken, canariesPath, canariesFileFor, plantCanaries, loadCanaries, removeCanaries, findCanary, TRAPS as CANARY_TRAPS } from './canary.js';
export type { Canary, CanaryRecord, CanaryShape, PlantOptions, PlantResult, RemoveResult as CanaryRemoveResult } from './canary.js';
export {
  LockSchema, LockToolSchema, LockServerSchema, buildLock, serializeLock, parseLock, diffLock, descriptionPatch, pinsToLock,
  lockExpectations, seedFromLock, findLockFile, lockDescription, lockUrl, LOCK_FILE, DESCRIPTION_CHARS,
} from './lockfile.js';
export type { Lock, LockServer, LockTool, ServerListing, LockChange, LockChangeKind, ParseLockResult, SeedResult, LockExpectations } from './lockfile.js';
