import { randomUUID } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdir } from "node:fs/promises";
import { exorciseRepo, fetchGithubRepo, readZip, redactFinding, redactSecretText, registryLookup, scanRepo, toUnifiedDiff, walkRepo, writeEntries } from "@exorcist-98/core";
import type { ConfigMap, Finding, HauntedMap, VersionAnswer, VersionLookup } from "@exorcist-98/core";
import { definitionsDir, hauntedRepoDir } from "./paths";
import { buildSnippet, redactSnippet } from "./snippet";
import { PATCH_MAX_BYTES } from "./protocol";
import type { ConfigMapMsg, HauntedMapMsg, PatchEvent, ScanEventMsg, WebFinding } from "./protocol";

export type ScanTarget =
  | { kind: "haunted-repo"; display: string }
  | { kind: "github"; display: string; owner: string; repo: string; ref?: string }
  /** An uploaded ZIP (L-032). Unpacked to a temporary folder that is always removed. */
  | { kind: "upload"; display: string; zip: Buffer };

/** Puts a copy of the repository in `dir`. Throws with a plain message on failure. */
export type CloneFn = (target: { owner: string; repo: string; ref?: string }, dir: string) => Promise<void>;

export type ScanServiceOptions = {
  clone?: CloneFn;
  maxFindings?: number;
  /**
   * Version lookups for the EX-010 fix in the exorcism patch. Default: the
   * public npm and PyPI registries (3 s each, answers cached for 10 minutes),
   * or none when EXORCIST_OFFLINE=1. Null: none.
   */
  lookup?: VersionLookup | null;
};

/** Findings kept for the exorcism patch (only the first ones count beyond this). */
const MAX_PATCH_FINDINGS = 20_000;
const versionCache = new Map<string, { at: number; answer: VersionAnswer }>();
const sharedLookup = registryLookup({ timeoutMs: 3000, cache: versionCache });

function defaultLookup(): VersionLookup | null {
  return process.env["EXORCIST_OFFLINE"] === "1" ? null : sharedLookup;
}

/** The patch with any secret on a diff line replaced by a marker. */
function redactPatch(patch: string): string {
  return patch.split("\n").map(redactSecretText).join("\n");
}

/** The exorcism patch for a scanned folder, capped at PATCH_MAX_BYTES. */
export async function buildPatchEvent(
  root: string,
  findings: readonly Finding[],
  lookup: VersionLookup | null,
): Promise<PatchEvent> {
  const results = await exorciseRepo(root, findings, { lookup, maxLookups: 20 });
  const p = toUnifiedDiff(results, { maxBytes: PATCH_MAX_BYTES });
  const skipped = results.reduce((n, r) => n + r.notes.length, 0);
  // Secrets are never sent in full, not even as diff context (m7-precision).
  return { type: "patch", patch: redactPatch(p.patch), files: p.files, fixes: p.fixes, omitted: p.omitted, skipped };
}

const DEFAULT_MAX_FINDINGS = 500;
const GENERIC_FATAL = "The scan could not be completed.";
const GENERIC_FILE_ERROR = "This file could not be read.";

/**
 * Download the repository as a tarball over HTTPS (no git binary, no
 * subprocess), with size, file-count and time limits.
 */
async function defaultClone(t: { owner: string; repo: string; ref?: string }, dir: string): Promise<void> {
  const r = await fetchGithubRepo({ owner: t.owner, repo: t.repo, dir, ...(t.ref ? { ref: t.ref } : {}) });
  if (!r.ok) throw new UserFacingError(r.error);
}

/** An error whose message is safe and useful to show to the user. */
export class UserFacingError extends Error {}

function toWebFinding(raw: Finding): WebFinding {
  // Secrets are never sent in full (m7-precision).
  const f = redactFinding(raw);
  const base: WebFinding = {
    source: f.source,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    file: f.file,
    line: f.line,
    col: f.col,
    span: f.span,
    owasp: f.owasp,
    fix: f.fix,
  };
  if (f.source === "heuristic") {
    return { ...base, rationale: f.rationale, confidence: f.confidence };
  }
  return { ...base, ...(f.decoded !== undefined ? { decoded: f.decoded } : {}) };
}

const MAX_MAP_CONFIGS = 50;
const MAX_MAP_GHOSTS = 100;
const MAX_MAP_NAME = 120;
const clipName = (s: string): string => (s.length > MAX_MAP_NAME ? `${s.slice(0, MAX_MAP_NAME - 1)}\u2026` : s);

/**
 * One config as sent to the page. The verdict (trifecta, severity, which legs
 * are filled) is computed by the engine on every server; only the drawing is
 * bounded. Ghosts with powers come first, so a config padded with harmless
 * filler still shows the dangerous ones, and `omitted` says how many quiet
 * ones were left out.
 */
function toWebConfig(c: ConfigMap): ConfigMapMsg {
  const ranked = [...c.ghosts.filter((g) => g.capabilities.length > 0), ...c.ghosts.filter((g) => g.capabilities.length === 0)];
  const ghosts = ranked.slice(0, MAX_MAP_GHOSTS).map((g) => ({ ...g, name: clipName(g.name) }));
  const leg = (names: string[]): string[] => names.slice(0, MAX_MAP_GHOSTS).map(clipName);
  return {
    file: c.file.slice(0, 1000),
    ghosts,
    legs: { 'private-data': leg(c.legs['private-data']), 'untrusted-input': leg(c.legs['untrusted-input']), exfiltration: leg(c.legs.exfiltration) },
    trifecta: c.trifecta,
    severity: c.severity,
    ...(ranked.length > ghosts.length ? { omitted: ranked.length - ghosts.length } : {}),
  };
}

/**
 * The map as sent to the page: only configs the scan shows, trifectas first,
 * at most MAX_MAP_CONFIGS of them. Null when nothing is left.
 */
export function toWebMap(map: HauntedMap, include: (rel: string) => boolean): HauntedMapMsg | null {
  const configs = map.configs
    .filter((c) => include(c.file))
    .sort((a, b) => Number(b.trifecta) - Number(a.trifecta) || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0))
    .slice(0, MAX_MAP_CONFIGS)
    .map(toWebConfig);
  return configs.length > 0 ? { configs } : null;
}

/**
 * Scan a target and yield protocol events. Never throws: any failure becomes a
 * generic `fatal` event, so no paths, stack traces or file contents reach the
 * client. A cloned repo is always removed.
 */
export async function* scanTarget(
  target: ScanTarget,
  options: ScanServiceOptions = {},
): AsyncGenerator<ScanEventMsg> {
  const maxFindings = options.maxFindings ?? DEFAULT_MAX_FINDINGS;
  let cleanup: (() => Promise<void>) | null = null;

  yield { type: "start", target: target.display };

  try {
    let root: string;
    if (target.kind === "haunted-repo") {
      root = hauntedRepoDir();
    } else if (target.kind === "upload") {
      const dir = join(tmpdir(), `exorcist-${randomUUID()}`);
      cleanup = () => rm(dir, { recursive: true, force: true });
      const z = readZip(target.zip);
      if (!z.ok) throw new UserFacingError(z.error);
      if (z.entries.length === 0) throw new UserFacingError("The ZIP file has no files that can be scanned.");
      await mkdir(dir, { recursive: true });
      writeEntries(dir, z.entries);
      root = dir;
    } else {
      const dir = join(tmpdir(), `exorcist-${randomUUID()}`);
      cleanup = () => rm(dir, { recursive: true, force: true });
      await (options.clone ?? defaultClone)({ owner: target.owner, repo: target.repo, ...(target.ref ? { ref: target.ref } : {}) }, dir);
      root = dir;
    }

    // The Haunted Repo folder also holds its own test helpers; only the
    // planted EX-NNN samples are part of the demo.
    const include = (rel: string): boolean =>
      target.kind === "haunted-repo" ? /^EX-\d{3}-/.test(rel) : true;

    // Count first (metadata only), so the page can show real progress (W-010).
    let total = 0;
    for await (const f of walkRepo(root)) if (include(f.rel)) total++;
    yield { type: "total", files: total };
    let emitted = 0;
    let found = 0;
    let filesSeen = 0;
    let capNoticeSent = false;
    let cachedFile = "";
    let cachedText = "";
    let completed = false;
    const forPatch: Finding[] = [];

    for await (const ev of scanRepo(root, {
      definitionsDir: definitionsDir(),
    })) {
      if (ev.type === "file") {
        if (!include(ev.file.rel)) continue;
        filesSeen++;
        yield { type: "file", rel: ev.file.rel, role: ev.file.role };
      } else if (ev.type === "finding") {
        if (!include(ev.finding.file)) continue;
        found++;
        if (forPatch.length < MAX_PATCH_FINDINGS) forPatch.push(ev.finding);
        if (emitted >= maxFindings) {
          if (!capNoticeSent) {
            capNoticeSent = true;
            yield {
              type: "error",
              file: "",
              message: `Too many findings. Showing the first ${maxFindings}.`,
            };
          }
          continue;
        }
        emitted++;
        const f = ev.finding;
        if (f.file !== cachedFile) {
          cachedFile = f.file;
          cachedText = await readFile(join(root, f.file), "utf8").catch(
            () => "",
          );
        }
        yield {
          type: "finding",
          finding: toWebFinding(f),
          snippet: redactSnippet(buildSnippet(cachedText, f.line, f.col, f.span)),
        };
      } else if (ev.type === "error") {
        if (!include(ev.file)) continue;
        yield { type: "error", file: ev.file, message: GENERIC_FILE_ERROR };
      } else if (ev.type === "map") {
        const map = toWebMap(ev.map, include);
        if (map) yield { type: "map", map };
      } else {
        const stats =
          target.kind === "haunted-repo"
            ? {
                filesScanned: filesSeen,
                filesSkipped: 0,
                findingsTotal: found,
                durationMs: ev.stats.durationMs,
              }
            : ev.stats;
        // Summary only: no file contents are ever logged.
        console.log(
          JSON.stringify({
            scan: target.display,
            filesScanned: stats.filesScanned,
            findingsTotal: stats.findingsTotal,
            durationMs: stats.durationMs,
          }),
        );
        completed = true;
        yield { type: "done", stats };
      }
    }

    // The exorcism patch, built before any downloaded or uploaded copy is
    // removed. A failure here never turns a finished scan into a failed one.
    if (completed) {
      let patch: PatchEvent | null = null;
      try {
        patch = await buildPatchEvent(root, forPatch, options.lookup !== undefined ? options.lookup : defaultLookup());
      } catch {
        console.log(JSON.stringify({ scan: target.display, patch: "failed" }));
      }
      if (patch) yield patch;
    }
  } catch (err) {
    yield { type: "fatal", message: err instanceof UserFacingError ? err.message : GENERIC_FATAL };
  } finally {
    if (cleanup) await cleanup().catch(() => undefined);
  }
}
