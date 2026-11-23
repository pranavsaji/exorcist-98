import { randomUUID } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdir } from "node:fs/promises";
import { fetchGithubRepo, readZip, scanRepo, walkRepo, writeEntries } from "@exorcist-98/core";
import type { Finding, HauntedMap } from "@exorcist-98/core";
import { definitionsDir, hauntedRepoDir } from "./paths";
import { buildSnippet } from "./snippet";
import type { HauntedMapMsg, ScanEventMsg, WebFinding } from "./protocol";

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
};

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

function toWebFinding(f: Finding): WebFinding {
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

/**
 * The map as sent to the page: only configs the scan shows, trifectas first,
 * at most MAX_MAP_CONFIGS of them. Null when nothing is left.
 */
export function toWebMap(map: HauntedMap, include: (rel: string) => boolean): HauntedMapMsg | null {
  const configs = map.configs
    .filter((c) => include(c.file))
    .sort((a, b) => Number(b.trifecta) - Number(a.trifecta) || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0))
    .slice(0, MAX_MAP_CONFIGS);
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
          snippet: buildSnippet(cachedText, f.line, f.col, f.span),
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
        yield { type: "done", stats };
      }
    }
  } catch (err) {
    yield { type: "fatal", message: err instanceof UserFacingError ? err.message : GENERIC_FATAL };
  } finally {
    if (cleanup) await cleanup().catch(() => undefined);
  }
}
