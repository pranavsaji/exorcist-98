import { randomUUID } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import simpleGit from "simple-git";
import { scanRepo } from "@exorcist-98/core";
import type { Finding } from "@exorcist-98/core";
import { definitionsDir, hauntedRepoDir } from "./paths";
import { buildSnippet } from "./snippet";
import type { ScanEventMsg, WebFinding } from "./protocol";

export type ScanTarget =
  | { kind: "haunted-repo"; display: string }
  | { kind: "github"; display: string; cloneUrl: string };

export type CloneFn = (cloneUrl: string, dir: string) => Promise<void>;

export type ScanServiceOptions = {
  clone?: CloneFn;
  maxFindings?: number;
};

const DEFAULT_MAX_FINDINGS = 500;
const GENERIC_FATAL = "The scan could not be completed.";
const GENERIC_FILE_ERROR = "This file could not be read.";

const GIT_ENV_ALLOWLIST = [
  "PATH",
  "HOME",
  "LANG",
  "LC_ALL",
  "TMPDIR",
  "SYSTEMROOT",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "NO_PROXY",
  "https_proxy",
  "http_proxy",
  "no_proxy",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
];

/**
 * Environment for the git subprocess: an allowlist, never the whole process
 * environment. This keeps cloud credentials out of git and avoids simple-git
 * refusing to run when variables such as GIT_PAGER are set.
 */
export function gitEnv(
  source: Readonly<Record<string, string | undefined>> = process.env,
): Record<string, string> {
  const env: Record<string, string> = { GIT_TERMINAL_PROMPT: "0" };
  for (const key of GIT_ENV_ALLOWLIST) {
    const v = source[key];
    if (v !== undefined) env[key] = v;
  }
  return env;
}

async function defaultClone(cloneUrl: string, dir: string): Promise<void> {
  const git = simpleGit({ timeout: { block: 60_000 } }).env(gitEnv());
  await git.clone(cloneUrl, dir, ["--depth", "1", "--single-branch"]);
}

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
  return base;
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
    } else {
      const dir = join(tmpdir(), `exorcist-${randomUUID()}`);
      cleanup = () => rm(dir, { recursive: true, force: true });
      await (options.clone ?? defaultClone)(target.cloneUrl, dir);
      root = dir;
    }

    // The Haunted Repo folder also holds its own test helpers; only the
    // planted EX-NNN samples are part of the demo.
    const include = (rel: string): boolean =>
      target.kind === "haunted-repo" ? /^EX-\d{3}-/.test(rel) : true;

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
  } catch {
    yield { type: "fatal", message: GENERIC_FATAL };
  } finally {
    if (cleanup) await cleanup().catch(() => undefined);
  }
}
