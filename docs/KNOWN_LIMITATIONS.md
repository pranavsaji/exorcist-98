# Known limitations

A working list of gaps, shortcuts and unverified claims, so they can be
addressed later. Each item has an ID, a priority, how sure we are, and a
suggested fix.

- **Priority**: High (security or correctness risk), Medium (wrong or weak
  result in some cases), Low (polish, missing feature).
- **Confidence**: *Verified* (reproduced or shown by reading the code),
  *Suspected* (reasoned about but not tested), *Unverified* (never run).

When an item is fixed, change its status to `Fixed in <commit>` and keep the row.

---

## 1. Security controls

| ID | Priority | Confidence | Limitation | Suggested fix |
|----|----------|------------|------------|---------------|
| L-001 | High | Fixed | The pre-commit secrets check never flagged anything because staged paths were resolved from the wrong directory. Fixed: paths resolve against the git root. Tests stage a fake key in a throwaway repo, including when run from a subdirectory and as a real hook process. | Remaining: the hook reads the shell command from `tool_input`; the exact field name Kiro uses is unverified, so the script scans every string in `tool_input`. |
| L-002 | High | Fixed | A real key within 30 characters of a placeholder was ignored. Now only matches inside a `EXAMPLE_*_DO_NOT_USE` token are skipped. | None. |
| L-003 | High | Partly fixed | Hooks are now `.kiro/hooks/*.json` in the documented v1 format. **Seen firing in Kiro:** `spec-change` (`PostFileSave`, agent prompt), several times. **Tested and not firing:** `pre-commit-secrets` (`PreToolUse`, shell command). On 2026-11-18 a `git commit` of a staged fake key went through twice in this session, once with matcher `shell` and once with explicit tool ids, while the hook's command blocks correctly when run by hand (exit 2). So `PreToolUse` command hooks did not run in this client. **Mitigation:** a git `pre-commit` hook (`.githooks/pre-commit`, installed by `exorcist init`) blocks secrets for every commit, tested with real `git commit`. `definition-save` and `mcp-config-change` not yet observed. | Test `PreToolUse` in Kiro IDE (not this agent session) and in Kiro CLI; capture a clip of one hook firing. |
| L-004 | High | Suspected | **Regular expressions from definitions run on attacker-controlled text with no time limit.** Patterns such as EX-004 (`[\s\S]*?...[\s\S]*?`) can backtrack badly on a 1 MB file. Community-contributed definitions make this worse. | Run signature matching in a worker with a timeout, or use a linear-time regex engine (RE2). Add a ReDoS check when loading definitions. |
| L-005 | Medium | Verified | Regex rules run on `norm.plain`, which still contains hidden characters. A zero-width character inserted inside a phrase (`ig<U+200B>nore previous`) evades EX-002, EX-004, EX-005, EX-006 and EX-008. EX-001 would still flag the character. | Add a `stripped` view of the text with hidden characters removed and run regex rules on both views. |
| L-006 | Medium | Verified | The hidden-Unicode list is short. It misses U+2060 (word joiner), U+00AD (soft hyphen), U+180E, U+034F, variation selectors (U+FE00 to U+FE0F, U+E0100 to U+E01EF) and others. | Extend the ranges in `normalizer.ts` and add a fixture and test per class. |
| L-007 | Medium | Verified | `repoUrl` validation only checks that the string starts with `https://github.com/`. Owner and repo shape, length and odd characters are not validated. There is no clone timeout, size cap or rate limit. | Use a strict `owner/repo` pattern, set a clone timeout and size limit, add rate limiting at the API gateway. |

## 2. Detection quality

| ID | Priority | Confidence | Limitation | Suggested fix |
|----|----------|------------|------------|---------------|
| L-010 | Medium | Verified | **Regex findings can report the wrong line and column** when the file contains HTML entities. Matching runs on `norm.plain` (entities decoded, so shorter) but the position is computed on `norm.original` using the match offset. | Keep an offset map from `plain` to `original`, or match on `original` and decode per match. |
| L-011 | Medium | Verified | json_path findings locate the value by searching for its first occurrence in the file. A value that appears twice always maps to the first. Non-string values report 1:1. | Use a JSON parser that returns source positions (for example `jsonc-parser`). |
| L-012 | Medium | Verified | EX-010 inspects only `args[0:2]` of package-runner servers. A bare positional word in those slots (such as `stdio`) would be flagged, and a package in a later slot would be missed. | Parse runner flags properly (`-y`, `--package`) to find the package argument. |
| L-013 | Medium | Partly fixed | EX-003 flagged the base64 integrity hashes in `pnpm-lock.yaml`, which would have failed this repo's own CI scan. Found by dogfooding and fixed: `sha1-`/`sha256-`/`sha384-`/`sha512-` hashes and `base64,` data URIs are skipped. No wider benign corpus has been scanned, so other false positives are likely. | Scan a corpus of real repos and count findings (see L-014). |
| L-014 | Medium | Verified | No false-positive evaluation exists for any definition. Tests only prove that each rule fires on its own fixture and, for EX-001, 007, 009, 010, that a few benign inputs do not. | Build a benign corpus (popular repos' READMEs, configs, manifests) and add a regression test that counts findings. |
| L-015 | Medium | Verified | EX-011 checks four variable names (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, `DATABASE_URL`). The plan describes it as "secrets not covered by `.kiroignore`", which is not implemented. | Reuse the `findSecrets` patterns and check `.kiroignore` and `.gitignore` coverage. |
| L-016 | Medium | Fixed | EX-006 was only a wording check. The Shield now pins each tool's hash and hides a changed tool (tested with real processes). | See S-001: not yet run inside Kiro. |
| L-017 | Low | Partly fixed | EX-015 now has a definition, and EX-016 and EX-017 are enforced by the Shield. Still missing: EX-013 (typosquat), EX-014 (steering override), EX-018 (confused deputy), EX-019 (memory poisoning), EX-020 (suspicious Power). | Add them. |
| L-018 | Low | Verified | Hex-encoded payloads are not decoded (the plan lists hex). Base64 candidates are only used to decide whether to call the LLM, not as findings. | Add a hex decoder and decode-and-rescan for both encodings. |
| L-019 | Low | Verified | The finding dedupe key is `ruleId:file:line:col`. A signature and a heuristic finding for the same span are not merged. | Dedupe on file plus span overlap and keep the higher-confidence one. |

## 3. Heuristic layer (Amazon Bedrock)

| ID | Priority | Confidence | Limitation | Suggested fix |
|----|----------|------------|------------|---------------|
| L-020 | High | Unverified | **The real Bedrock client has never run.** All tests use `FakeBedrockClient`. The model IDs (`anthropic.claude-3-haiku-20240307-v1:0`, `anthropic.claude-3-5-sonnet-20241022-v2:0`) may be unavailable, retired, or need an inference profile in the chosen region. | Make model IDs configurable, run one real call in a smoke test, and handle throttling and timeouts. |
| L-021 | Medium | Verified | Heuristic findings take line, column, rule ID, severity and fix from the first signature finding in the file (or `HEU-000` and `high` if none). They do not point at the span the model quoted. | Locate `quoted_span` in the file and assign severity from the model's `threat_class`. |
| L-022 | Medium | Verified | Triage (Haiku) and judge (Sonnet) receive the same prompt, one call per file, and only the top span. Other suspicious spans in the same file are never judged. | Batch several spans per call and give the judge the triage verdict. |
| L-023 | Low | Verified | `ScanOptions.maxFileSizeBytes` is declared but never used. The walker hard-codes 1 MB. | Pass the option to `walkRepo`. |

## 4. API and deployment

| ID | Priority | Confidence | Limitation | Suggested fix |
|----|----------|------------|------------|---------------|
| L-030 | High | Unverified | The Lambda handler has only run with a mocked clone and a mocked scan. It has never cloned a real repo or been deployed. There is no infrastructure code (function, API Gateway, S3 bucket with a 24-hour lifecycle). | Add IaC (CDK or SAM), a bundling step that includes `definitions/`, and an integration test that clones a small public repo. |
| L-031 | Medium | Verified | The handler's default `DEFINITIONS_PATH` (`/var/task/definitions`) is not populated by any build step. | Copy `definitions/` into the bundle. |
| L-032 | Medium | Verified | Zip upload scanning (listed in the plan) is not implemented anywhere. | Add an upload route with size limits and zip-slip protection. |
| L-033 | Low | Verified | The JSON report has no repository identifier or scanner version. The SARIF version is hard-coded to `0.1.0`. | Include the repo URL and read the version from `package.json`. |

## 5. Tooling, CI and process

| ID | Priority | Confidence | Limitation | Suggested fix |
|----|----------|------------|------------|---------------|
| L-040 | Low | Fixed in d58a207 | CI now runs on GitHub with Node 22 and the pnpm version from `packageManager`; `test`, `build` and `e2e` were green on `d58a207`. Each job still re-installs dependencies. | Cache the pnpm store if runs get slow. |
| L-041 | Low | Verified | The orchestrator idempotence property (PBT-ORC-01) from the M1 spec is not written. | Add the test. |
| L-042 | Low | Partly fixed | `docs/KIRO_LOG.md` had guessed dates (11-19 and 11-20, later than the commits). Dates now match the commit dates. A hook firing is recorded in text but not on video. | Record a clip of `spec-change` firing. |
| L-045 | Medium | Fixed | `packages/core` now declares its own dependencies (zod, js-yaml, jsonpath-plus, simple-git, the Bedrock SDK). The CLI and MCP server are bundled with esbuild, so they need none at run time. | None. |
| L-043 | Low | Verified | Several tests locate fixtures and definitions by counting `../` segments from the test file. | Export a `repoRoot()` helper from one test utility. |
| L-044 | Low | Verified | The Haunted Repo EX-001 fixture is the only fixture with literal control characters. Editors and some tools may strip them when the file is saved. It is now generated by `scripts/make-ex001-fixture.mjs`; tests (INT-DEF EX-001 and the route golden path) fail if the characters are missing. | Remaining: add a check in CI that regenerating the fixture produces no diff. |

## 6. Web app (M2)

| ID | Priority | Confidence | Limitation | Suggested fix |
|----|----------|------------|------------|---------------|
| W-001 | Medium | Partly fixed | A scripted Chrome 157 run (`pnpm e2e`, 20 checks) now covers: scan, results order, detail, every finding's highlight, keyboard focus ring, Escape, Start menu, minimize and restore, drag, real GitHub scan, cancel, reduced motion, encyclopedia and a narrow screen. **Not covered:** how the glitch animation looks in motion, screen readers, Safari and Firefox, touch input, and hands-on use by a person. | Do a manual pass with a screen reader and in Firefox and Safari. |
| W-002 | High | Mostly fixed (M4) | GitHub scans now download the default branch as a tarball over HTTPS, so no `git` binary is needed. The app builds as a standalone server that ships `definitions/` and the Haunted Repo; a copy run outside the repository passed the full browser suite. **Still open: no host is chosen and there is no public URL.** | Pick a host (see `docs/DEPLOY.md`), deploy, and run `E2E_BASE=<url> pnpm e2e` against it. |
| W-003 | Medium | Verified | `POST /api/scan` has no rate limit, authentication or concurrency cap. Each GitHub scan clones to temporary disk with only a 60-second block timeout and no size cap. | Add rate limiting and a concurrency limit; cap clone size; reuse the L-007 work. |
| W-004 | Low | Fixed (M4) | Under 900 pixels wide the windows now fill the width and the desktop icons are hidden (the Start menu has the same entries). Checked at 390 pixels in Chrome. Windows still stack by z-order and are switched from the taskbar. | Consider a real mobile layout with tabs instead of stacked windows. |
| W-005 | Medium | Fixed (M4) | Windows move with Alt+arrow keys (Shift moves further); each window describes the keys to screen readers. Checked in the browser suite. | None. |
| W-006 | Medium | Partly fixed | `pnpm e2e` covers `Desktop`, `Window`, `Taskbar` and `useScan` through a real browser, but it is not run in CI and needs a built, running server, network access (it clones two public repos) and an installed Chrome. There are still no component-level interaction tests. | Run it in CI with a Chrome install; add a mock for the clone steps. |
| W-007 | Low | Mostly fixed | Highlights now work for multi-character hidden runs and for JSON strings with escaped quotes. A finding still has no highlight when its span came from entity-decoded text and no longer matches the file text (same root cause as L-010). The line is still shown. | Fix L-010 with an offset map. |
| W-008 | Medium | Verified | The Haunted Repo scan shows only `EX-NNN-*` files; the filter lives in `scan-service` and its summary stats are recomputed there. The engine itself would also scan the folder's README and test helpers. | Move the fixtures' test files out of `fixtures/haunted-repo/` or add an ignore file the engine understands. |
| W-009 | Medium | Verified | The server stops after 500 findings and says so; the browser keeps only the last 400 log lines. A repo with many findings is truncated. | Add paging, grouping by rule, and a download of the full report. |
| W-010 | Low | Verified | The progress bar is indeterminate while a scan runs, because the total number of files is not known up front. | Count files first or send a total with the `start` event. |
| W-011 | Low | Verified | Plain-language text exists for EX-001 to EX-012 only. Other rules (and heuristic findings with no signature) fall back to the rule title. | Add entries when EX-013 and later ship; a test already fails if a loaded definition has no entry. |
| W-012 | Low | Verified | The "Virus Definitions" icon and the detail link leave the desktop (the detail link opens a new tab; the icon navigates away and loses scan state). | Show the encyclopedia in a window. |
| W-013 | Low | Fixed (M4) | Sounds are synthesised with Web Audio (no audio files), muted by default, with a taskbar toggle stored in `localStorage`. Checked in the browser suite that it starts muted and survives a reload. Not checked: how the cues sound to a person. | Listen to each cue. |
| W-014 | Low | Verified | `next build` rewrote `apps/web/tsconfig.json` (added `allowJs`). | Commit the generated value so the file stops changing. |
| W-015 | Low | Verified | Colour contrast was chosen with AA in mind but never measured. The "possessed" glitch and focus rings were not checked against a screen reader or high-contrast mode. | Run axe and a manual screen-reader pass. |
| W-016 | Medium | Verified | **The Haunted Repo scan is not deterministic in size.** A run reports 36 findings; adding or editing a rule or fixture changes the count, and nothing pins the expected set. The golden path only checks that all 12 shipped rules fire. | Add a snapshot of (rule, file, line) for the Haunted Repo and review changes to it deliberately. |
| W-017 | Low | Verified | `pnpm e2e` writes screenshots to `e2e-output/` (gitignored) and hard-codes Chrome's macOS path unless `CHROME_PATH` is set. | Read the path from `playwright-core`'s channel option or auto-detect per platform. |
| W-018 | Low | Verified | Windows can overlap the desktop icons and each other at 900 to 1300 pixels wide; the layout was only checked at 1366 and 390. | Check 1024 and 768 and adjust the starting positions. |
| W-019 | Medium | Verified | **The Dockerfile has never been built.** The Docker daemon was not running during M4. | Run `docker build -t exorcist-98 .` and the browser suite against the container. |
| W-020 | Low | Verified | Tarball scans only cover the default branch (`HEAD`). Branch, tag and commit URLs are not supported, and private repositories cannot be scanned. | Accept `/tree/<ref>` URLs and pass the ref to codeload. |
| W-021 | Low | Verified | The `/product` page has no founder or LinkedIn link, which the startup bonus asks for. | Add your link. |

## 7. Shield, Vault, CLI, MCP server, Power and Action (M3)

| ID | Priority | Confidence | Limitation | Suggested fix |
|----|----------|------------|------------|---------------|
| S-001 | High | Unverified | **The Shield has never run inside Kiro.** Tested against a fake MCP server, the official SDK client and real processes. It now advertises `tools.listChanged` and sends `notifications/tools/list_changed` after `exorcist approve`, so a client that honours it re-lists without a reconnect (tested with real processes). Unknown: how Kiro shows a hidden tool and a blocked call, and whether it shows MCP stderr. | Wrap a real server in Kiro (needs `.kiro/settings/mcp.json`, see S-003) and capture a rug pull. |
| S-002 | High | Verified | **Nothing is published to npm, and the unscoped name is taken.** `exorcist` on npm is an unrelated source-map tool, so an earlier `exorcist init` default (`npx -y exorcist`) would have run someone else's package. Fixed: everything now uses `@exorcist-98/cli` and `@exorcist-98/mcp-server` (both names free on 2026-11-18). Publishing needs the npm org `exorcist-98` and your npm login. | Create the npm org, `pnpm --filter @exorcist-98/cli publish` and the same for the MCP server; then install the Power in Kiro. |
| S-003 | High | Verified | **`.kiro/settings/mcp.json` was not created.** Writing it was blocked by a permission rule, so this project's own MCP server is not registered in Kiro and `MCP servers: 1` in the log is not yet true. The MCP server itself works (tested with the SDK client). | Add the entry from the final message of the M3 work, or allow the write. |
| S-004 | Medium | Verified | "Ask the user" is not an interactive prompt. A risky call is refused with a message naming the exact `exorcist approve ...` command. After an approval the shield notifies the client (`tools/list_changed`). | Use MCP elicitation if Kiro supports it. |
| S-005 | Medium | Verified | Only local (stdio) servers can be wrapped. Remote servers (`url`) are left alone and are not protected. | Add an HTTP/SSE proxy mode. |
| S-006 | Medium | Verified | Pins use trust on first use: a tool that is malicious from the first moment but matches no rule is pinned. Only name, description and input schema are pinned, not the server's code or its results. | Pin package versions and hashes (EX-010), and offer a review step before the first pin. |
| S-007 | Medium | Verified | The host check only sees URLs written with `http://` or `https://`. Bare host names, IP addresses without a scheme, other schemes (ssh, ftp) and encoded URLs are not checked. A tool with network access of its own can send data without any URL in its arguments. | Check more forms; run untrusted servers in a sandbox. |
| S-008 | Medium | Verified | Secret detection covers three shapes (AWS access key, GitHub token, OpenAI-style key). Other credentials pass. | Add more patterns and entropy checks. |
| S-009 | Medium | Verified | Result inspection is pattern-based. A paraphrased injection ("pay no attention to what came before") passes. The AI heuristic layer is not part of the Shield or the CLI. | Route suspicious results through the Bedrock judge (see L-020). |
| S-010 | Medium | Verified | Requests the server sends to the agent (sampling, elicitation, roots) and its notifications are forwarded without inspection. | Inspect server-initiated requests. |
| S-011 | Medium | Verified | A server that prints logs to stdout breaks the protocol; the Shield drops those lines (with an alert). A very long line (over 16 MB) is dropped. | None needed; it is a server bug. |
| S-012 | Medium | Verified | Alerts go to stderr and `.exorcist/alerts.jsonl`. The user only sees them if Kiro shows MCP stderr or they run `exorcist alerts`. | Add a desktop or in-editor notification. |
| S-013 | Medium | Unverified | State lives in `.exorcist/` relative to the working directory. A server started by Kiro may not run in the project folder; `wrap` writes an absolute `--dir` from where it was run. | Always pass an absolute `--dir` (wrap does) and document it. |
| S-014 | Low | Verified | Restoring an MCP server flips only its `disabled` flag, so changes to that server's other settings made while it was quarantined are kept, and a server whose entry was deleted is recreated from the backup. | Fine; documented. |
| S-015 | Low | Unverified | The `pre-commit-secrets` and `guard-commit` hooks read the shell command from `tool_input` by looking at every string in it, because the exact field name Kiro uses was not found in the docs. | Confirm with a real firing (see L-003). |
| S-016 | Medium | Fixed in d58a207 | **The first run on GitHub failed.** CI: `pnpm/action-setup` refused because `version: 10` and `packageManager` were both set. Action: `package_json_file` with `github.action_path` gave "no pnpm version". Both read from GitHub's public check-run annotations. Fixed (pnpm from `packageManager` only; the Action installs it with npm from its own package.json), actions moved to current majors (checkout v7, setup-node v7, pnpm/action-setup v6, github-script v9, codeql-action v4, upload-artifact v7) and Node 22. Tests now pin both causes. CI and the Action's `scan` job were green on `d58a207`. | Open a pull request to exercise the comment step. |
| S-017 | Low | Verified | The dogfood scan in CI skips `fixtures`, `docs`, `definitions`, `.kiro/specs`, `packages` and test folders, so it covers about 67 files (agent instructions, hooks, Power, scripts, workflows). | Scan more once the false-positive rate is known (L-014). |
| S-018 | Low | Verified | `scan_repo` and the other MCP tools only accept paths inside the folder the server was started in (symlinks are resolved). The folder Kiro starts it in is unverified. | Confirm in Kiro. |
| S-019 | Low | Verified | `findDefinitionsDir` exists twice (CLI and MCP server). | Move it to one shared module. |
| S-020 | Low | Verified | `exorcist scan` runs signatures only. The Bedrock heuristic layer is not in the CLI. | Add `--ai` once L-020 is verified. |
| S-021 | High | Unverified | **The Crew app has never run inside Kiro Crew.** It is tested with unit tests and a stand-in gateway. Its own list of Crew assumptions (mount signature, backend port, proxy signature details) is in `pranavsaji/exorcist-98-crew` `docs/KNOWN_LIMITATIONS.md`. | Install Crew and work through C-001 to C-007 there. |

---

## Appendix: how limitations were found

Items marked *Verified* were confirmed by reading the code or running a
command (L-001 by running `pnpm exec` and comparing the working directory).
Items marked *Suspected* follow from the code but no failing input has been
produced yet. Items marked *Unverified* describe code that has never run
against the real system it targets.
