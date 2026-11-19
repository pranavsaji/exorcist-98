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
| L-001 | High | Verified | **The pre-commit secrets hook never flags anything.** The hook runs `pnpm --filter @exorcist-98/core exec ...`, which runs in `packages/core`. `git diff --cached --name-only` returns repo-root-relative paths, so `existsSync` fails and `scanFile` silently skips every file. (`pnpm exec` printed `cwd=.../packages/core`.) | Resolve staged paths against `git rev-parse --show-toplevel`. Add a test that stages a file with a fake key and expects exit 1. Make a missing file an error, not a skip. |
| L-002 | High | Verified | `findSecrets` ignores any key within 30 characters of an `EXAMPLE_*_DO_NOT_USE` placeholder, so a real key placed next to a placeholder is not reported. | Only skip a match when the matched text itself is, or sits inside, a placeholder token. Add a property test for "real key adjacent to placeholder". |
| L-003 | High | Unverified | **Hook file format was never checked against Kiro.** The four hooks in `.kiro/hooks/*.yaml` use a trigger and action schema I wrote from memory. Kiro may expect a different format or file name, in which case none of them fire. | Create each hook through the Kiro hooks UI, compare the generated file with ours, and rewrite ours to match. Capture a clip of one firing. |
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
| L-013 | Medium | Suspected | EX-003 flags any 40+ character base64-like run, so lockfile integrity hashes and embedded keys in `config` and `code` files are likely false positives. No benign corpus has been scanned. | Exclude lockfiles and known hash prefixes (`sha512-`), require a decode to text or a URL, and measure false positives on a corpus of real repos. |
| L-014 | Medium | Verified | No false-positive evaluation exists for any definition. Tests only prove that each rule fires on its own fixture and, for EX-001, 007, 009, 010, that a few benign inputs do not. | Build a benign corpus (popular repos' READMEs, configs, manifests) and add a regression test that counts findings. |
| L-015 | Medium | Verified | EX-011 checks four variable names (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, `DATABASE_URL`). The plan describes it as "secrets not covered by `.kiroignore`", which is not implemented. | Reuse the `findSecrets` patterns and check `.kiroignore` and `.gitignore` coverage. |
| L-016 | Medium | Verified | EX-006 only detects rug-pull language in a static file. Real rug-pull detection (a tool hash changing after approval) needs the Shield. | Implement in M3 (`packages/shield`). |
| L-017 | Low | Verified | EX-013 to EX-020 have no definitions. Fixtures exist for all 20. | Add definitions as the engine and Shield gain the needed capabilities. |
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
| L-040 | Medium | Unverified | **CI has never run.** The workflow targets Node 20 and pnpm 10, but all local work used Node 22. It re-installs in every job. | Push a branch and watch a run. Pin the pnpm version to the `packageManager` field. |
| L-041 | Low | Verified | The orchestrator idempotence property (PBT-ORC-01) from the M1 spec is not written. | Add the test. |
| L-042 | Low | Verified | `docs/KIRO_LOG.md` has guessed dates for M1 rows and no evidence of a hook firing. | Replace dates with real ones and record a clip. |
| L-045 | Medium | Verified | `packages/core/package.json` declares no dependencies. They live in the root `devDependencies`, so the package works inside the monorepo but would break if published or run through `npx exorcist`. | Move `zod`, `js-yaml`, `jsonpath-plus` and the AWS SDK into `packages/core` dependencies. |
| L-043 | Low | Verified | Several tests locate fixtures and definitions by counting `../` segments from the test file. | Export a `repoRoot()` helper from one test utility. |
| L-044 | Low | Verified | The Haunted Repo EX-001 fixture is the only fixture with literal control characters. Editors and some tools may strip them when the file is saved. It is now generated by `scripts/make-ex001-fixture.mjs`; tests (INT-DEF EX-001 and the route golden path) fail if the characters are missing. | Remaining: add a check in CI that regenerating the fixture produces no diff. |

## 6. Web app (M2)

| ID | Priority | Confidence | Limitation | Suggested fix |
|----|----------|------------|------------|---------------|
| W-001 | Medium | Partly fixed | A scripted Chrome 157 run (`pnpm e2e`, 20 checks) now covers: scan, results order, detail, every finding's highlight, keyboard focus ring, Escape, Start menu, minimize and restore, drag, real GitHub scan, cancel, reduced motion, encyclopedia and a narrow screen. **Not covered:** how the glitch animation looks in motion, screen readers, Safari and Firefox, touch input, and hands-on use by a person. | Do a manual pass with a screen reader and in Firefox and Safari. |
| W-002 | High | Unverified | **Hosting is undecided and the GitHub-clone path may not work on serverless.** `POST /api/scan` shells out to `git`, which is often missing from serverless runtimes. The route also reads `definitions/` and `fixtures/` from disk, which a deployment must include (or point `EXORCIST_ROOT` at). | Pick the host (Amplify, Vercel or a container), prove one real scan there, and fall back to the GitHub tarball API if `git` is unavailable. |
| W-003 | Medium | Verified | `POST /api/scan` has no rate limit, authentication or concurrency cap. Each GitHub scan clones to temporary disk with only a 60-second block timeout and no size cap. | Add rate limiting and a concurrency limit; cap clone size; reuse the L-007 work. |
| W-004 | Low | Fixed | Under 900 pixels wide the windows now fill the width and the desktop icons are hidden (the Start menu has the same entries). Checked at 390 pixels in Chrome. Windows still stack by z-order and are switched from the taskbar. | Consider a real mobile layout with tabs instead of stacked windows. |
| W-005 | Medium | Verified | Windows cannot be moved by keyboard (dragging uses the pointer). They can be focused, minimized and closed from the keyboard. | Add arrow-key move mode on the title bar. |
| W-006 | Medium | Partly fixed | `pnpm e2e` covers `Desktop`, `Window`, `Taskbar` and `useScan` through a real browser, but it is not run in CI and needs a built, running server, network access (it clones two public repos) and an installed Chrome. There are still no component-level interaction tests. | Run it in CI with a Chrome install; add a mock for the clone steps. |
| W-007 | Low | Mostly fixed | Highlights now work for multi-character hidden runs and for JSON strings with escaped quotes. A finding still has no highlight when its span came from entity-decoded text and no longer matches the file text (same root cause as L-010). The line is still shown. | Fix L-010 with an offset map. |
| W-008 | Medium | Verified | The Haunted Repo scan shows only `EX-NNN-*` files; the filter lives in `scan-service` and its summary stats are recomputed there. The engine itself would also scan the folder's README and test helpers. | Move the fixtures' test files out of `fixtures/haunted-repo/` or add an ignore file the engine understands. |
| W-009 | Medium | Verified | The server stops after 500 findings and says so; the browser keeps only the last 400 log lines. A repo with many findings is truncated. | Add paging, grouping by rule, and a download of the full report. |
| W-010 | Low | Verified | The progress bar is indeterminate while a scan runs, because the total number of files is not known up front. | Count files first or send a total with the `start` event. |
| W-011 | Low | Verified | Plain-language text exists for EX-001 to EX-012 only. Other rules (and heuristic findings with no signature) fall back to the rule title. | Add entries when EX-013 and later ship; a test already fails if a loaded definition has no entry. |
| W-012 | Low | Verified | The "Virus Definitions" icon and the detail link leave the desktop (the detail link opens a new tab; the icon navigates away and loses scan state). | Show the encyclopedia in a window. |
| W-013 | Low | Verified | Sound effects and the mute toggle required by `ui.md` are not built (planned for M4). | Add original sounds, muted by default, with a toggle. |
| W-014 | Low | Verified | `next build` rewrote `apps/web/tsconfig.json` (added `allowJs`). | Commit the generated value so the file stops changing. |
| W-015 | Low | Verified | Colour contrast was chosen with AA in mind but never measured. The "possessed" glitch and focus rings were not checked against a screen reader or high-contrast mode. | Run axe and a manual screen-reader pass. |
| W-016 | Medium | Verified | **The Haunted Repo scan is not deterministic in size.** A run reports 36 findings; adding or editing a rule or fixture changes the count, and nothing pins the expected set. The golden path only checks that all 12 shipped rules fire. | Add a snapshot of (rule, file, line) for the Haunted Repo and review changes to it deliberately. |
| W-017 | Low | Verified | `pnpm e2e` writes screenshots to `e2e-output/` (gitignored) and hard-codes Chrome's macOS path unless `CHROME_PATH` is set. | Read the path from `playwright-core`'s channel option or auto-detect per platform. |
| W-018 | Low | Verified | Windows can overlap the desktop icons and each other at 900 to 1300 pixels wide; the layout was only checked at 1366 and 390. | Check 1024 and 768 and adjust the starting positions. |

---

## Appendix: how limitations were found

Items marked *Verified* were confirmed by reading the code or running a
command (L-001 by running `pnpm exec` and comparing the working directory).
Items marked *Suspected* follow from the code but no failing input has been
produced yet. Items marked *Unverified* describe code that has never run
against the real system it targets.
