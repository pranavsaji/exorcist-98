# Requirements Document
## Introduction
Spec m14-first-five-minutes: make the first five minutes of a judge's visit work, and make CI install what we publish. Source: `TASK-judges.md` (moved to `docs/kiro-briefs/` when the work is done).
Five areas: a recording at the top of the README, a page for someone with five minutes (`docs/START-HERE.md`), a sourced comparison with tools that already exist, a CI job that installs the published packages, and the usual finish (facts, log, commit).
## Glossary
- **Published shape**: the packages as a user gets them: tarballs from `npm pack`, installed into an empty project, with no workspace links.
- **Live links**: the three web demos `/?demo=haunted`, `/?demo=rug-pull` and `/?demo=trifecta` on `https://exorcist-98.vercel.app`.
- **Pitch**: the line `**The 90s antivirus, resurrected for AI coding agents.**` at the top of `README.md`.
- **Criterion ID**: `FF-n.m`. The name of every test that checks a criterion starts with its ID.
## Requirements
### Requirement 1: (FF-1) A moving picture at the top of the README
**User Story:** As a judge opening the repository, I want to see the product work in 21 seconds before I read anything, so that I know what it does.
#### Acceptance Criteria
FF-1.1 `docs/media/rug-pull-demo.gif` is the first thing under the pitch in `README.md`, as a Markdown image.
FF-1.2 Its alt text says what happens in it: a trusted tool changes its description, the same attack with and without the Shield, "compromised" against "protected".
FF-1.3 A caption directly under it links the live rug-pull demo (`/?demo=rug-pull`) and names the ending, "Result: protected".
FF-1.4 The Touch ID placeholder comment and the Shield console image after it are unchanged and still in that order.
FF-1.5 `README.md` stays short: at most 115 lines.
FF-1.6 Our own scan of `README.md` and of `docs/START-HERE.md` is `Verdict: CLEAN` with exit code 0.
FF-1.7 The file is a real GIF (starts with `GIF8`) of at most 2.5 MB.
### Requirement 2: (FF-2) docs/START-HERE.md
**User Story:** As someone with five minutes, I want one page that tells me what to open, what to run and what I should see, so that I can check each claim myself.
#### Acceptance Criteria
FF-2.1 `docs/START-HERE.md` exists and `README.md` links it within its first 14 lines.
FF-2.2 A "60 seconds, nothing to install" part lists the three live links, each with what to look for (the POSSESSED verdict, "Result: protected.", the EX-027 hold).
FF-2.3 A "5 minutes on your own machine" part gives `npx -y @exorcist-98/cli scan .`, the Kiro Power import URL and `exorcist init --kiro`.
FF-2.4 A scenario table has one row per demo or attack with four cells (scenario, how to run it, what Exorcist 98 does, expected result). The expected results for the Haunted Repo (exit 1, the number of threats from `docs/facts.json`, "Verdict: POSSESSED") and for a clean folder match what the built CLI prints.
FF-2.5 A table answers four judging questions (potential impact, how Kiro was used, design, what is new), each with at least two links into this repository, and every linked path exists.
FF-2.6 The honest limits are exactly three bullets and link `docs/KNOWN_LIMITATIONS.md`.
FF-2.7 Every relative link in `README.md`, `docs/START-HERE.md` and `docs/REFERENCE.md` resolves to a file or folder that exists, and every `#anchor` to a heading that exists.
FF-2.8 The site footer links `docs/START-HERE.md` on the product page, the how-we-used-Kiro page and the framed pages (Threat Encyclopedia), and the desktop's About window links it too.
FF-2.9 `docs/START-HERE.md` is in the list of documents whose numbers `scripts/facts.mjs` writes and checks, and quotes at least one number through a marker.
### Requirement 3: (FF-3) How this differs from tools that already exist
**User Story:** As a reviewer who knows the field, I want an honest, sourced comparison, so that I can see what is new and where other tools do more.
#### Acceptance Criteria
FF-3.1 `docs/REFERENCE.md` has a table with Exorcist 98 and at least six existing tools: Snyk Agent Scan (mcp-scan), Lakera Guard, a Semgrep ruleset, GitHub secret scanning, and at least two MCP proxies or firewalls.
FF-3.2 Every existing tool's row links the tool's own documentation as its source, and nothing is stated that the source does not say.
FF-3.3 A feature that could not be confirmed is written "Not documented", and a cell is never empty or a guess.
FF-3.4 The section says what Exorcist 98 adds (at least three points) and where another tool does more (at least five points).
FF-3.5 `README.md` summarises the section in two lines and links it.
FF-3.6 The earlier unsourced comparison ("as far as we can tell") is removed.
### Requirement 4: (FF-4) CI that installs the published shape
**User Story:** As a maintainer, I want CI to install what we publish and run it, so that a packaging mistake cannot reach npm.
#### Acceptance Criteria
FF-4.1 `exorcist --version` from the installed tarball equals the version in `packages/cli/package.json`.
FF-4.2 Scanning `fixtures/haunted-repo` with the installed CLI exits non-zero and prints "Verdict: POSSESSED".
FF-4.3 Scanning a clean temporary folder exits 0 and prints "Verdict: CLEAN".
FF-4.4 The installed MCP server answers `initialize` (with the package's version) and `tools/list` over stdio with exactly the tools `explain_finding`, `quarantine`, `scan_mcp_config` and `scan_repo`, which are the tools the server source registers.
FF-4.5 The tarballs are installed into an empty temporary project, and the installed packages are real folders, not links into the workspace.
FF-4.6 The logic is in `scripts/published-shape.mjs`, which runs on its own, prints one PASS or FAIL line per check and exits 0 only if every check passes.
FF-4.7 A missing build or a failing step is a failed check, never a pass, and the temporary folder is removed.
FF-4.8 Child processes get a temporary HOME and `EXORCIST_DIR` and none of the caller's tokens, so a run never touches the user's `~/.exorcist`.
FF-4.9 `.github/workflows/ci.yml` has a job `published-shape` that runs the script.
### Requirement 5: (FF-5) Finish
**User Story:** As the owner, I want the numbers, the log and the repository tidy, so that nothing in the documents is stale.
#### Acceptance Criteria
FF-5.1 `docs/KIRO_LOG.md` has one row for this spec, by the Kiro IDE agent, naming `TASK-judges.md`.
FF-5.2 The brief is moved to `docs/kiro-briefs/TASK-judges.md`.
FF-5.3 The spec folder has `requirements.md`, `design.md` and `tasks.md`, and the last task is the commit (not pushed).
FF-5.4 Every criterion above has a test whose name starts with its ID.
FF-5.5 `node scripts/facts.mjs --run-tests --docs` has been run, `pnpm -r typecheck` and `pnpm vitest run` pass from the repository root, and the web end-to-end run passes because the site changed.
