# Design Document
## Overview
Mostly documents, one script and one small web component. No new dependency and no new network call at run time. The comparison was written from each tool's own documentation, read on 2026-11-25.
## Architecture
```
README.md ── gif, caption, START-HERE link, two-line comparison
docs/START-HERE.md ── 60 s links · 5 min commands · scenario table · judging map · limits
docs/REFERENCE.md ── "How this differs from tools that already exist" (table + adds + does more)
scripts/published-shape.mjs ── pack → install in empty project → run → judge
.github/workflows/ci.yml ── job `published-shape` runs the script
apps/web: components/SiteFooter.tsx ── used by RetroFrame, /product, /how-kiro; link in the About window
```
## Components and Interfaces
### README
The GIF and its caption sit directly under the pitch, then one bold line to START-HERE, then the badges. The Touch ID placeholder comment is untouched. The comparison is two lines in "What it protects you from". Tests find the pitch by its text and read the next non-empty lines, so a later edit that pushes the picture down fails FF-1.1.
### START-HERE
Plain sentences first, commands second. The scenario table carries only claims a test can check: the Haunted Repo row and the clean row are compared with the built CLI's real output (exit code, threat count from `facts.json`, verdict line). Numbers come through `<!--f:key-->` markers, and `scripts/facts.mjs` lists the page in `DOCS`, so `--check` fails when one goes stale. The judging table links paths, and a test resolves each one.
### Comparison
Columns: what it looks at, runs between agent and server, catches a changed tool, where it runs and what leaves the machine, source. Rules:
- A cell states what the linked page says. If the page does not say it, the cell says "Not documented".
- The last column is the tool's own documentation, never a blog about it. The Exorcist 98 row links this repository.
- "What Exorcist 98 adds" lists only differences that hold against every row. A difference that does not (per-call checking against MCPTrust, a flow rule against Invariant and mcp-fence) is not claimed; the second list says where the other tool does more.
The unsourced section it replaces ("as far as we can tell") said no other tool checks before every call and no other tool has a built-in flow rule. mcp-fence and MCPTrust document pinning and blocking, and Invariant and mcp-fence document flow rules, so those claims were dropped.
### The published-shape script
`runPublishedShapeCheck({ root, build, keep, log })` returns `{ ok, checks, dir }` and never throws for a failed check.
1. Build `dist/` for each package only if it is missing (`--no-build` makes that an error). It does not rebuild an existing `dist/`, because a parallel test run rebuilds the MCP server by deleting `dist/` first.
2. `npm pack --ignore-scripts --json --pack-destination <tmp>` in each package (as `scripts/release.sh` does), with up to three tries.
3. Empty project with only a `package.json`; `npm install --ignore-scripts --no-package-lock <two tarballs>`. Both packages bundle everything they need, so nothing else is fetched.
4. Check that both installed packages are real folders (`lstat`), run the `bin` files named in each `package.json` with `node`, with a clean environment (`cleanEnv`: temporary HOME, `EXORCIST_DIR`, no tokens).
5. `--version`, a scan of `fixtures/haunted-repo` from the checkout, a scan of a temporary clean folder, then a stdio session with the MCP server: `initialize`, `notifications/initialized`, `tools/list` as newline-delimited JSON. `judgeMcpAnswers` is a pure function so a wrong tool list or version can be tested without a server.
6. Remove the temporary folder unless `--keep`.
Checks are `{ id, name, ok, detail }`, and the detail says what was seen (an exit code, the printed version, the tool names).
### Site footer
`SiteFooter` is a `<footer aria-label="Site footer">` with two links on the `on-desk` style that other static-page links use (white text on the desktop background, underlined). It is rendered by `RetroFrame` (every Threat Encyclopedia page), the product page and the how-we-used-Kiro page. The About window on the desktop gets a third link next to the existing ones. `START_HERE_URL` is the GitHub URL of the page on `main`.
## Data Models
One new shape: a check result, `{ id: string; name: string; ok: boolean; detail: string }`, and the run result `{ ok: boolean; checks: Check[]; dir: string | undefined }` (typed in `scripts/published-shape.d.mts`). The comparison table is a Markdown table with a fixed six-column header, which the tests read.
## Correctness Properties
### Property 1: A check that cannot run is a failure
For any step of `runPublishedShapeCheck` that throws or times out, the result has at least one failed check and `ok` is false, so the script never exits 0 without having looked. Validates FF-4.7.
### Property 2: The documents state only what a test or a source backs
Scenario results are compared with real CLI output, links resolve, and a comparison cell that no source confirms says "Not documented". Validates FF-2.4, FF-2.7 and FF-3.3.
### Property 3: A requirement without a test fails the suite
Every criterion ID in `requirements.md` appears at the start of a test name. Validates FF-5.4.
## Error Handling
`npm pack` is tried up to three times. A timeout, a bad exit code or an unexpected JSON line from a child process becomes the `detail` of a failed check; no error crosses the module boundary as an exception.
## Testing Strategy
- `packages/cli/src/__tests__/first-five-minutes.test.ts`: FF-1, FF-2.1 to FF-2.7, FF-2.9, FF-3 and FF-5. It runs the built CLI for FF-1.6 and FF-2.4.
- `packages/cli/src/__tests__/published-shape.test.ts`: FF-4. One test runs the real pack and install; others test the pure parts.
- `apps/web/src/__tests__/site-footer.test.tsx`: FF-2.8.
- FF-5.4 reads `requirements.md` and fails if a criterion has no test whose title starts with its ID.
- The web end-to-end run (`pnpm e2e`) is run because the site changed.
## Risks
- The comparison goes stale as tools change. The page says when it was read and tells the reader to check the source.
- `npm pack` and `npm install` need npm on the PATH. Node 20 and later ship it, and so does the CI image.
