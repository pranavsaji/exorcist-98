# Spec: m2-ui

Milestone M2. A Next.js web app in `apps/web` with an original haunted retro
desktop: a scan window with a live log, a results list, a finding detail window,
and a Threat Encyclopedia generated from `definitions/`. It uses the M1 engine
(`@exorcist-98/core`) through a streaming API route.

Out of scope for this spec: zip upload, sound (M4), SARIF download and badge
(M4), AWS deployment, the Shield and Quarantine Vault (M3), landing page (M4).

---

## REQ-01 App scaffold

1. `apps/web` is a Next.js 14 App Router app with Tailwind CSS and TypeScript
   strict mode (`tech.md`).
2. The app imports the engine through `@exorcist-98/core` (workspace
   dependency). No engine code is copied.
3. `pnpm -r build`, `pnpm -r typecheck` and `pnpm test` all pass from the root.
4. Dependencies added to `apps/web` are listed with a reason in `design.md`.

## REQ-02 Scan API route

1. `POST /api/scan` accepts JSON validated with zod: either
   `{ "target": "haunted-repo" }` or `{ "repoUrl": "https://github.com/owner/repo" }`.
2. `target: "haunted-repo"` scans the bundled `fixtures/haunted-repo/`
   directory. No path is ever taken from the request.
3. `repoUrl` must match a strict `https://github.com/<owner>/<repo>` pattern
   (letters, digits, `.`, `_`, `-`; optional `.git` or trailing slash). Anything
   else returns HTTP 400.
4. The response is a stream of newline-delimited JSON events
   (`application/x-ndjson`): `start`, `file`, `finding`, `error`, `done`,
   `fatal`.
5. Each `finding` event carries the engine finding plus a `snippet` with up to
   two lines of context on each side and the exact span position, with hidden
   Unicode revealed as visible markers.
6. A cloned repository is removed after the scan, even on failure. The clone
   uses `--depth 1 --single-branch` and a timeout.
7. Errors sent to the client are generic (`fatal` with a fixed message). Stack
   traces, paths and file contents are never sent or logged. Only the repo URL,
   counts and timings are logged.

## REQ-03 Event protocol

1. Event and request shapes are defined once as zod schemas in
   `apps/web/src/lib/protocol.ts` and used by both the route and the client.
2. A client-side NDJSON reader turns a byte stream into validated events. Any
   chunking of the same bytes yields the same events. Invalid lines are
   reported as a typed error, not thrown.

## REQ-04 Desktop shell

1. The home page is a desktop with icons (Scan, Virus Definitions, About), a
   taskbar with a Start button, window buttons and a clock.
2. Windows have a title bar, close and minimize buttons, and can be focused and
   dragged. Focus order and z-order are consistent.
3. Everything is reachable and operable by keyboard. Focus is visible.
4. The look is original: no real operating-system or antivirus brand assets, no
   brand fonts or logos (`ui.md`).

## REQ-05 Scan window

1. Inputs: a GitHub URL field, a "Scan" button, and a "Scan the Haunted Repo"
   button.
2. A green-on-black log (`role="log"`, polite) shows each file as it is
   scanned and each finding as it is found.
3. A progress bar fills as files are scanned. When a finding arrives it
   glitches ("possessed"); the glitch is disabled when the user prefers reduced
   motion.
4. The window shows final stats (files scanned, findings, duration) and an
   overall infection level.
5. A scan can be cancelled; starting a new scan cancels the previous one.

## REQ-06 Results list

1. Findings are listed worst first (critical, high, medium, low).
2. Each row shows the infection level as a text label plus a distinct shape
   icon (colour is never the only signal), a plain-language headline, the file
   and the line.
3. Selecting a row (mouse or keyboard) opens the finding detail window.

## REQ-07 Finding detail

1. Plain language first, security terms second: a headline such as "This file
   hides instructions for your AI", then the rule ID, title and OWASP mapping.
2. Shows file, line, column, severity, threat class and the fix.
3. Shows the code snippet with the exact quoted span highlighted. Hidden
   characters appear as visible markers such as `[U+200B]`.
4. Heuristic findings also show the rationale and confidence.

## REQ-08 Threat Encyclopedia

1. `/encyclopedia` lists every definition in `definitions/`.
2. `/encyclopedia/[id]` shows, for one definition: a plain-language summary of
   the attack, severity, OWASP mapping, the defanged example from the matching
   Haunted Repo fixture (hidden characters revealed), and the fix.
3. Unknown IDs return a 404 page.
4. Pages are generated from the files on disk, so adding a definition adds a
   page without editing the app.

## REQ-09 Accessibility and design rules

1. Keyboard navigation, visible focus rings, screen-reader labels and
   WCAG AA contrast for text.
2. Severity is always shown with a text label and a shape, never colour alone.
3. No sound in M2.

## REQ-10 Tests

All new logic has tests. Property-based tests (fast-check):

| ID | Property |
|----|----------|
| PBT-WEB-01 | Splitting an NDJSON byte stream at any positions yields the same events as parsing it whole. |
| PBT-WEB-02 | `revealHidden` output never contains a hidden code point, and leaves text without hidden characters unchanged. |
| PBT-WEB-03 | For any line (up to 100 characters, so nothing is trimmed) and any span on it, a snippet's `before + match + after` equals `revealHidden(line)` and `match` equals `revealHidden(span)`. |
| PBT-WEB-04 | A string accepted by `parseGithubUrl` always has the `https://github.com/owner/repo` shape; strings with extra path, query, credentials or other hosts are rejected. |
| PBT-WEB-05 | Findings sorted by `sortFindings` are never out of severity order. |

Other tests:

- Every definition in `definitions/` has a plain-language entry.
- Golden-path integration test: `POST /api/scan` with `haunted-repo` streams
  `start`, findings from at least 8 different rules with snippets, and ends
  with `done`.
- Presentational components render severity as text plus a shape.
- Invalid request bodies and non-GitHub URLs return 400.

## REQ-11 Documentation

1. `docs/KIRO_LOG.md` records the M2 spec and tests.
2. `docs/KNOWN_LIMITATIONS.md` gains an M2 section.
