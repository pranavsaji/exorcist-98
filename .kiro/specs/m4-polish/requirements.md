# Spec: m4-polish

Milestone M4 from the plan: accessibility pass, sound (muted by default), empty
states, SARIF export and badge, startup landing page, the Crew app, plus the
deployment work that the "working web app URL" submission rule depends on.

## REQ-01 Sound

1. Original sounds only, synthesised with the Web Audio API (no audio files).
2. Muted by default. A taskbar toggle with `aria-pressed` turns sound on and off;
   the choice is stored locally and survives a reload.
3. Cues: a threat found (throttled so a burst of findings is one sound), a scan
   ending clean, a scan ending with threats, sound turned on.
4. Each cue is under one second and quiet.

## REQ-02 Reports and badge

1. After a scan, the results window offers SARIF (code scanning), Markdown (pull
   request), JSON and an SVG README badge. Reports are built in the page from the
   findings already shown; nothing is uploaded.
2. The reporters used in the page have no Node imports (`@exorcist-98/core/browser`)
   so the browser and the CLI share one implementation.
3. The badge says "exorcised" when clean, otherwise "possessed: N <worst level>".
   It is a self-contained SVG with `role="img"` and an accessible label.
4. `exorcist scan --format badge` writes the same SVG.

## REQ-03 Accessibility

1. Windows can be moved from the keyboard (Alt+arrow keys; Shift moves further).
   Each window describes its keyboard controls to screen readers.
2. Visible button text matches its accessible name (WCAG 2.5.3).
3. Every page, including new ones, passes an automated axe scan with 0
   violations in the browser test.
4. Empty states exist for the results and detail windows.

## REQ-04 Landing page

1. `/product` explains the problem, the four parts, who it is for, and plans.
   Anything not built is labelled as planned.
2. No invented customers, numbers or quotes. No third-party logos.
3. Linked from the desktop's About window and Start menu.

## REQ-05 Deployable web app

1. Scanning a GitHub repository needs no `git` binary: the default branch is
   downloaded as a tarball over HTTPS.
2. Tar extraction writes only regular files, never follows links, never writes
   outside the target folder, and enforces limits while reading: 25 MB
   compressed, 150 MB unpacked, 20,000 files, 1 MB per file, 30 seconds.
3. A truncated or malformed archive is an error, not a partial scan.
4. The web app builds as a standalone Node server that includes the
   definitions and the Haunted Repo. The server works when copied away from the
   monorepo.
5. A Dockerfile builds the same server.

## REQ-06 Crew app

Finish `pranavsaji/exorcist-98-crew` against the Crew manifest documentation:
the Sentry agent, the agent-hygiene skill, the nightly patrol and a dashboard
page. Validate the manifest in a test. (Tracked in that repository's own spec.)

## REQ-07 Tests

| ID | Property |
|----|----------|
| PBT-WEB-06 | The badge always reflects the worst severity present. |
| PBT-TAR-01 | Any set of files round-trips through tar, read and write with identical bytes. |
| PBT-TAR-02 | Whatever the entry names, nothing is written outside the target folder. |

Plus: browser steps for sound, Alt+arrow moves, report downloads and the
landing page; tar limits, truncation, timeout and 404; the deployment rehearsal.
