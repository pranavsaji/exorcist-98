# Tasks: m2-ui

Run `pnpm test` and `pnpm -r typecheck` after each task.

- [x] TASK-01 Scaffold: dependencies, `next.config.mjs`, Tailwind, tsconfig,
      vitest config, layout, global styles. `next build` succeeds. (REQ-01)
- [x] TASK-02 Pure libraries with tests: `protocol`, `ndjson`, `github`,
      `snippet`, `severity`, `plain`, `paths`. PBT-WEB-01 to 05. (REQ-03, REQ-10)
- [x] TASK-03 `scan-service` and `POST /api/scan`, with the golden-path
      integration test and 400-case tests. (REQ-02)
- [x] TASK-04 Retro components: Window, Taskbar, DesktopIcon, Icons,
      SeverityBadge, ProgressBar, RetroFrame. Render tests. (REQ-04, REQ-09)
- [x] TASK-05 `useScan` hook, ScanWindow, ResultsWindow, FindingDetail,
      Desktop page. (REQ-05, REQ-06, REQ-07)
- [x] TASK-06 Threat Encyclopedia pages. (REQ-08)
- [x] TASK-07 Docs: KIRO_LOG, KNOWN_LIMITATIONS M2 section. (REQ-11)
- [x] TASK-08 Final check: `pnpm install`, `pnpm -r build`, `pnpm test`,
      `pnpm -r typecheck`; run the app and fetch the pages.

Order: 01, then 02 and 04 in any order, 03 after 02, 05 after 02 to 04,
06 after 02, 07 and 08 last.
