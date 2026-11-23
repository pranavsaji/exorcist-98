# Notes: m5-exorcise

Choices made where the spec left room or could not be followed literally.

- **EX-021 (added by m5-ouija).** After the rebase on main the fixer also
  removes variation-selector runs of 4+ (EX-021): exactly what the normalizer
  reports, never one to three selectors (a heart's U+FE0F, an ideographic
  selector). When both EX-001 and EX-021 are on, a run that only becomes 4+
  after a zero-width character between its parts is removed is removed too.
- **Version lookups use the registry HTTP API, not `npm view`.** Same answer
  (the `latest` dist-tag), no npm binary or subprocess needed, and it works on
  the web server. `uvx` packages are looked up on PyPI and pinned as
  `pkg@1.2.3` (or `pkg==1.2.3` after `--from`). `bunx`/`pnpx` use npm. Every
  lookup has a time limit (5 s in the CLI, 3 s on the web server, cached 10
  minutes there, at most 20 per web scan); a failed lookup skips the pin with
  a note.
- **Two EX-010 cases are never pinned:** a package that looks like a typosquat
  (EX-013), and an npm package whose current version is a `-security`
  placeholder (npm's replacement for a package removed for malware; the Haunted
  Repo's `mcp-server-github` is one). Pinning either would hide the real problem.
- **Subdivision flags.** main has its own exemption for the England,
  Scotland and Wales flag tag sequences (FLAG_TAG_SEQUENCE); the rebase kept
  main's implementation and only exports `findHiddenUnicode` and
  `isHiddenCodePoint` for the fixer. `normalizer-flags.test.ts` still passes.
- **HTML comments flagged by EX-002** are removed only when the flagged phrase
  is inside the comment, and never when the comment is inside Markdown code.
  An EX-002 phrase in ordinary text is left for a human.
- **Vault format.** A new entry kind `exorcise` holds every file of one
  `--write` run (exact bytes, sha256 before and after), so one
  `exorcist vault restore <id>` undoes the whole run. Restore refuses a file
  that was edited after the exorcism unless `--force`.
- **The vault is never scanned.** The walker skips a `vault` folder directly
  inside a `.exorcist` folder (at any depth), so backups of possessed files
  never show up as findings again. Everything else under `.exorcist/` is still
  scanned, and so is any other folder named `vault`.
- **Security review fixes.** A file whose name has control characters (C0,
  DEL, C1) or is not a plain relative path is never fixed or put in a patch
  (reported for a human); other unusual names are C-quoted in the patch the
  way git does. The tar and zip readers refuse such entry names, so they are
  never written to disk. Line/column lookups use a per-file line index (no
  quadratic slicing), and each file lists at most 500 changes plus a summary
  line (`changeCount` keeps the real total).
- **Web patch event** is sent after `done` (the last event of a successful
  scan, never after `fatal`). It is capped at 1 MB by whole files; files left
  out are counted in `omitted`. The page offers it for uploads, GitHub repos and
  the Haunted Repo.
- **CLI output.** In a dry run the diff goes to stdout and the summary to
  stderr, so `exorcist exorcise . > fix.patch && git apply fix.patch` works.
- **Verification after the rebase (2026-11-23).** `pnpm -r typecheck` clean;
  `pnpm test` 1040/1040 (80 files); web build OK; browser suite on
  `next start -p 3205`: 32/32 steps, 0 axe violations. The m5-byoa step from
  main failed in the merged suite (the Field Report window opened in the step
  before covered the lab, so the tab click was intercepted); the step now
  brings the lab to the front from the taskbar first.
