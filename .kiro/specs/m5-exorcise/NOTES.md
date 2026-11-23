# Notes: m5-exorcise

Choices made where the spec left room or could not be followed literally.

- **EX-021 does not exist yet.** REQ-01.1 asks to also remove variation-selector
  runs of 4+ "when that rule exists". There is no EX-021 definition, so only
  the EX-001 classes (zero-width, bidi controls, tag characters) are removed.
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
- **Subdivision flags.** The England, Scotland and Wales flag emoji are a black
  flag plus tag characters. EX-001 reported them, and removing those tags would
  break the emoji, contradicting PBT-EXO-02's spirit. The normalizer now treats
  exactly those three sequences as benign (any other tag run, including after a
  black flag, is still reported). Covered by `normalizer-flags.test.ts`.
- **HTML comments flagged by EX-002** are removed only when the flagged phrase
  is inside the comment, and never when the comment is inside Markdown code.
  An EX-002 phrase in ordinary text is left for a human.
- **Vault format.** A new entry kind `exorcise` holds every file of one
  `--write` run (exact bytes, sha256 before and after), so one
  `exorcist vault restore <id>` undoes the whole run. Restore refuses a file
  that was edited after the exorcism unless `--force`.
- **The vault inside the project.** The default state folder is the project's
  `.exorcist/`, so the backups (the possessed originals) sit inside the scanned
  folder. `exorcise` skips the state folder; `exorcist scan` does not (it would
  be an easy hiding place), so after `--write` a plain scan also reports the
  backup copies until the vault entry is removed or `.exorcist/` is listed in
  `.exorcistignore`.
- **Web patch event** is sent after `done` (the last event of a successful
  scan, never after `fatal`). It is capped at 1 MB by whole files; files left
  out are counted in `omitted`. The page offers it for uploads, GitHub repos and
  the Haunted Repo.
- **CLI output.** In a dry run the diff goes to stdout and the summary to
  stderr, so `exorcist exorcise . > fix.patch && git apply fix.patch` works.
- **Verification (2026-11-23, on a heavily loaded machine).** `pnpm -r
  typecheck` clean; web build succeeds. Full `pnpm test`: 855 of 856 passed;
  the one failure was the timing check in `precision-round2.test.ts` ("stays
  fast on a very long line", 1037 ms against a 1000 ms limit), which passes when
  run alone (75/75). The browser suite (`scripts/e2e-chrome.mjs`, including the
  new Disinfect step) passed every step with 0 axe violations.
