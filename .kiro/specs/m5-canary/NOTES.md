# Notes: m5-canary (decisions made while finishing it)

- Detection (raw, whitespace-split, percent-encoded, base64 standard and
  URL-safe at any byte alignment, wrapped over lines, and base64 of a split or
  encoded token) is one function, `findCanaryInText` in
  `packages/core/src/canary.ts`, shared by the Shield, the scanner and the
  pre-commit hook. A base64 match is decoded and must hold the whole token, so
  a near miss is not a hit.
- The Shield reads every string and key of a message with no depth or count
  limit for this check, so oversized arguments cannot hide a token (the
  ordinary inspection still fails closed on its own limits).
- Besides tool calls (REQ-02.2), the Shield also refuses a canary token in the
  agent's answer to a server request (sampling, elicitation) and in any other
  request to the server (for example `resources/read`), in every mode. A tool
  result with a token is passed on with a medium alert (REQ-02.3).
- `plant` refuses to plant over existing traps or records; replanting is
  `--remove` then `plant`, so a record never points at a file that no longer
  holds its token. Records name which folders `plant` created (`madeDirs`) so
  `--remove` restores the folder exactly (PBT-CAN-03), and a trap path must
  stay inside `.exorcist/canary/`, so a tampered records file cannot make
  `--remove` delete anything else.
- REQ-01.2 "the Shield's state folder is told": by default the state folder is
  the project's `.exorcist`, where the records already are. When it is
  somewhere else (`--dir` or `EXORCIST_DIR`), `plant` writes the records path
  into that folder's `policy.json` as `canaries`, and `--remove` takes it out.
- `exorcist canary` with no subcommand is an error (it does not plant by
  surprise); `exorcist canary list|remove` work as aliases of the flags.
- EX-022 YAML is `enabled: false`: it is the encyclopedia entry (title, OWASP,
  fix). Matching needs the project's records, so it is done in code.
- The pre-commit check reads the staged blob, not the working copy, and allows
  only `.exorcist/canary/` and `.exorcist/canaries.json`.
- The Lab's canary token is fixed (assembled at run time) so replays stay
  deterministic; real installs get random tokens from `newToken()`. No test or
  source file holds a whole token. This repo's `.gitignore` keeps locally
  planted traps out of commits.
