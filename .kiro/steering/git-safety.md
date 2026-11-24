---
inclusion: fileMatch
fileMatchPattern: ["packages/core/src/origin.ts", "packages/core/src/repo-config-guard.ts", "packages/cli/src/commands/origin.ts", "packages/core/src/secrets-check.ts", "packages/cli/src/commands/check-staged.ts", "apps/web/src/lib/scan-service.ts"]
---

# Git in a repository we did not write

A scanned repository is attacker input, including its own `.git/config`.

- Never run a git command that a repository's config can turn into a program. Before
  `exorcist origin` runs git in a folder, `repo-config-guard.ts` reads its config files
  without git and refuses if any key can run a command (`filter.*`, `diff.*.command`,
  `diff.*.textconv`, `diff.external`, `include*`, `gpg.program`, `core.fsmonitor`,
  `core.sshCommand`, `core.gitProxy`, `core.hooksPath`). A parse error means refuse. A
  second pass asks git to list the same files with `--no-includes`, which executes nothing.
- Every git call goes through `runGit`: an argument array, never a shell; `GIT_PREFIX`
  overrides (`core.fsmonitor=false`, `core.hooksPath=/dev/null`, `core.sshCommand=`,
  `protocol.allow=never`, `diff.external=`, `core.pager=cat`, ...); an environment without
  `GIT_DIR`, `GIT_WORK_TREE` and friends, with `GIT_CONFIG_NOSYSTEM=1` and
  `GIT_CONFIG_GLOBAL=/dev/null`; a time limit and an output cap. Errors carry our own
  wording, never git's (git quotes attacker-controlled paths).
- Author names, emails and messages are attacker text: split fields on NUL (`%x00`), never
  on a character a person can type, and print them through `sanitizeGitText` (terminal
  escapes removed, at most 200 characters).
