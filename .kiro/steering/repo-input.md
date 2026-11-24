---
inclusion: fileMatch
fileMatchPattern: ["packages/shield/src/**", "packages/core/src/allowed-reads.ts", "packages/core/src/on-access.ts", "packages/core/src/liveupdate.ts", "packages/cli/src/commands/lock.ts", "packages/cli/src/commands/update.ts", "packages/cli/src/commands/on-access.ts"]
---

# A file that comes with the repository is never an approval

- `exorcist.lock` records expected fingerprints, never approvals. The Shield reads it into a
  separate in-memory map used only to detect drift; a tool that matches the lock still goes
  through first-use checks, and one that differs is held as a rug pull (EX-006).
- On-access allowances live outside the project: `$EXORCIST_DIR/allowed-reads/<sha256 of the
  project path>.json` (default `~/.exorcist/`). A list inside the project tree, including
  through a symlink, is refused, so a repository cannot ship the hash of its own poisoned file.
- LiveUpdate installs a definitions set only after checking an Ed25519 signature over the
  exact manifest bytes, before the manifest is parsed. No private key is ever committed
  (`no-private-keys.test.ts`).
- Policy, pins and approvals change only through `exorcist approve ...` run by the user.
  Agents are told never to edit `.exorcist/` (the `exorcist.md` steering that `exorcist init`
  writes).
