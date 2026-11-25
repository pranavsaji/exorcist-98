# Feature brief: Exorcist 98 as a guard inside Kiro's own workflow

Write a Kiro spec in `.kiro/specs/m10-kiro-gate/` (requirements, design,
tasks), then implement every task. Follow `.kiro/steering/`. Read Kiro's
documentation for hooks, Powers and custom agents first (kiro.dev/docs/hooks,
kiro.dev/docs/powers, kiro.dev/docs/powers/create, kiro.dev/docs/chat/agents or
the current equivalents) and cite what you rely on in the design.

## 1. A gate the agent cannot walk past

- `exorcist gate`: scans the agent-facing files changed in this session (steering,
  specs, hooks, MCP configs, AGENTS.md and friends, README) against the last
  committed version, and exits non-zero with a short plain-language list when
  the change adds a high or critical finding. Fast (well under a second on this
  repository), read-only, no network.
- A Kiro hook in `.kiro/hooks/` that runs it when the agent finishes its turn
  (the Stop / agent-stop event in Kiro's hook docs), so the agent cannot finish
  while it has just written something possessed into the project. Use the
  existing `scripts/kiro-hook.sh` launcher pattern (it finds Node with a minimal
  PATH). `exorcist init --kiro` installs it.
- Tests: the gate passes on a clean change, fails on a change that adds hidden
  characters to a steering file, ignores findings that were already there, and
  the hook JSON matches Kiro's schema as the other hook tests check.

## 2. The Power, by the book

- Check the Power against the current Kiro Powers docs. If Kiro expects a
  `POWER.md` (or any other file) that `power/` lacks, add it; keep
  `plugin.json`, `mcp.json` and the skills valid against the Agent Plugins
  schema. Add a steering file in the Power if the docs support it, telling the
  agent to pass the absolute workspace path to `scan_repo` and to approve the
  folder prompt.
- Keep the version pins in step (0.1.3 now).

## 3. The two custom agents

`.kiro/agents/exorcist-reviewer.json` and `exorcist-red-team.json` exist but
were never loaded in Kiro. Check them against Kiro's custom-agent format,
fix what is wrong, and document how to start each one in Kiro.

## 4. Record it

A row in `docs/KIRO_LOG.md` for this work by the Kiro IDE agent, and the hooks
count updated. Run `pnpm -r typecheck` and `pnpm vitest run`. Commit. Do not
push.
