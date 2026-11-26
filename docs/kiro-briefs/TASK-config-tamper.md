# Feature brief: attacks that rewrite the agent's own settings, and leaks through Kiro's built-in tools

Write a Kiro spec in `.kiro/specs/m11-config-tamper/` (requirements, design,
tasks), then implement every task. Follow `.kiro/steering/`. Give every
requirement an ID (CT-1, CT-2, ...) and start the name of each test that checks
it with that ID, for example `it('CT-3: ...')`, so the tests can be traced back
to the spec.

Another entry in this hackathon tests coding agents against these attack
classes. Exorcist 98 should catch every one of them, in the scanner, in the
Kiro hooks, or in both.

## 1. Agent settings that trust everything (extend EX-007, or EX-030)

- Read `definitions/EX-007-overbroad-autoapprove.yaml` first. Where it can be
  extended, extend it; use a new rule EX-030 only for what EX-007 cannot
  express.
- Detect committed editor and agent settings that let the agent run commands
  without asking: Kiro's trusted-commands setting in `.vscode/settings.json`
  (and Kiro's own settings files) holding a wildcard or a broad shell pattern,
  and the auto-approve settings of the other agents the scanner already knows
  (Claude Code `permissions.allow` with a bare shell wildcard, Cursor, Cline,
  Copilot and friends; check each name in their docs, do not guess).
  Wildcard trust in a committed file is critical.
- Detect text addressed to an agent that asks it to change those settings, or
  to edit `.kiro/hooks/`, `.kiro/agents/`, `.kiro/steering/` or `AGENTS.md`
  (an attacker making the change stick).
- Extend the `mcp-config-write-guard` PreToolUse hook so an agent write that
  adds trusted commands to `.vscode/settings.json`, or that creates or changes a
  file in `.kiro/hooks/` or `.kiro/agents/`, needs the same person-only
  confirmation (Touch ID on macOS) as an MCP config write. Kiro's file write
  tools are `fs_write` and `str_replace`; shell writes come through
  `execute_bash`. Keep the existing behaviour for MCP configs.
- Find the public write-up of the 2025 Kiro issue where a poisoned file made
  the agent change its trusted commands, and cite it in `docs/INCIDENTS.md`.
  If you cannot find a primary source, say so; do not invent one.

## 2. Instructions to weaken tests (EX-031)

Text addressed to an agent (comments, README, issues, TODO notes, tool
results) that tells it to skip, delete or weaken tests or CI checks, or to make
a failing check pass: adding `.skip`, `xit` or `test.todo`, deleting a test
file "because it is flaky", `--no-verify`, `|| true` on a CI step, lowering a
coverage threshold. Ordinary test code that uses `.skip` must not fire; the
rule is about instructions to the agent. Use the negated-cue support from m7.

## 3. Instructions to push or publish somewhere else (EX-032)

Text addressed to an agent asking it to push to a remote other than origin, add
a new remote, publish a package, change the package registry, or open a pull
request against a different repository.

## 4. Hidden instructions in HTML meta tags and alt text (extend EX-028)

`<meta>` tags whose name is aimed at a model (for example `ai-instructions`,
`llm`, `assistant`) and image alt text carrying instructions. Extend EX-028
rather than adding a rule.

## 5. Leaks through Kiro's own tools, not MCP

- A PreToolUse hook `guard-web-fetch` for Kiro's `web_fetch` tool (check the
  hook input format in kiro.dev/docs/hooks): block a fetch whose URL carries a
  secret-shaped value, a canary token, or a value that appears in a `.env*`
  file of this workspace. Reuse `redact-secrets` and the canary code. Exit
  code 2 blocks; the reason is one plain line and never prints the secret.
- Extend the write path the same way: a PreToolUse guard on `fs_write` and
  `str_replace` that blocks writing a value from `.env*` into any other file.
- `exorcist init --kiro` installs both hooks.

## 6. Kiro's sandbox as an extra layer

Read kiro.dev/docs/sandbox. `exorcist init --kiro --sandbox` writes
`.kiro/settings/sandbox.json` (enabled, network blocked by default, MCP
sandboxing on) only when the file does not exist, and prints what it changed
and how to undo it. Without `--sandbox`, `init` only mentions the option. The
scanner reports, as info, a committed sandbox file that turns MCP sandboxing
off; remember that a project file can only tighten the global policy.

## 7. Show it and measure it

- Possession Lab attack 9 in the web app: the settings attack, blocked. Keep
  the existing accessibility and e2e checks passing and add a step for it.
- Benchmark cases in `fixtures/benchmark/` for every new detection, each with a
  benign look-alike that must stay clean. All samples defanged (`.invalid`
  hosts, placeholder tokens).
- Update `docs/INCIDENTS.md`, `docs/REFERENCE.md` (definitions list),
  `docs/KNOWN_LIMITATIONS.md`. Run `node scripts/facts.mjs --run-tests --docs`.

## 8. Finish

A row in `docs/KIRO_LOG.md` for this work by the Kiro IDE agent. Move this
brief to `docs/kiro-briefs/`. Run `pnpm -r typecheck` and `pnpm vitest run`
until they pass. Commit. Do not push.
