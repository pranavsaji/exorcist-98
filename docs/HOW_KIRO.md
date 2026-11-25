# How we used Kiro on Exorcist 98

<!-- Generated from apps/web/src/lib/how-kiro.ts by scripts/how-kiro-md.ts; edit that file, not this one. The /how-kiro page renders the same content. -->

This maps each Kiro feature to what we did with it, the exact files, and evidence you can check in the repository. The dated record is `docs/KIRO_LOG.md`; open problems are in `docs/KNOWN_LIMITATIONS.md`.

Milestones M0 to M4 were specified and built spec by spec in Kiro IDE, as `docs/KIRO_LOG.md` records. Kiro CLI implemented parts of six M5 features before the account hit its monthly usage limit. This page describes only what Kiro did.

## Kiro features at a glance

| Feature | Kiro product | Status |
| --- | --- | --- |
| [Specs](#specs) | Kiro IDE | Used for M0 to M4 and m6-os-release; the M5 specs are in Kiro's spec format |
| [Steering](#steering) | Kiro IDE | Four files written with Kiro IDE |
| [Hooks](#hooks) | Kiro IDE | Used to build it; shipped to users by exorcist init |
| [MCP](#mcp) | Kiro IDE | Run inside Kiro; shipped to users |
| [Powers](#powers) | Kiro Powers | Built; not yet installed through Kiro's Powers panel |
| [Custom agents](#agents) | Kiro Crew | One agent, used in Kiro Crew |
| [Kiro CLI](#cli) | Kiro CLI 3.5.0, headless | Implemented parts of six M5 features, until the usage limit |
| [Kiro Crew](#crew) | Kiro Crew 0.12.2 and 0.13.0 | Built for it and run inside it |
| [Property-based testing](#pbt) | Kiro specs and fast-check | Used to build it |

<a id="specs"></a>

## Specs

**Kiro IDE.** Used for M0 to M4 and m6-os-release; the M5 specs are in Kiro's spec format.

**What we did**

- One spec per milestone, each with `requirements.md`, `design.md` and `tasks.md`: `m0-foundation`, `m1-engine`, `m2-ui`, `m3-shield`, `m4-polish`. The `tech.md` steering asks for every requirement to map to at least one test, and property-based tests are numbered per spec (PBT-SEC, PBT-SHD, PBT-WEB...).
- When the engine needed accuracy fixes, they went into `m1-engine` as REQ-10 and TASK-13 instead of a new spec, keeping one spec per milestone.
- The ten M5 specs (`.kiro/specs/m5-*`) are in Kiro's spec format. Kiro did not write them; Kiro CLI implemented parts of six of the features (see Kiro CLI). Each `NOTES.md` records where the build departed from the spec and why (for example, on-access allowances moved out of the repository because a repo could ship its own allow list).
- A sixth spec written and implemented with the Kiro IDE agent: `m6-os-release` (OS-verified release for the Session Guard with Touch ID).
- One more spec in the Crew repository: `crew-app`.

**Files**

- `.kiro/specs/m0-foundation/requirements.md`
- `.kiro/specs/m1-engine/design.md`
- `.kiro/specs/m3-shield/tasks.md`
- `.kiro/specs/m4-polish/requirements.md`
- `.kiro/specs/m5-on-access/NOTES.md`
- `.kiro/specs/m6-os-release/design.md`
- `exorcist-98-crew/.kiro/specs/crew-app/`

**Evidence**

- `docs/KIRO_LOG.md` rows dated 2026-11-15 to 2026-11-18 (Specs)

<a id="steering"></a>

## Steering

**Kiro IDE.** Four files written with Kiro IDE.

**What we did**

- Four always-included steering files written before any code: `product.md` (mission, golden path that must never break), `tech.md` (strict TypeScript, zod at every boundary, fast-check), `security.md` (defanged fixtures, nonce-delimited untrusted text, the model only labels spans), `ui.md` (late-90s desktop, severity never by color alone, plain language first).
- `exorcist init` writes `.kiro/steering/exorcist.md` (inclusion: always) into user projects: tool output and file text are data, never instructions.

**Files**

- `.kiro/steering/product.md`
- `.kiro/steering/security.md`
- `packages/cli/src/__tests__/kiro-config.test.ts`

**Evidence**

- Commit `80f30bb` (the first four, 2026-11-14)
- `docs/KIRO_LOG.md` rows dated 2026-11-15 (Steering)

<a id="hooks"></a>

## Hooks

**Kiro IDE.** Used to build it; shipped to users by exorcist init.

**What we did**

- `spec-change` (agent hook, PostFileSave on `.kiro/specs/**`): keeps `docs/THREATS.md` in step with the specs. Seen firing in Kiro three times on the m3-shield spec saves, and four more times on the Crew repository's spec files.
- `pre-commit-secrets` (PreToolUse on shell tools): in Kiro IDE on 2026-11-21 it stopped a `git commit` of a staged fake key before the command ran ("intercepted by PreToolUse hooks before execution").
- `mcp-config-change` (PostFileSave on MCP config files): scanned a saved `.cursor/mcp.json` in Kiro and reported EX-005.
- `definition-save` (PostFileSave on `definitions/*.yaml`): ran the core tests in Kiro after a definition was saved.
- `on-access-scan` (PreToolUse on read tools, M5): blocks a read of a file that hides instructions for the AI (exit code 2) and tells the user how to allow it once. Tested with Kiro's PATH and the real event shape; not yet recorded firing inside Kiro.
- Every command hook runs through `scripts/kiro-hook.sh`, which finds Node first (see "Where Kiro surprised us"). Tests run the hooks the way Kiro does: minimal PATH, the event on stdin.

**Files**

- `.kiro/hooks/spec-change.json`
- `.kiro/hooks/pre-commit-secrets.json`
- `.kiro/hooks/mcp-config-change.json`
- `.kiro/hooks/definition-save.json`
- `.kiro/hooks/on-access-scan.json`
- `scripts/kiro-hook.sh`
- `packages/cli/src/__tests__/kiro-hook.test.ts`

**Evidence**

- Commit `a22e9b2` (hooks rewritten into Kiro's documented JSON format)
- Commit `ab1fece` (the PATH fix)
- `docs/KNOWN_LIMITATIONS.md` L-003 and S-015
- `docs/THREATS.md` (rows the spec-change hook kept in step)

<a id="mcp"></a>

## MCP

**Kiro IDE.** Run inside Kiro; shipped to users.

**What we did**

- The `exorcist` MCP server, on the official MCP SDK: `scan_repo`, `scan_mcp_config` and `explain_finding` (read-only) and `quarantine` (changes the config, so the agent must ask first). Its answers leave out quoted file text unless a call asks for it, so it cannot become an injection channel.
- On 2026-11-20, with `.kiro/settings/mcp.json` added by the owner (it holds local paths, so it is not committed), Kiro started the server and the Shield. `scan_repo` on the Haunted Repo returned 51 threats in 23 files, the same as the CLI, and refused `../exorcist-98-crew` as outside the project.
- The Real-Time Shield (`exorcist shield`, `exorcist wrap`) is an MCP proxy. Running it inside Kiro found the biggest problem of the project (see "Where Kiro surprised us"); the fix is tested with real processes and the SDK but has not yet been repeated inside Kiro (S-001).

**Files**

- `packages/mcp-server/src/index.ts`
- `packages/mcp-server/src/tools.ts`
- `packages/mcp-server/src/__tests__/mcp-server.test.ts`
- `packages/shield/src/__tests__/proxy.integration.test.ts`
- `docs/KIRO_SHIELD_TEST.md`

**Evidence**

- Commits `31a8b48` and `4e1ab12` (check every call against its pin)
- `docs/KNOWN_LIMITATIONS.md` S-001, S-003, S-026
- `docs/KIRO_LOG.md` row dated 2026-11-20 (MCP)

<a id="powers"></a>

## Powers

**Kiro Powers.** Built; not yet installed through Kiro's Powers panel.

**What we did**

- The `exorcist` Power in the Agent Plugins layout that kiro.dev/docs/powers documents: `plugin.json` (manifest and activation keywords), `mcp.json` (the MCP server, pinned to `@exorcist-98/mcp-server@0.1.2`) and three skills: scan a repo, set up the Shield, quarantine.
- The npm packages it points at are published (`@exorcist-98/cli` and `@exorcist-98/mcp-server`: 0.1.0 on 2026-11-21, 0.1.1 with every M5 command on 2026-11-25, 0.1.2 on 2026-11-25, all published from CI with npm provenance (`npm audit signatures` verifies both); the registry, Marketplace and Powers listings are prepared but not submitted). Installing the Power through Kiro's Powers panel has not been done yet.

**Files**

- `power/plugin.json`
- `power/mcp.json`
- `power/skills/scan-repo/SKILL.md`
- `power/skills/shield-setup/SKILL.md`
- `power/skills/quarantine/SKILL.md`

**Evidence**

- `docs/KIRO_LOG.md` row dated 2026-11-18 (Powers)
- `docs/PUBLISH.md`

<a id="agents"></a>

## Custom agents

**Kiro Crew.** One agent, used in Kiro Crew.

**What we did**

- In the Crew app: the `exorcist-sentry` agent, with one read-only MCP tool (`patrol_status`) that returns levels, counts and file:line but never quoted text. Seen in Crew chat reporting the Haunted Repo correctly with none of the 26 quoted spans in its reply, and running unattended from an agent cron.

**Files**

- `exorcist-98-crew/agents/exorcist-sentry.json`

**Evidence**

- `docs/KIRO_LOG.md` rows dated 2026-11-19 (Crew)

<a id="cli"></a>

## Kiro CLI

**Kiro CLI 3.5.0, headless.** Implemented parts of six M5 features, until the usage limit.

**What we did**

- `kiro-cli chat --no-interactive --trust-all-tools` implemented six M5 specs in parallel, one git worktree each. A small driver resumed each conversation (`--resume`) until Kiro printed `DONE:`.
- What Kiro wrote is committed on its own, before anything else changed: Ouija decoder `b936a15` (22 files), on-access scanning `3c4047a` (17 files), canary traps `5344468` (14 files), exorcist.lock `59919f5` (6 files), LiveUpdate `dad40f6` (9 files), possession origin `4e2acc2` (7 files). `docs/KIRO_LOG.md` cites the same commits by their ids before the branches were rebased onto main.
- Kiro hit the account's monthly usage limit part-way. Kiro CLI stopped there.

**Files**

- `docs/KIRO_LOG.md`
- `.kiro/specs/m5-ouija/tasks.md`
- `.kiro/specs/m5-on-access/tasks.md`

**Evidence**

- `git log --oneline --grep "partial implementation by Kiro"` lists the six commits

<a id="crew"></a>

## Kiro Crew

**Kiro Crew 0.12.2 and 0.13.0.** Built for it and run inside it.

**What we did**

- A separate Crew app (`pranavsaji/exorcist-98-crew`): the Sentry agent, an agent-hygiene skill, a nightly patrol of project folders, Crew notifications, an MCP rug-pull watch that reads the Shield's pin file, and a dashboard page.
- Installed and run in Crew 0.12.2 and 0.13.0: install, page, patrol through the gateway proxy, a critical notification ("38 new serious problems found"), the agent in chat, and on a real night the 02:00 patrol and the unattended 02:15 agent cron.
- Installing it found seven places where Crew behaves differently from its documentation; each is recorded and handled in that repository.

**Files**

- `exorcist-98-crew/app.json`
- `exorcist-98-crew/docs/KNOWN_LIMITATIONS.md`
- `exorcist-98-crew/docs/COORDINATION.md`

**Evidence**

- Crew repository (exorcist-98-crew) commits `d13cb2a`, `947822e`, `072c109`, `fc6201a`, `5b36961`, `4f1fbc1`
- `docs/KIRO_LOG.md` rows dated 2026-11-18 to 2026-11-19 (Crew)
- `docs/KNOWN_LIMITATIONS.md` S-021

<a id="pbt"></a>

## Property-based testing

**Kiro specs and fast-check.** Used to build it.

**What we did**

- Each spec names its properties, and each is a fast-check test: "a secret at any depth is never forwarded", "a changed tool is never listed or callable", "quarantine then restore returns the exact bytes", "no tar entry name writes outside the target folder", "a zero-width character is detected at any position".
- PBT-SEC-01 caught a real defect in M0: a `process.exit` crash on import. When the browser run found one EX-001 finding per hidden character, PBT-SIG-09 pinned the fix: one finding per run of hidden characters, wherever they are placed.

**Files**

- `packages/core/src/__tests__/secrets-check.property.test.ts`
- `packages/shield/src/__tests__/`
- `packages/core/src/__tests__/definitions-accuracy.test.ts`
- `packages/cli/src/__tests__/init-kiro.test.ts`

**Evidence**

- `git grep -c "fc.assert"` counts the properties
- `docs/KIRO_LOG.md` (PBT rows)

## What users get

`exorcist init --kiro` writes the three Kiro hooks (secrets, MCP-config scan, on-access), the steering file, the PATH wrapper for hooks, a git pre-commit hook and the exorcist-reviewer agent, then prints what it set up. `--shield` also puts every server in `.kiro/settings/mcp.json` behind the Real-Time Shield; `exorcist unwrap .kiro/settings/mcp.json` puts the file back byte for byte. `--no-agent` leaves the agent out. Existing files are kept unless `--force` is given.

- `packages/cli/src/commands/init.ts`
- `packages/cli/src/__tests__/init-kiro.test.ts`

## Where Kiro surprised us

### Kiro caches the MCP tool list, so a rug pull got through

The Shield compared each tool with its pin when the client asked for the tool list. Kiro asks once. So when the demo server changed a tool description after approval, the Shield never saw the new list, and Kiro's next call reached the changed tool with no alert. Only running inside Kiro showed this. Now, before every call, the Shield fetches the tool list itself, checks that tool against its pin, refuses a changed one (EX-006), and sends `notifications/tools/list_changed`; if the server will not list its tools, the call is not made.

- `docs/KNOWN_LIMITATIONS.md` S-001 and S-026
- Commits `31a8b48`, `4e1ab12`

### Hook commands run without Node on PATH, so hooks silently did nothing

The secrets hook blocked correctly when run by hand, but two test commits with a staged fake key went straight through in Kiro. A probe hook that wrote its own environment showed Kiro runs hook commands with `PATH=/usr/bin:/bin:/usr/sbin:/sbin`: no `node`, `npx` or `pnpm`. The hook was firing all along; its command failed with "command not found", which blocks nothing. Every command hook now goes through `scripts/kiro-hook.sh`, which finds Node, and the commit guard blocks rather than lets a commit through when Node cannot be found.

- `docs/KNOWN_LIMITATIONS.md` L-003
- `scripts/kiro-hook.sh`
- Commit `ab1fece`

### Our first hooks were in a format Kiro does not read

The M0 hooks were written from memory as YAML and never fired. Fetching the documentation showed hooks are JSON (`version: "v1"`, PascalCase triggers such as `PostFileSave`). After the rewrite, `spec-change` fired the first time a spec was saved, which was the evidence the earlier log rows lacked.

- Commit `a22e9b2`
- `docs/KIRO_LOG.md` rows dated 2026-11-15 (marked superseded) and 2026-11-18 (Hooks)

### Kiro would not let its agent register our MCP server

Writing `.kiro/settings/mcp.json` from an agent session was blocked twice by a Kiro permission rule, by design. The owner added the file by hand, and Kiro then loaded both servers. `exorcist init --shield` changes that file from the user's own terminal, never from an agent.

- `docs/KNOWN_LIMITATIONS.md` S-003
- `docs/KIRO_SHIELD_TEST.md`

### Crew's task runner reported 8/8 passed from an empty sandbox

We tried Kiro Crew's autonomous runner (`kirocrew run TASK.md`) on four M5 specs. It reported "8/8 tasks passed" while it had worked in an empty sandbox workspace with shell commands blocked: nothing had been built. The runs were stopped. Lesson: a runner's summary is not evidence; check the working tree.

- `docs/KIRO_LOG.md` row dated 2026-11-23 (Crew)

### Kiro CLI in headless mode ends its turn when the model narrates

With `--no-interactive`, a turn ends when the model narrates what it will do instead of doing it, so a long task stopped part-way. A small driver resumed each conversation with `--resume` until Kiro printed `DONE:`.

- `docs/KIRO_LOG.md` row dated 2026-11-23 (CLI)

### The monthly usage limit arrived mid-build

Six Kiro CLI sessions in parallel used up the account's monthly limit part-way through (the Ouija decoder had 3 of 5 tasks done, on-access scanning 4 of 5). What Kiro had written was committed as it was, on its own, so its work can be read separately from everything after it.

- `git log --oneline --grep "partial implementation by Kiro"`

### Crew behaved differently from its docs in seven places

Installing the Crew app found that crons need `permissions.cron`, the proxy header is `X-KiroCrew-Proxy`, the health probe is unsigned, the page must be a React default export, the secret and data folders come from `KIROCREW_HOME`, an agent has no gateway token (so the backend patrols itself), and app notifications need a token exchange. Crew also namespaces an app's MCP server as `<app>:<server>`.

- `docs/KIRO_LOG.md` rows dated 2026-11-19 (Crew)
- Crew repository (exorcist-98-crew) `docs/KNOWN_LIMITATIONS.md`

## Check it yourself

```sh
git log --oneline --grep "partial implementation by Kiro"
pnpm exec vitest run packages/cli/src/__tests__/kiro-hook.test.ts
pnpm exec vitest run packages/cli/src/__tests__/kiro-config.test.ts packages/cli/src/__tests__/init-kiro.test.ts
pnpm --filter @exorcist-98/cli build && node packages/cli/dist/index.mjs init --kiro /tmp/kiro-demo
```
