# Distribution listings: what is prepared and how to submit

Prepared on 2026-11-24. Nothing here has been submitted. **OWNER** marks a step
that needs the owner's account, a click, or an agreement.

| Listing | Prepared in this branch | Status |
|---|---|---|
| Official MCP Registry | `server.json`, `mcpName` in `packages/mcp-server/package.json`, both packages at 0.1.2 | Needs 0.1.2 on npm first |
| GitHub Marketplace (Action) | Root `action.yml` qualifies as is; fallback repo in `distribution/action-repo/` | Ready |
| Kiro Powers registry | `power/` checked against the Agent Plugins 1.0.0 schemas and fixed; form answers below | Ready after a test install in Kiro |

## Step 0: publish 0.1.2 to npm (required for the MCP Registry and the Power)

The registry checks `mcpName` in the package.json **of the published version**,
and 0.1.1 has none. This branch pins 0.1.2 everywhere (`power/mcp.json`, the
Power skills, `exorcist init` defaults, the package READMEs), so publish 0.1.2
before this reaches `main`; otherwise the Power and `exorcist init` on `main`
point at a version npm does not have.

1. Push this branch as `release/0.1.2` (release.yml publishes only from `main` or `release/*`).
2. **OWNER**: Actions, *Release to npm*, *Run workflow* on `release/0.1.2`, confirm `0.1.2`, then approve the `npm-release` environment.
3. Check: `npm view @exorcist-98/mcp-server@0.1.2 mcpName` prints `io.github.pranavsaji/exorcist-98`.
4. Merge `release/0.1.2` into `main`. Then change the README line "Every command above is in the published npm version, `@exorcist-98/cli@0.1.1`" to 0.1.2, and the publish dates in `docs/KIRO_LOG.md` and `apps/web/src/lib/how-kiro.ts` (then `node_modules/.bin/tsx scripts/how-kiro-md.ts`).

## 1. Official MCP Registry

Sources (read 2026-11-24; registry release v1.8.16):
github.com/modelcontextprotocol/registry `docs/modelcontextprotocol-io/quickstart.mdx`,
`package-types.mdx`, `versioning.mdx`, `docs/reference/server-json/official-registry-requirements.md`,
`pkg/model/constants.go` (current schema `2025-12-11`).

Requirements met:
- `server.json` uses `https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json` and validates against it (checked with ajv). Description is 99 characters (limit 100).
- `name` `io.github.pranavsaji/exorcist-98` equals `mcpName` in `packages/mcp-server/package.json` (npm ownership check). GitHub login proves the `io.github.pranavsaji/` namespace.
- npm package from `https://registry.npmjs.org` only; exact version `0.1.2`, no range or dist-tag; stdio transport via `npx`. Optional env: `EXORCIST_ROOTS`, `EXORCIST_MCP_NO_QUOTES`.
- Each version can be published once and cannot be changed afterwards.
- A test (`packages/cli/src/__tests__/repo-files.test.ts`) keeps `server.json`, `mcpName` and both package versions in step.

Submit, from the repository root at the commit that has `server.json`, after step 0:

```sh
brew install mcp-publisher            # or the release binary from the quickstart
mcp-publisher validate                # validates ./server.json
mcp-publisher login github            # OWNER: device code at https://github.com/login/device, as pranavsaji
mcp-publisher publish
curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.pranavsaji/exorcist-98"
```

The registry is in preview, and the docs warn that data may be reset. **OWNER**: read
`docs/modelcontextprotocol-io/terms-of-service.mdx` before publishing. Later, CI can
publish with `mcp-publisher login github-oidc` (`id-token: write`, see `github-actions.mdx`).
Then mark the README Install row as listed.

## 2. GitHub Marketplace (the GitHub Action)

Source: docs.github.com, *Publishing actions in GitHub Marketplace*
(github/docs `content/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace.md`),
and *Metadata syntax* for branding.

Requirements and how this repository meets them:
- Public repository: yes.
- One `action.yml` at the root: yes (others in sub-folders are allowed but not listed; `distribution/action-repo/action.yml` is not listed).
- **No rule against workflow files any more.** It was removed from the docs on 2026-05-25 (github/docs commit `0130d0a713`, "Remove no workflow files prerequisite"). The page still advises keeping an action repository to the action's own files, which is why the fallback below exists.
- Unique name: `Exorcist 98` had 0 results on github.com/marketplace?type=actions&query=exorcist (2026-11-24), and there is no GitHub user or organisation `exorcist-98`. It is not a Marketplace category or a GitHub feature name.
- Branding: `shield` is in the Feather v4.28.0 list and `purple` is an allowed colour.
- Description: now 124 characters (quoted). The 125-character limit is not in the current docs; it was shortened as a precaution.
- Two-factor authentication on the owner's account, and the Marketplace Developer Agreement accepted.

### Option A (recommended): list the monorepo as it is

1. **OWNER**: make sure 2FA is on for github.com/pranavsaji.
2. **OWNER**: open https://github.com/pranavsaji/exorcist-98/blob/main/action.yml, click **Draft a release** in the banner.
3. **OWNER**: tick **Publish this Action to the GitHub Marketplace**. If the box is disabled, click the link to accept the **GitHub Marketplace Developer Agreement** and accept it.
4. Wait for "Everything looks good!". Primary category **Security**, second category **Code quality**.
5. Tag `v0.1.2` targeting `main` (after step 0), title `Exorcist 98 v0.1.2`, short notes.
6. **OWNER**: **Publish release** (asks for 2FA).
7. Change the README example from `pranavsaji/exorcist-98@main` to `@v0.1.2`, and mark the Install row as listed.

This action builds the CLI from source with pnpm on every run (about a minute).

### Option B (fallback): a standalone action repository

Use it if the release page rejects the monorepo, or for a faster action.
`distribution/action-repo/` has `action.yml` (written by `node scripts/action-repo.mjs`
from the root `action.yml`: the same steps, but it installs `@exorcist-98/cli@0.1.2`
from npm with `--ignore-scripts` and runs `npm audit signatures` instead of building),
`README.md` (usage, inputs, least-privilege permissions, no secrets) and `LICENSE`.
It has no workflow files. A test fails if it drifts from the root action.

1. **OWNER**: create the public repository `pranavsaji/exorcist-98-action`.
2. Copy the three files to its root, commit, push.
3. Steps 1 to 6 of option A on that repository, tag `v0.1.2`.

Only one repository can hold the name `Exorcist 98`. If you use B, do not also list A.

## 3. Kiro Powers

Sources: kiro.dev/docs/powers, kiro.dev/docs/powers/create, kiro.dev/docs/powers/installation,
agent-plugins.org/schemas/1.0.0/{plugin,mcp}.schema.json, github.com/kirodotdev/powers
(README and CONTRIBUTING; `power-builder/skills/agent-plugins-reference/SKILL.md`), kiro.dev/powers/submit.

How third-party Powers get listed: **not by pull request.** kirodotdev/powers
CONTRIBUTING says "To submit a power please visit https://kiro.dev/powers/submit/",
and its README says other powers are hosted by their authors. The form asks for a
public GitHub repository link; Kiro gets in touch "if it's a good fit". So the
Power stays in this repository and nothing needs a PR branch.

Checked and fixed in `power/`:
- `plugin.json` and `mcp.json` validate against the Agent Plugins 1.0.0 schemas (ajv, 2020-12).
- Keywords cut from 11 to 7 specific ones; the Power Builder guidance warns that broad words ("security", "scan", "mcp") cause false activations.
- Each skill description now says when to use it, as the Agent Skills guidance asks.
- The skills now say what to do when the `exorcist` CLI is not installed (the Power installs only the MCP server): use `npx -y @exorcist-98/cli@0.1.2`, and `init --kiro --shield` for wrapping, so wrapped servers can find the shield.
- Pins moved to 0.1.2; removed the stray `power/.gitkeep`.

Before submitting (after step 0):
1. **OWNER**: in Kiro, Powers panel, *Add Custom Power*, *Import power from a folder*, choose `power/`. Check that the MCP server starts and lists 4 tools, and that "scan this repo for prompt injection" activates the Power. Then try *Import power from a repository URL* with `https://github.com/pranavsaji/exorcist-98/tree/main/power`. The README says this has not been done yet.

Form at https://kiro.dev/powers/submit/ (**OWNER**: personal details, and agreeing to the Kiro Registry Publisher Terms and Conditions and the Privacy Notice):

| Field | Answer |
|---|---|
| Resource type | Power |
| First name, last name, email | owner |
| Organization (optional) | leave empty, or "Exorcist 98" |
| Use case (3-4 words) | Antivirus for AI agents |
| Public GitHub repository URL | `https://github.com/pranavsaji/exorcist-98/tree/main/power` (the repository root also works if the form insists) |
| Logo (optional, SVG/EPS preferred, PNG accepted, 5 MB max) | `packages/vscode/icon.png` (128x128 PNG) |
| Domain or problem | Coding agents obey text they read: READMEs, steering and rules files, MCP tool descriptions, tool results. Exorcist 98 scans a project and its MCP configs for hidden instructions, poisoned or changed tools, dangerous hooks and leaked secrets, explains each finding in plain language, can put a shield in front of MCP servers, and quarantines a bad server with a backup. The MCP server returns no quoted file text by default, so it cannot become an injection channel itself. Open source, Apache-2.0, published to npm with provenance. |
