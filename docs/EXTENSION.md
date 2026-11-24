# Exorcist 98 for Kiro: the editor extension

`packages/vscode` is an extension for Kiro and VS Code. Kiro is a VS Code fork
that installs extensions from [Open VSX](https://open-vsx.org); the same
`.vsix` works in both. What it does is described in
[`packages/vscode/README.md`](../packages/vscode/README.md), which is also its
marketplace page.

How it was made: the extension was written with Claude Code, outside Kiro, and
then installed into Kiro (see `docs/KIRO_LOG.md`, 2026-11-24).

## Design in one paragraph

All decisions live in pure modules with no `vscode` import, unit-tested with
Vitest: `roles.ts` (which files to scan; the roles come from the core's
`classifyFile` and `parseMcpConfig`), `scanner.ts` (the core's `scanText` on
the editor's in-memory text, plus the EX-023 trifecta check for MCP configs),
`diagnostics.ts` (finding to diagnostic: range, severity, message, encyclopedia
link), `hidden.ts` (the core's `removeHiddenUnicode` for the markers and
`decodeHidden`/`displayMessage` for the hover) and `fixes.ts` (the core's
`exorciseFile`, turned into minimal text edits). `adapter.ts` converts their
plain data into `vscode` objects one to one, and `extension.ts` wires events.
The tests run the pure modules directly, the adapter against a mocked `vscode`
module, and the built, minified `dist/extension.js` inside a fake editor host
that scans a folder on disk and asks for a quick fix and a hover.

## Build

```sh
pnpm install
pnpm --filter exorcist-98-kiro build      # dist/extension.js and dist/definitions/
pnpm --filter exorcist-98-kiro package    # exorcist-98-kiro-0.1.0.vsix (runs the minified build first)
```

`build.mjs` bundles with esbuild into one CommonJS file (`vscode` is external),
marks the core package side-effect free so the modules the extension never
uses (git, live update, the registry lookup, the AI layer) are dropped, and
fails if the bundle would still require `child_process`, `http`, `https`,
`net`, `tls`, `dgram` or `worker_threads`, or call `fetch`. The bundle
requires only `fs/promises`, `path`, `vm` and `vscode`.

`vsce package --no-dependencies` is used because everything is bundled; the
package contains only `dist/extension.js`, `dist/definitions/*.yaml`,
`package.json`, `README.md`, `CHANGELOG.md`, `LICENSE` and `icon.png`
(`.vscodeignore`). Check with `npx vsce ls` in `packages/vscode`.

The icon is `apps/web/src/app/icon.svg` rendered to 128x128 with ImageMagick:
`magick -background none -density 1152 apps/web/src/app/icon.svg -resize 128x128 -strip PNG32:packages/vscode/icon.png`.

Tests: `pnpm test` (the workspace includes `packages/vscode/vitest.config.ts`),
or `pnpm vitest run --project exorcist-98-kiro`. Typecheck: `pnpm -r typecheck`.

## Install from the .vsix

Kiro:

```sh
kiro --install-extension packages/vscode/exorcist-98-kiro-0.1.0.vsix
kiro --list-extensions | grep exorcist     # exorcist-98.exorcist-98-kiro
```

VS Code: `code --install-extension packages/vscode/exorcist-98-kiro-0.1.0.vsix`.

Either editor also has *Extensions: Install from VSIX...* in the Command
Palette. To remove: `kiro --uninstall-extension exorcist-98.exorcist-98-kiro`.

To see it work, open this repository's `fixtures/haunted-repo` in Kiro. Its
samples are named `EX-0xx-*.md|json|yaml`, which are not agent file names, so
only `README.md` is scanned by default; add them in the folder's settings
(`.vscode/settings.json` or the Settings UI, Workspace tab):

```json
{ "exorcist98.extraGlobs": ["EX-*"] }
```

The samples then light up in the Problems view, the status bar shows the ghost
count, `EX-001-hidden-unicode.md` and `EX-021-smuggled-bytes.md` get hidden-
character markers with the decoded message on hover, and the lightbulb offers
*Exorcise: remove hidden characters*. A file under `.kiro/steering/` or named
`AGENTS.md` needs no setting. The output channel *Exorcist 98* logs what was
scanned.

## Publish to Open VSX (owner action)

Publishing is done by the repository owner, not by an agent: it needs an
account and a personal token that only the owner should create.

1. Sign in at <https://open-vsx.org> with GitHub and sign the Eclipse
   Foundation publisher agreement (Open VSX asks for it on first login).
2. Create an access token: avatar menu, *Settings*, *Access Tokens*. Keep it
   out of the repository and out of agent sessions.
3. Create the namespace once (it must match `"publisher"` in
   `packages/vscode/package.json`, now `exorcist-98`; change both if you want
   another name):

   ```sh
   npx ovsx create-namespace exorcist-98 -p <token>
   ```

4. Publish the file you tested:

   ```sh
   npx ovsx publish packages/vscode/exorcist-98-kiro-0.1.0.vsix -p <token>
   ```

   (`OVSX_PAT=<token> npx ovsx publish ...` also works.) Kiro's extension view
   finds it after Open VSX indexes it, usually within minutes.
5. Optionally claim the namespace (an issue at
   <https://github.com/EclipseFdn/open-vsx.org>) so it shows as verified.

For the Visual Studio Marketplace the steps are the same with `npx vsce
publish` and an Azure DevOps token for a publisher named `exorcist-98`.

Before a new version: bump `version` in `packages/vscode/package.json`, add a
`CHANGELOG.md` entry, run `pnpm test`, then package and publish the new file.

## Limits

- Only the signature rules and the EX-023 trifecta check run in the editor.
  The AI judge (Bedrock), canary-trap matching, Shield pins and the EX-010
  version-pinning fix need the network or local records; use the CLI.
- A file over 10 MB is not read; it is reported as EX-026, like the CLI.
- The workspace scan considers at most 20,000 candidate files and skips the
  CLI walker's folders (`node_modules`, `.git`, `dist`, ...).
- Not yet seen in a screenshot inside Kiro at the time of writing: installation
  was confirmed with `kiro --list-extensions`, and the built bundle is tested in
  a fake editor host, but not by driving Kiro's UI.
