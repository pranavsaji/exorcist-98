---
inclusion: manual
---
# Cutting a release
Include this with `#release` when publishing `@exorcist-98/cli` and `@exorcist-98/mcp-server`.
The scripts are the authority (`scripts/release.sh`, `.github/workflows/release.yml`,
`docs/PUBLISH.md`); this is a summary of what they do.
- Both packages publish at the `version` in their own `package.json` (`packages/cli`,
  `packages/mcp-server`). Set the versions first and commit; both scripts stop on a
  version that is already on npm.
- Only the owner publishes. An agent never runs `npm login`, `npm publish` or
  `pnpm publish`, and never triggers the release workflow.
- Local path: `sh scripts/release.sh` from a clean checkout of the release, after
  `npm login`. It refuses to run with uncommitted tracked changes, with no npm login, or
  when either version is already on npm. It then runs `pnpm install --frozen-lockfile`,
  builds both packages, runs both packages' vitest suites, checks with `npm pack --dry-run`
  that only `dist/`, `definitions/`, `README.md`, `package.json` and `LICENSE` ship, and
  only then publishes and checks the versions on npm.
- CI path: the "Release to npm" workflow (`workflow_dispatch`, run from `main` or a
  `release/*` branch). The `confirm` input must be the version being published and must
  match both `package.json` files. It runs in the `npm-release` environment, which needs
  the owner's approval, and publishes with npm provenance through trusted publishing; no
  npm token is stored in the repository.
- `docs/PUBLISH.md` documents publishing with `pnpm publish`, because pnpm rewrites the
  `workspace:*` development dependencies. Check that file and `scripts/release.sh` agree
  before relying on either.
- Afterwards, smoke test the published package: `npx -y @exorcist-98/cli@<version> --version`
  and `npx -y @exorcist-98/cli@<version> scan .`.
- Never put an npm token, one-time code or other secret in the repository, a commit
  message or a log.
