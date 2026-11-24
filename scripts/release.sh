#!/bin/sh
# Publish @exorcist-98/cli and @exorcist-98/mcp-server at the version in their
# package.json files. Run it yourself, from a clean checkout of the release:
#
#   npm login            # once; npm may ask for a one-time code on publish
#   sh scripts/release.sh
#
# It stops before publishing if anything is off: wrong branch state, failing
# tests, a version already on npm, or a package that would ship an unexpected
# file.
set -eu
cd "$(dirname "$0")/.."

CLI_V=$(node -p "require('./packages/cli/package.json').version")
MCP_V=$(node -p "require('./packages/mcp-server/package.json').version")
echo "Releasing @exorcist-98/cli@$CLI_V and @exorcist-98/mcp-server@$MCP_V"

[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "Commit or discard local changes first."; exit 1; }
npm whoami >/dev/null 2>&1 || { echo "Not logged in to npm: run npm login first."; exit 1; }
for p in "cli@$CLI_V" "mcp-server@$MCP_V"; do
  if npm view "@exorcist-98/$p" version >/dev/null 2>&1; then echo "@exorcist-98/$p is already on npm."; exit 1; fi
done

pnpm install --frozen-lockfile
pnpm --filter @exorcist-98/cli build
pnpm --filter @exorcist-98/mcp-server build
pnpm --filter @exorcist-98/cli exec vitest run
pnpm --filter @exorcist-98/mcp-server exec vitest run

# Only dist/, definitions/, README.md and package.json may ship.
for d in cli mcp-server; do
  ( cd "packages/$d" && npm pack --dry-run --json 2>/dev/null ) | node -e '
    const files = JSON.parse(require("fs").readFileSync(0, "utf8"))[0].files.map((f) => f.path);
    const bad = files.filter((f) => !/^(dist\/|definitions\/|README\.md$|package\.json$|LICENSE$)/.test(f));
    if (bad.length) { console.error("unexpected files: " + bad.join(", ")); process.exit(1); }
    console.log(files.length + " files OK");'
done

( cd packages/cli && npm publish --access public )
( cd packages/mcp-server && npm publish --access public )
npm view "@exorcist-98/cli@$CLI_V" version
npm view "@exorcist-98/mcp-server@$MCP_V" version
echo "Published. Smoke test: npx -y @exorcist-98/cli@$CLI_V --version"
