// Write distribution/action-repo/action.yml from the root action.yml.
//   node scripts/action-repo.mjs
//
// The standalone action repository (a fallback for GitHub Marketplace, see
// distribution/SUBMIT.md) runs the same steps as the root action, but installs
// the published @exorcist-98/cli at one pinned version, checks its npm
// provenance, and runs no build. A test checks that the committed file is
// exactly what this script writes, so the two actions cannot drift apart.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const BUILD_STEP = /    # pnpm is installed from the action's own package\.json[\s\S]*?pnpm --filter @exorcist-98\/cli build\n/;
const ROOT_CLI = '${{ github.action_path }}/packages/cli/dist/index.mjs';
const PUBLISHED_CLI = '${{ runner.temp }}/exorcist-cli/node_modules/@exorcist-98/cli/dist/index.mjs';

/** The standalone action.yml for a given root action.yml and CLI version. */
export function standaloneAction(rootYml, version) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`not an exact version: ${version}`);
  if (!BUILD_STEP.test(rootYml)) throw new Error('action.yml: the build step was not found; update scripts/action-repo.mjs');
  if (!rootYml.includes(ROOT_CLI)) throw new Error('action.yml: the CLI path was not found; update scripts/action-repo.mjs');
  const install = [
    `    # The published CLI at one pinned version, checked against its npm provenance`,
    `    # (npm audit signatures). Nothing is built and no install scripts run.`,
    `    - name: Install Exorcist 98 (@exorcist-98/cli@${version})`,
    `      shell: bash`,
    `      run: |`,
    `        dir="$RUNNER_TEMP/exorcist-cli"`,
    `        mkdir -p "$dir" && cd "$dir"`,
    `        npm init -y >/dev/null`,
    `        npm install --no-fund --no-audit --ignore-scripts "@exorcist-98/cli@${version}"`,
    `        npm audit signatures`,
    ``,
  ].join('\n');
  const header = `# Generated from action.yml in github.com/pranavsaji/exorcist-98 by scripts/action-repo.mjs. Do not edit here.\n`;
  return header + rootYml.replace(BUILD_STEP, install).split(ROOT_CLI).join(PUBLISHED_CLI);
}

export function currentStandaloneAction() {
  const root = fileURLToPath(new URL('..', import.meta.url));
  const version = JSON.parse(readFileSync(`${root}packages/cli/package.json`, 'utf8')).version;
  return standaloneAction(readFileSync(`${root}action.yml`, 'utf8'), version);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  writeFileSync(fileURLToPath(new URL('../distribution/action-repo/action.yml', import.meta.url)), currentStandaloneAction());
}
