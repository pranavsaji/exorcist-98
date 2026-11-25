/**
 * "How we used Kiro": one source for the /how-kiro page and docs/HOW_KIRO.md.
 *
 * docs/HOW_KIRO.md is generated from this module (`howKiroMarkdown`), and a test
 * fails if the two differ, if a cited file does not exist, or if a cited
 * commit is not in the repository. Text uses `backticks` for code only.
 *
 * Regenerate the Markdown after editing:
 *   node_modules/.bin/tsx scripts/how-kiro-md.ts
 */

export type Surface = {
  /** Anchor id on the page. */
  id: string;
  title: string;
  /** Which Kiro product, in words. */
  tool: string;
  /** Plain label, never color alone. */
  status: string;
  did: string[];
  /** Paths in this repository (checked to exist), or `exorcist-98-crew/...` for the Crew repository. */
  files: string[];
  evidence: string[];
};

export type Story = { id: string; title: string; story: string; evidence: string[] };

export const HOW_KIRO_TITLE = 'How we used Kiro on Exorcist 98';

export const HOW_KIRO_INTRO = [
  'This maps each Kiro feature to what we did with it, the exact files, and evidence you can check in the repository. The dated record is `docs/KIRO_LOG.md`; open problems are in `docs/KNOWN_LIMITATIONS.md`.',
  'Milestones M0 to M4 were specified and built spec by spec in Kiro IDE, as `docs/KIRO_LOG.md` records. Kiro CLI implemented parts of six M5 features before the account hit its monthly usage limit. This page describes only what Kiro did.',
];

export const SURFACES: Surface[] = [
  {
    id: 'specs',
    title: 'Specs',
    tool: 'Kiro IDE',
    status: 'Used for M0 to M4 and m6-os-release; the M5 specs are in Kiro\'s spec format',
    did: [
      'One spec per milestone, each with `requirements.md`, `design.md` and `tasks.md`: `m0-foundation`, `m1-engine`, `m2-ui`, `m3-shield`, `m4-polish`. The `tech.md` steering asks for every requirement to map to at least one test, and property-based tests are numbered per spec (PBT-SEC, PBT-SHD, PBT-WEB...).',
      'When the engine needed accuracy fixes, they went into `m1-engine` as REQ-10 and TASK-13 instead of a new spec, keeping one spec per milestone.',
      'The ten M5 specs (`.kiro/specs/m5-*`) are in Kiro\'s spec format. Kiro did not write them; Kiro CLI implemented parts of six of the features (see Kiro CLI). Each `NOTES.md` records where the build departed from the spec and why (for example, on-access allowances moved out of the repository because a repo could ship its own allow list).',
      'A sixth spec written and implemented with the Kiro IDE agent: `m6-os-release` (OS-verified release for the Session Guard with Touch ID).',
      'One more spec in the Crew repository: `crew-app`.',
    ],
    files: ['.kiro/specs/m0-foundation/requirements.md', '.kiro/specs/m1-engine/design.md', '.kiro/specs/m3-shield/tasks.md', '.kiro/specs/m4-polish/requirements.md', '.kiro/specs/m5-on-access/NOTES.md', '.kiro/specs/m6-os-release/design.md', 'exorcist-98-crew/.kiro/specs/crew-app/'],
    evidence: ['`docs/KIRO_LOG.md` rows dated 2026-11-15 to 2026-11-18 (Specs)'],
  },
  {
    id: 'steering',
    title: 'Steering',
    tool: 'Kiro IDE',
    status: 'Four files written with Kiro IDE',
    did: [
      'Four always-included steering files written before any code: `product.md` (mission, golden path that must never break), `tech.md` (strict TypeScript, zod at every boundary, fast-check), `security.md` (defanged fixtures, nonce-delimited untrusted text, the model only labels spans), `ui.md` (late-90s desktop, severity never by color alone, plain language first).',
      '`exorcist init` writes `.kiro/steering/exorcist.md` (inclusion: always) into user projects: tool output and file text are data, never instructions.',
    ],
    files: ['.kiro/steering/product.md', '.kiro/steering/security.md', 'packages/cli/src/__tests__/kiro-config.test.ts'],
    evidence: ['Commit `80f30bb` (the first four, 2026-11-14)', '`docs/KIRO_LOG.md` rows dated 2026-11-15 (Steering)'],
  },
  {
    id: 'hooks',
    title: 'Hooks',
    tool: 'Kiro IDE',
    status: 'Used to build it; shipped to users by exorcist init',
    did: [
      '`spec-change` (agent hook, PostFileSave on `.kiro/specs/**`): keeps `docs/THREATS.md` in step with the specs. Seen firing in Kiro three times on the m3-shield spec saves, and four more times on the Crew repository\'s spec files.',
      '`pre-commit-secrets` (PreToolUse on shell tools): in Kiro IDE on 2026-11-21 it stopped a `git commit` of a staged fake key before the command ran ("intercepted by PreToolUse hooks before execution").',
      '`mcp-config-change` (PostFileSave on MCP config files): scanned a saved `.cursor/mcp.json` in Kiro and reported EX-005.',
      '`definition-save` (PostFileSave on `definitions/*.yaml`): ran the core tests in Kiro after a definition was saved.',
      '`on-access-scan` (PreToolUse on read tools, M5): blocks a read of a file that hides instructions for the AI (exit code 2) and tells the user how to allow it once. Tested with Kiro\'s PATH and the real event shape; not yet recorded firing inside Kiro.',
      '`exorcist-gate` (Stop, m10-kiro-gate): when the agent finishes its turn, `exorcist gate` checks the steering, spec, hook, agent and MCP files it changed against the last commit, and exits 1 with a short plain-language list if the change adds a high or critical finding (findings already in the last commit are ignored). Kiro sends the failing command\'s stderr to the agent. Read-only, no network, about half a second here. Tested with Kiro\'s PATH and a real Stop event shape; not yet recorded firing inside Kiro. `exorcist init --kiro` writes it, disabled while the published CLI has no `gate` command.',
      'Every command hook runs through `scripts/kiro-hook.sh`, which finds Node first (see "Where Kiro surprised us"). Tests run the hooks the way Kiro does: minimal PATH, the event on stdin.',
    ],
    files: ['.kiro/hooks/spec-change.json', '.kiro/hooks/pre-commit-secrets.json', '.kiro/hooks/mcp-config-change.json', '.kiro/hooks/definition-save.json', '.kiro/hooks/on-access-scan.json', '.kiro/hooks/exorcist-gate.json', 'scripts/kiro-hook.sh', 'packages/cli/src/__tests__/kiro-hook.test.ts'],
    evidence: ['Commit `a22e9b2` (hooks rewritten into Kiro\'s documented JSON format)', 'Commit `ab1fece` (the PATH fix)', '`docs/KNOWN_LIMITATIONS.md` L-003 and S-015', '`docs/THREATS.md` (rows the spec-change hook kept in step)'],
  },
  {
    id: 'mcp',
    title: 'MCP',
    tool: 'Kiro IDE',
    status: 'Run inside Kiro; shipped to users',
    did: [
      'The `exorcist` MCP server, on the official MCP SDK: `scan_repo`, `scan_mcp_config` and `explain_finding` (read-only) and `quarantine` (changes the config, so the agent must ask first). Its answers leave out quoted file text unless a call asks for it, so it cannot become an injection channel.',
      'On 2026-11-20, with `.kiro/settings/mcp.json` added by the owner (it holds local paths, so it is not committed), Kiro started the server and the Shield. `scan_repo` on the Haunted Repo returned 51 threats in 23 files that day, the same as the CLI then (the Haunted Repo gives fewer now, after the precision fixes of 2026-11-24; see docs/facts.json), and refused `../exorcist-98-crew` as outside the project.',
      'The Real-Time Shield (`exorcist shield`, `exorcist wrap`) is an MCP proxy. Running it inside Kiro found the biggest problem of the project (see "Where Kiro surprised us"); the fix is tested with real processes and the SDK but has not yet been repeated inside Kiro (S-001).',
    ],
    files: ['packages/mcp-server/src/index.ts', 'packages/mcp-server/src/tools.ts', 'packages/mcp-server/src/__tests__/mcp-server.test.ts', 'packages/shield/src/__tests__/proxy.integration.test.ts', 'docs/KIRO_SHIELD_TEST.md'],
    evidence: ['Commits `31a8b48` and `4e1ab12` (check every call against its pin)', '`docs/KNOWN_LIMITATIONS.md` S-001, S-003, S-026', '`docs/KIRO_LOG.md` row dated 2026-11-20 (MCP)'],
  },
  {
    id: 'powers',
    title: 'Powers',
    tool: 'Kiro Powers',
    status: 'Built; not yet installed through Kiro\'s Powers panel',
    did: [
      'The `exorcist` Power in the Agent Plugins layout that kiro.dev/docs/powers documents: `plugin.json` (manifest and activation keywords), `mcp.json` (the MCP server, pinned to `@exorcist-98/mcp-server@0.1.2`) and three skills: scan a repo, set up the Shield, quarantine.',
      'The npm packages it points at are published (`@exorcist-98/cli` and `@exorcist-98/mcp-server`: 0.1.0 on 2026-11-21, 0.1.1 with every M5 command on 2026-11-25, 0.1.2 on 2026-11-25, all published from CI with npm provenance (`npm audit signatures` verifies both); the registry, Marketplace and Powers listings are prepared but not submitted). Installing the Power through Kiro\'s Powers panel has not been done yet.',
    ],
    files: ['power/plugin.json', 'power/mcp.json', 'power/skills/scan-repo/SKILL.md', 'power/skills/shield-setup/SKILL.md', 'power/skills/quarantine/SKILL.md'],
    evidence: ['`docs/KIRO_LOG.md` row dated 2026-11-18 (Powers)', '`docs/PUBLISH.md`'],
  },
  {
    id: 'agents',
    title: 'Custom agents',
    tool: 'Kiro Crew',
    status: 'One agent used in Kiro Crew; two Kiro agents checked against the docs, not yet seen loading in Kiro',
    did: [
      'In `.kiro/agents/`: `exorcist-reviewer` (only the three read-only Exorcist tools, from its own `exorcist` MCP server) and `exorcist-red-team` (writes defanged samples only under `fixtures/benchmark/`, runs one test command). Checked field by field against kiro.dev/docs/custom-agents/configuration-reference; the reviewer had no MCP server of its own, so on a clone its tools did not exist, and now has one. To start one: trust the workspace in Kiro IDE and pick it in the agent picker of the chat header, or in Kiro CLI run `kiro-cli chat --agent exorcist-reviewer` (or `/agent swap` in a session). Use `exorcist-red-team` the same way.',
      'In the Crew app: the `exorcist-sentry` agent, with one read-only MCP tool (`patrol_status`) that returns levels, counts and file:line but never quoted text. Seen in Crew chat reporting the Haunted Repo correctly with none of the 26 quoted spans in its reply, and running unattended from an agent cron.',
    ],
    files: ['.kiro/agents/exorcist-reviewer.json', '.kiro/agents/exorcist-red-team.json', 'exorcist-98-crew/agents/exorcist-sentry.json'],
    evidence: ['`docs/KIRO_LOG.md` rows dated 2026-11-19 (Crew)'],
  },
  {
    id: 'cli',
    title: 'Kiro CLI',
    tool: 'Kiro CLI 3.5.0, headless',
    status: 'Implemented parts of six M5 features, until the usage limit',
    did: [
      '`kiro-cli chat --no-interactive --trust-all-tools` implemented six M5 specs in parallel, one git worktree each. A small driver resumed each conversation (`--resume`) until Kiro printed `DONE:`.',
      'What Kiro wrote is committed on its own, before anything else changed: Ouija decoder `b936a15` (22 files), on-access scanning `3c4047a` (17 files), canary traps `5344468` (14 files), exorcist.lock `59919f5` (6 files), LiveUpdate `dad40f6` (9 files), possession origin `4e2acc2` (7 files). `docs/KIRO_LOG.md` cites the same commits by their ids before the branches were rebased onto main.',
      'Kiro hit the account\'s monthly usage limit part-way. Kiro CLI stopped there.',
    ],
    files: ['docs/KIRO_LOG.md', '.kiro/specs/m5-ouija/tasks.md', '.kiro/specs/m5-on-access/tasks.md'],
    evidence: ['`git log --oneline --grep "partial implementation by Kiro"` lists the six commits'],
  },
  {
    id: 'crew',
    title: 'Kiro Crew',
    tool: 'Kiro Crew 0.12.2 and 0.13.0',
    status: 'Built for it and run inside it',
    did: [
      'A separate Crew app (`pranavsaji/exorcist-98-crew`): the Sentry agent, an agent-hygiene skill, a nightly patrol of project folders, Crew notifications, an MCP rug-pull watch that reads the Shield\'s pin file, and a dashboard page.',
      'Installed and run in Crew 0.12.2 and 0.13.0: install, page, patrol through the gateway proxy, a critical notification ("38 new serious problems found"), the agent in chat, and on a real night the 02:00 patrol and the unattended 02:15 agent cron.',
      'Installing it found seven places where Crew behaves differently from its documentation; each is recorded and handled in that repository.',
    ],
    files: ['exorcist-98-crew/app.json', 'exorcist-98-crew/docs/KNOWN_LIMITATIONS.md', 'exorcist-98-crew/docs/COORDINATION.md'],
    evidence: ['Crew repository (exorcist-98-crew) commits `d13cb2a`, `947822e`, `072c109`, `fc6201a`, `5b36961`, `4f1fbc1`', '`docs/KIRO_LOG.md` rows dated 2026-11-18 to 2026-11-19 (Crew)', '`docs/KNOWN_LIMITATIONS.md` S-021'],
  },
  {
    id: 'pbt',
    title: 'Property-based testing',
    tool: 'Kiro specs and fast-check',
    status: 'Used to build it',
    did: [
      'Each spec names its properties, and each is a fast-check test: "a secret at any depth is never forwarded", "a changed tool is never listed or callable", "quarantine then restore returns the exact bytes", "no tar entry name writes outside the target folder", "a zero-width character is detected at any position".',
      'PBT-SEC-01 caught a real defect in M0: a `process.exit` crash on import. When the browser run found one EX-001 finding per hidden character, PBT-SIG-09 pinned the fix: one finding per run of hidden characters, wherever they are placed.',
    ],
    files: ['packages/core/src/__tests__/secrets-check.property.test.ts', 'packages/shield/src/__tests__/', 'packages/core/src/__tests__/definitions-accuracy.test.ts', 'packages/cli/src/__tests__/init-kiro.test.ts'],
    evidence: ['`git grep -c "fc.assert"` counts the properties', '`docs/KIRO_LOG.md` (PBT rows)'],
  },
];

export const SURPRISES: Story[] = [
  {
    id: 'tool-cache',
    title: 'Kiro caches the MCP tool list, so a rug pull got through',
    story: 'The Shield compared each tool with its pin when the client asked for the tool list. Kiro asks once. So when the demo server changed a tool description after approval, the Shield never saw the new list, and Kiro\'s next call reached the changed tool with no alert. Only running inside Kiro showed this. Now, before every call, the Shield fetches the tool list itself, checks that tool against its pin, refuses a changed one (EX-006), and sends `notifications/tools/list_changed`; if the server will not list its tools, the call is not made.',
    evidence: ['`docs/KNOWN_LIMITATIONS.md` S-001 and S-026', 'Commits `31a8b48`, `4e1ab12`'],
  },
  {
    id: 'hook-path',
    title: 'Hook commands run without Node on PATH, so hooks silently did nothing',
    story: 'The secrets hook blocked correctly when run by hand, but two test commits with a staged fake key went straight through in Kiro. A probe hook that wrote its own environment showed Kiro runs hook commands with `PATH=/usr/bin:/bin:/usr/sbin:/sbin`: no `node`, `npx` or `pnpm`. The hook was firing all along; its command failed with "command not found", which blocks nothing. Every command hook now goes through `scripts/kiro-hook.sh`, which finds Node, and the commit guard blocks rather than lets a commit through when Node cannot be found.',
    evidence: ['`docs/KNOWN_LIMITATIONS.md` L-003', '`scripts/kiro-hook.sh`', 'Commit `ab1fece`'],
  },
  {
    id: 'yaml-hooks',
    title: 'Our first hooks were in a format Kiro does not read',
    story: 'The M0 hooks were written from memory as YAML and never fired. Fetching the documentation showed hooks are JSON (`version: "v1"`, PascalCase triggers such as `PostFileSave`). After the rewrite, `spec-change` fired the first time a spec was saved, which was the evidence the earlier log rows lacked.',
    evidence: ['Commit `a22e9b2`', '`docs/KIRO_LOG.md` rows dated 2026-11-15 (marked superseded) and 2026-11-18 (Hooks)'],
  },
  {
    id: 'settings-blocked',
    title: 'Kiro would not let its agent register our MCP server',
    story: 'Writing `.kiro/settings/mcp.json` from an agent session was blocked twice by a Kiro permission rule, by design. The owner added the file by hand, and Kiro then loaded both servers. `exorcist init --shield` changes that file from the user\'s own terminal, never from an agent.',
    evidence: ['`docs/KNOWN_LIMITATIONS.md` S-003', '`docs/KIRO_SHIELD_TEST.md`'],
  },
  {
    id: 'crew-runner',
    title: 'Crew\'s task runner reported 8/8 passed from an empty sandbox',
    story: 'We tried Kiro Crew\'s autonomous runner (`kirocrew run TASK.md`) on four M5 specs. It reported "8/8 tasks passed" while it had worked in an empty sandbox workspace with shell commands blocked: nothing had been built. The runs were stopped. Lesson: a runner\'s summary is not evidence; check the working tree.',
    evidence: ['`docs/KIRO_LOG.md` row dated 2026-11-23 (Crew)'],
  },
  {
    id: 'cli-narrates',
    title: 'Kiro CLI in headless mode ends its turn when the model narrates',
    story: 'With `--no-interactive`, a turn ends when the model narrates what it will do instead of doing it, so a long task stopped part-way. A small driver resumed each conversation with `--resume` until Kiro printed `DONE:`.',
    evidence: ['`docs/KIRO_LOG.md` row dated 2026-11-23 (CLI)'],
  },
  {
    id: 'usage-limit',
    title: 'The monthly usage limit arrived mid-build',
    story: 'Six Kiro CLI sessions in parallel used up the account\'s monthly limit part-way through (the Ouija decoder had 3 of 5 tasks done, on-access scanning 4 of 5). What Kiro had written was committed as it was, on its own, so its work can be read separately from everything after it.',
    evidence: ['`git log --oneline --grep "partial implementation by Kiro"`'],
  },
  {
    id: 'crew-docs',
    title: 'Crew behaved differently from its docs in seven places',
    story: 'Installing the Crew app found that crons need `permissions.cron`, the proxy header is `X-KiroCrew-Proxy`, the health probe is unsigned, the page must be a React default export, the secret and data folders come from `KIROCREW_HOME`, an agent has no gateway token (so the backend patrols itself), and app notifications need a token exchange. Crew also namespaces an app\'s MCP server as `<app>:<server>`.',
    evidence: ['`docs/KIRO_LOG.md` rows dated 2026-11-19 (Crew)', 'Crew repository (exorcist-98-crew) `docs/KNOWN_LIMITATIONS.md`'],
  },
];


export const USER_SETUP = {
  title: 'What users get',
  text: '`exorcist init --kiro` writes the four Kiro hooks (secrets, MCP-config scan, on-access, and the Stop gate, which stays off until the pinned CLI has `gate`), the steering file, the PATH wrapper for hooks, a git pre-commit hook and the exorcist-reviewer agent, then prints what it set up. `--shield` also puts every server in `.kiro/settings/mcp.json` behind the Real-Time Shield; `exorcist unwrap .kiro/settings/mcp.json` puts the file back byte for byte. `--no-agent` leaves the agent out. Existing files are kept unless `--force` is given.',
  files: ['packages/cli/src/commands/init.ts', 'packages/cli/src/__tests__/init-kiro.test.ts'],
};

export const CHECK_COMMANDS: string[] = [
  'git log --oneline --grep "partial implementation by Kiro"',
  'pnpm exec vitest run packages/cli/src/__tests__/kiro-hook.test.ts',
  'pnpm exec vitest run packages/cli/src/__tests__/kiro-config.test.ts packages/cli/src/__tests__/init-kiro.test.ts',
  'pnpm --filter @exorcist-98/cli build && node packages/cli/dist/index.mjs init --kiro /tmp/kiro-demo',
];

/** docs/HOW_KIRO.md, generated from the content above. */
export function howKiroMarkdown(): string {
  const out: string[] = [
    `# ${HOW_KIRO_TITLE}`,
    '',
    '<!-- Generated from apps/web/src/lib/how-kiro.ts by scripts/how-kiro-md.ts; edit that file, not this one. The /how-kiro page renders the same content. -->',
    '',
    ...HOW_KIRO_INTRO.flatMap((p) => [p, '']),
    '## Kiro features at a glance',
    '',
    '| Feature | Kiro product | Status |',
    '| --- | --- | --- |',
    ...SURFACES.map((s) => `| [${s.title}](#${s.id}) | ${s.tool} | ${s.status} |`),
    '',
  ];
  for (const s of SURFACES) {
    out.push(`<a id="${s.id}"></a>`, '', `## ${s.title}`, '', `**${s.tool}.** ${s.status}.`, '', '**What we did**', '');
    for (const d of s.did) out.push(`- ${d}`);
    out.push('', '**Files**', '');
    for (const f of s.files) out.push(`- \`${f}\``);
    out.push('', '**Evidence**', '');
    for (const e of s.evidence) out.push(`- ${e}`);
    out.push('');
  }
  out.push(`## ${USER_SETUP.title}`, '', USER_SETUP.text, '', ...USER_SETUP.files.map((f) => `- \`${f}\``), '');
  out.push('## Where Kiro surprised us', '');
  for (const st of SURPRISES) {
    out.push(`### ${st.title}`, '', st.story, '', ...st.evidence.map((e) => `- ${e}`), '');
  }
  out.push('## Check it yourself', '', '```sh', ...CHECK_COMMANDS, '```', '');
  return out.join('\n');
}
