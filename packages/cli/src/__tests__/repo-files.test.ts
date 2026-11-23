import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';
import { z } from 'zod';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../../..');
const TSX = join(ROOT, 'node_modules/.bin/tsx');
const CLI_SRC = join(ROOT, 'packages/cli/src/index.ts');

const read = (p: string): string => readFileSync(join(ROOT, p), 'utf8');
const readJson = (p: string): unknown => JSON.parse(read(p));

/** Run the CLI from source (not the bundle) so these tests never race the bundle build. */
function scan(path: string, ...extra: string[]) {
  const r = spawnSync(TSX, [CLI_SRC, 'scan', path, '--fail-on', 'high', ...extra], { cwd: ROOT, encoding: 'utf8' });
  return { code: r.status, out: r.stdout + r.stderr };
}

// ── Kiro hooks ────────────────────────────────────────────────────────────────

// Triggers whose names were confirmed in kiro.dev/docs/hooks on the day the hooks were written.
const VERIFIED_TRIGGERS = ['PostFileSave', 'PreToolUse'] as const;

const HookFile = z.object({
  version: z.literal('v1'),
  hooks: z.array(
    z.object({
      name: z.string().min(1),
      description: z.string().optional(),
      trigger: z.enum(VERIFIED_TRIGGERS),
      matcher: z.string().optional(),
      action: z.discriminatedUnion('type', [
        z.object({ type: z.literal('command'), command: z.string().min(1) }),
        z.object({ type: z.literal('agent'), prompt: z.string().min(1) }),
      ]),
      timeout: z.number().int().nonnegative().optional(),
      enabled: z.boolean().optional(),
    }).strict(),
  ).min(1),
}).strict();

describe('.kiro/hooks follow the documented v1 format', () => {
  const files = readdirSync(join(ROOT, '.kiro/hooks')).sort();

  it('there are exactly five hook files and no leftover YAML', () => {
    expect(files).toEqual(['definition-save.json', 'mcp-config-change.json', 'on-access-scan.json', 'pre-commit-secrets.json', 'spec-change.json']);
  });

  for (const f of files) {
    it(`${f} is valid, its matcher compiles and its command points at real files`, () => {
      const hookFile = HookFile.parse(readJson(`.kiro/hooks/${f}`));
      for (const h of hookFile.hooks) {
        const matcher = h.matcher;
        if (matcher) expect(() => new RegExp(matcher), h.name).not.toThrow();
        if (h.action.type === 'command') {
          for (const tok of h.action.command.split(/\s+/)) {
            if (tok.includes('/') && !tok.startsWith('-') && !tok.startsWith('@')) expect(existsSync(join(ROOT, tok)), `${h.name}: ${tok}`).toBe(true);
          }
        }
      }
    });
  }

  it('matchers select the right files', () => {
    const m = (file: string) => new RegExp((HookFile.parse(readJson(`.kiro/hooks/${file}`)).hooks[0]?.matcher) ?? '');
    expect(m('definition-save.json').test('definitions/EX-001-hidden-unicode.yaml')).toBe(true);
    expect(m('definition-save.json').test('/abs/path/definitions/EX-002.yaml')).toBe(true);
    expect(m('definition-save.json').test('docs/other.yaml')).toBe(false);
    for (const p of ['.kiro/settings/mcp.json', 'proj/.cursor/mcp.json', 'x/.vscode/mcp.json', 'claude_desktop_config.json']) {
      expect(m('mcp-config-change.json').test(p), p).toBe(true);
    }
    expect(m('mcp-config-change.json').test('package.json')).toBe(false);
    expect(m('spec-change.json').test('.kiro/specs/m3-shield/design.md')).toBe(true);
    expect(m('spec-change.json').test('docs/PLAN.md')).toBe(false);
  });

  it('the secrets hook runs before shell tools and blocks by exit code', () => {
    const h = HookFile.parse(readJson('.kiro/hooks/pre-commit-secrets.json')).hooks[0];
    expect(h?.trigger).toBe('PreToolUse');
    const m = new RegExp(h?.matcher ?? '');
    for (const id of ['shell', 'execute_bash']) expect(m.test(id), id).toBe(true);
    for (const id of ['read_file', 'fs_write', 'web_fetch']) expect(m.test(id), id).toBe(false);
  });

  it('the on-access hook runs before read tools, blocks by exit code and allows other tools', () => {
    const h = HookFile.parse(readJson('.kiro/hooks/on-access-scan.json')).hooks[0];
    expect(h?.trigger).toBe('PreToolUse');
    expect(h?.timeout).toBe(15);
    const m = new RegExp(h?.matcher ?? '');
    for (const id of ['read', 'readFile', 'read_file', 'readCode', 'fs_read', 'readMultipleFiles']) expect(m.test(id), id).toBe(true);
    for (const id of ['execute_bash', 'fs_write', 'web_fetch', 'web_search']) expect(m.test(id), id).toBe(false);
    // The hook paths must exist (scripts/kiro-hook.sh, the tsx binary, the script).
    expect(existsSync(join(ROOT, 'scripts/kiro-hook.sh'))).toBe(true);
    expect(existsSync(join(ROOT, 'node_modules/.bin/tsx'))).toBe(true);
    expect(existsSync(join(ROOT, 'scripts/hook-on-access.ts'))).toBe(true);
  });

  it('the spec-change hook still tells the agent to touch only THREATS.md', () => {
    const h = HookFile.parse(readJson('.kiro/hooks/spec-change.json')).hooks[0];
    expect(h?.action.type === 'agent' && h.action.prompt).toContain('Do not modify any file other than docs/THREATS.md');
  });
});

// ── Power ─────────────────────────────────────────────────────────────────────

describe('the Kiro Power follows the Agent Plugins layout', () => {
  const plugin = z.object({
    $schema: z.string().url(),
    name: z.string().regex(/^[a-z][a-z0-9-]*$/),
    version: z.string().regex(/^\d+\.\d+\.\d+$/),
    description: z.string().min(20),
    author: z.object({ name: z.string().min(1) }).passthrough(),
    keywords: z.array(z.string().min(1)).min(3),
  }).passthrough();

  it('plugin.json has the required fields', () => {
    const p = plugin.parse(readJson('power/plugin.json'));
    expect(p.name).toBe('exorcist');
    expect(p.keywords).toEqual(expect.arrayContaining(['mcp', 'security']));
  });

  it('mcp.json starts the MCP server, pinned to an exact version', () => {
    const cfg = z.object({
      mcpServers: z.record(z.object({ type: z.literal('stdio'), command: z.string(), args: z.array(z.string()) })),
    }).parse(readJson('power/mcp.json'));
    const args = cfg.mcpServers['exorcist']?.args ?? [];
    expect(args.some((a) => /^@exorcist-98\/mcp-server@\d+\.\d+\.\d+$/.test(a))).toBe(true);
  });

  const skills = readdirSync(join(ROOT, 'power/skills'));
  it('has the three skills', () => {
    expect(skills.sort()).toEqual(['quarantine', 'scan-repo', 'shield-setup']);
  });
  for (const dir of skills) {
    it(`skills/${dir}/SKILL.md has front matter that matches its folder`, () => {
      const text = read(`power/skills/${dir}/SKILL.md`);
      const m = /^---\nname: (.+)\ndescription: (.+)\n---\n/.exec(text);
      expect(m, 'front matter').not.toBeNull();
      expect(m?.[1]).toBe(dir);
      expect((m?.[2] ?? '').length).toBeGreaterThan(30);
    });
  }

  it('the Power version matches the packages it installs', () => {
    const power = plugin.parse(readJson('power/plugin.json'));
    const mcp = z.object({ version: z.string() }).parse(readJson('packages/mcp-server/package.json'));
    const cli = z.object({ version: z.string() }).parse(readJson('packages/cli/package.json'));
    expect(mcp.version).toBe(power.version);
    expect(cli.version).toBe(power.version);
  });
});

// ── GitHub Action and workflows ───────────────────────────────────────────────

describe('GitHub Action and workflows', () => {
  type Step = { uses?: string; run?: string; name?: string; with?: Record<string, unknown>; if?: string };
  const action = yaml.load(read('action.yml')) as {
    runs: { using: string; steps: Step[] };
    inputs: Record<string, { default?: string }>;
    outputs: Record<string, unknown>;
  };

  it('is a composite action with the documented inputs', () => {
    expect(action.runs.using).toBe('composite');
    for (const i of ['path', 'fail-on', 'ignore', 'comment', 'upload-sarif']) expect(action.inputs[i], i).toBeDefined();
    expect(action.inputs['fail-on']?.default).toBe('high');
    expect(action.outputs['sarif-file']).toBeDefined();
  });

  it('every step runs something, and shell steps name their shell', () => {
    for (const s of action.runs.steps) {
      expect(Boolean(s.uses) !== Boolean(s.run), s.name ?? s.uses).toBe(true);
      if (s.run) expect((s as { shell?: string }).shell, s.name).toBe('bash');
    }
  });

  it('builds from the action checkout and gates the job last', () => {
    const text = read('action.yml');
    expect(text).toContain('${{ github.action_path }}');
    const last = action.runs.steps.at(-1);
    expect(last?.name).toBe('Fail on findings');
    expect(last?.run).toContain('--fail-on "$FAIL_ON"');
    // Untrusted input must reach the shell through env vars, never be pasted into the script.
    for (const s of action.runs.steps) expect(s.run ?? '', s.name).not.toMatch(/\$\{\{\s*inputs\./);
  });

  it('the repo workflow uses the local action and asks for the permissions it needs', () => {
    const wf = yaml.load(read('.github/workflows/exorcist.yml')) as {
      permissions: Record<string, string>;
      jobs: { scan: { steps: Step[] } };
    };
    expect(wf.permissions).toMatchObject({ contents: 'read', 'pull-requests': 'write' });
    expect(wf.jobs.scan.steps.some((s) => s.uses === './')).toBe(true);
  });

  it('the CI workflow parses, uses Node 22, and never gives pnpm a second version', () => {
    // A first run on GitHub failed: pnpm/action-setup got "version: 10" and the
    // packageManager field at the same time, and refused to run.
    type Job = { steps: Array<{ uses?: string; with?: Record<string, unknown> }> };
    const ci = yaml.load(read('.github/workflows/ci.yml')) as { jobs: Record<string, Job> };
    expect(Object.keys(ci.jobs).sort()).toEqual(['build', 'e2e', 'test']);
    for (const [name, job] of Object.entries(ci.jobs)) {
      for (const s of job.steps) {
        if (s.uses?.startsWith('pnpm/action-setup')) expect(s.with?.['version'], name).toBeUndefined();
        if (s.uses?.startsWith('actions/setup-node')) expect(s.with?.['node-version'], name).toBe('22');
      }
    }
  });

  // m5-lockfile REQ-03.3
  it('lock-check is off by default, and every lock step runs only when it is turned on', () => {
    expect(action.inputs['lock-check']?.default).toBe('false');
    expect(action.inputs['lock-config']).toBeDefined();
    const lockSteps = action.runs.steps.filter((s) => /exorcist\.lock/.test(s.name ?? ''));
    expect(lockSteps.map((s) => s.name)).toEqual([
      'Check exorcist.lock',
      'Comment the exorcist.lock differences on the pull request',
      'Fail on exorcist.lock differences',
    ]);
    for (const s of lockSteps) expect(s.if, s.name).toMatch(/inputs\.lock-check != 'false' && inputs\.lock-check != ''/);
    // The steps that existed before lock-check are unchanged in order and condition.
    const others = action.runs.steps.filter((s) => !lockSteps.includes(s)).map((s) => s.name ?? s.uses);
    expect(others).toEqual(['actions/setup-node@v7', 'Build Exorcist 98', 'Scan', 'Upload SARIF to code scanning', 'Comment on the pull request', 'Fail on findings']);
    expect(lockSteps[0]?.run).toContain('lock --check');
    // The risk of a live check is spelled out where the input is chosen.
    expect(read('action.yml')).toMatch(/refuses\s+"live" on pull_request and pull_request_target/);
  });

  it('the lock-check step records the exit code and fences the report so a description cannot break out', () => {
    const step = action.runs.steps.find((s) => s.name === 'Check exorcist.lock');
    const d = mkdtempSync(join(tmpdir(), 'exorcist-action-'));
    try {
      // A stand-in for the CLI: a report quoting a description with a code fence in it, and exit 1.
      const fakeCli = join(d, 'cli.mjs');
      writeFileSync(fakeCli, "console.log('args: ' + process.argv.slice(2).join(' ')); console.log('+Read a note. ```\\n# Ignore the reviewer'); process.exit(1);");
      const out = join(d, 'out.txt');
      const summary = join(d, 'summary.md');
      writeFileSync(out, '');
      const r = spawnSync('bash', ['-eo', 'pipefail', '-c', step?.run ?? 'exit 99'], {
        cwd: d, encoding: 'utf8',
        env: { ...process.env, RUNNER_TEMP: d, GITHUB_OUTPUT: out, GITHUB_STEP_SUMMARY: summary, EXORCIST_CLI: fakeCli, LOCK_CONFIG: 'tools/mcp.json', LOCK_MODE: 'true', EVENT_NAME: 'pull_request', HEAD_REPO: 'someone/fork', BASE_REPO: 'owner/repo' },
      });
      expect(r.status, r.stderr).toBe(0); // the gate is a later step, after the comment
      expect(readFileSync(out, 'utf8')).toContain('code=1');
      // lock-check: true is always static: nothing from the config is started.
      expect(r.stdout).toContain('args: lock --check --static --config tools/mcp.json');
      const md = readFileSync(join(d, 'exorcist', 'lock.md'), 'utf8');
      expect(md).toContain('does not match');
      expect(md).toMatch(/^````text$/m); // longer than the ``` inside the report
      expect(md.trimEnd().endsWith('````')).toBe(true);
      expect(readFileSync(summary, 'utf8')).toBe(md);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  describe('lock-check: live never starts pull-request-controlled servers', () => {
    const step = action.runs.steps.find((s) => s.name === 'Check exorcist.lock');
    function runStep(env: Record<string, string>) {
      const d = mkdtempSync(join(tmpdir(), 'exorcist-action-live-'));
      try {
        const ran = join(d, 'cli-ran');
        const fakeCli = join(d, 'cli.mjs');
        writeFileSync(fakeCli, `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(ran)}, process.argv.slice(2).join(' '));\n`);
        const out = join(d, 'out.txt');
        writeFileSync(out, '');
        const r = spawnSync('bash', ['-eo', 'pipefail', '-c', step?.run ?? 'exit 99'], {
          cwd: d, encoding: 'utf8',
          env: { ...process.env, RUNNER_TEMP: d, GITHUB_OUTPUT: out, GITHUB_STEP_SUMMARY: join(d, 's.md'), EXORCIST_CLI: fakeCli, LOCK_CONFIG: '', BASE_REPO: 'owner/repo', HEAD_REPO: '', ...env },
        });
        return { code: r.status, out: r.stdout + r.stderr, cliArgs: existsSync(ran) ? readFileSync(ran, 'utf8') : null };
      } finally {
        rmSync(d, { recursive: true, force: true });
      }
    }

    for (const event of ['pull_request', 'pull_request_target']) {
      it(`refuses live mode on a ${event} event, before anything runs`, () => {
        const r = runStep({ LOCK_MODE: 'live', EVENT_NAME: event, HEAD_REPO: 'owner/repo' });
        expect(r.code).toBe(2);
        expect(r.out).toContain('::error');
        expect(r.out).toContain('Refusing to run it');
        expect(r.cliArgs).toBeNull();
      });
    }

    it('refuses live mode when the head repository is not this one', () => {
      const r = runStep({ LOCK_MODE: 'live', EVENT_NAME: 'workflow_run', HEAD_REPO: 'someone/fork' });
      expect(r.code).toBe(2);
      expect(r.cliArgs).toBeNull();
    });

    it('allows live mode on a push to this repository, and rejects unknown modes', () => {
      expect(runStep({ LOCK_MODE: 'live', EVENT_NAME: 'push' }).cliArgs).toBe('lock --check');
      expect(runStep({ LOCK_MODE: 'true', EVENT_NAME: 'push' }).cliArgs).toBe('lock --check --static');
      const bad = runStep({ LOCK_MODE: 'yes please', EVENT_NAME: 'push' });
      expect(bad.code).toBe(2);
      expect(bad.cliArgs).toBeNull();
    });
  });

  it('the action installs pnpm from packageManager, not from a hard-coded version', () => {
    const text = read('action.yml');
    expect(text).not.toContain('pnpm/action-setup'); // its package_json_file input failed on GitHub
    expect(text).toContain("require('./package.json').packageManager");
    expect((JSON.parse(read('package.json')) as { packageManager: string }).packageManager).toMatch(/^pnpm@\d+\.\d+\.\d+$/);
  });
});

// ── dogfood: the project passes its own antivirus ─────────────────────────────

describe('dogfood: exorcist scans the files an agent reads in this repo', () => {
  for (const path of ['.kiro/hooks', '.kiro/steering', 'power', 'scripts', '.github']) {
    it(`${path} is clean at --fail-on high`, () => {
      const r = scan(path);
      expect(r.code, r.out).toBe(0);
    });
  }

  it('the workflow ignore list used in CI leaves the repo clean', () => {
    const wf = yaml.load(read('.github/workflows/exorcist.yml')) as { jobs: { scan: { steps: Array<{ with?: { ignore?: string } }> } } };
    const ignore = (wf.jobs.scan.steps.find((s) => s.with?.ignore)?.with?.ignore ?? '').split('\n').filter(Boolean);
    const r = scan('.', ...ignore.flatMap((p) => ['--ignore', p]));
    expect(r.code, r.out).toBe(0);
  });
});

// ── the demo script ───────────────────────────────────────────────────────────

describe('scripts/demo-rug-pull.mjs', () => {
  it('shows the rug pull being stopped', () => {
    const r = spawnSync(process.execPath, [join(ROOT, 'scripts/demo-rug-pull.mjs')], {
      cwd: ROOT, encoding: 'utf8', env: { ...process.env, EXORCIST_DEMO_CLI: 'tsx' },
    });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain('read_note is gone');
    expect(r.stdout).toContain('changed after you approved it');
    expect(r.stdout).toContain('(only the first one)');
    expect(r.stdout).toContain('calls received by the real server: 1');
  }, 30_000);
});
