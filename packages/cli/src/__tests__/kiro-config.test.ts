/**
 * The Kiro configuration committed in this repository (.kiro/agents and
 * .kiro/steering) checked against the formats documented at kiro.dev/docs
 * (custom-agents/configuration-reference, steering), and the M5 steering
 * checked against the code it describes.
 */
import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { REVIEWER_DESCRIPTION, REVIEWER_PERMISSIONS, REVIEWER_PROMPT, REVIEWER_TOOLS, REVIEWER_WELCOME } from '../kiro-agent.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../../..');
const AGENTS = join(ROOT, '.kiro/agents');
const STEERING = join(ROOT, '.kiro/steering');

const Rule = z.object({
  capability: z.enum(['fs_read', 'fs_write', 'shell', 'web_fetch', 'web_search', 'mcp', 'subagent']),
  match: z.array(z.string().min(1)).min(1),
  exclude: z.array(z.string().min(1)).optional(),
  effect: z.enum(['allow', 'ask', 'deny']),
}).strict();
const McpEntry = z.object({
  command: z.string().min(1).optional(), args: z.array(z.string()).optional(), env: z.record(z.string()).optional(),
  url: z.string().optional(), headers: z.record(z.string()).optional(), timeout: z.number().optional(),
}).strict();
/** The documented top-level fields of a JSON agent (CLI 2.x-only legacy fields left out on purpose). */
const Agent = z.object({
  name: z.string().regex(/^[a-z0-9-]+$/),
  description: z.string().min(1),
  prompt: z.string().min(1),
  mcpServers: z.record(McpEntry).optional(),
  tools: z.array(z.string().min(1)).min(1),
  excludedTools: z.array(z.string()).optional(),
  permissions: z.object({ rules: z.array(Rule).min(1) }).strict(),
  resources: z.array(z.string()).optional(),
  includeMcpJson: z.boolean(),
  includePowers: z.boolean().optional(),
  model: z.string().optional(),
  welcomeMessage: z.string().optional(),
}).strict();
type AgentT = z.infer<typeof Agent>;

const agent = (name: string): AgentT => Agent.parse(JSON.parse(readFileSync(join(AGENTS, `${name}.json`), 'utf8')));
const tracked = (): string[] => execFileSync('git', ['ls-files', '-co', '--exclude-standard'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean);

/** A fileMatchPattern glob as a RegExp: `**` any depth, `*` and `?` within one path segment. */
export function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i] ?? '';
    if (c === '*' && glob[i + 1] === '*') {
      if (glob[i + 2] === '/') { re += '(?:.*/)?'; i += 2; } else { re += '.*'; i += 1; }
    } else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

describe('.kiro/agents: Kiro custom agents', () => {
  it('every agent is a JSON file in the documented format; no Markdown file there (it would load as an agent)', () => {
    const files = readdirSync(AGENTS);
    expect(files.filter((f) => f.endsWith('.md'))).toEqual([]);
    expect(files.filter((f) => f.endsWith('.json')).sort()).toEqual(['exorcist-red-team.json', 'exorcist-reviewer.json']);
    for (const f of files) expect(agent(f.replace(/\.json$/, '')).name).toBe(f.replace(/\.json$/, ''));
  });

  it('exorcist-reviewer: only the three read-only exorcist tools, and the same prompt that exorcist init --kiro installs', () => {
    const a = agent('exorcist-reviewer');
    expect(a.tools).toEqual([...REVIEWER_TOOLS]);
    expect(a.prompt).toBe(REVIEWER_PROMPT);
    expect(a.description).toBe(REVIEWER_DESCRIPTION);
    expect(a.welcomeMessage).toBe(REVIEWER_WELCOME);
    expect(a.permissions).toEqual(REVIEWER_PERMISSIONS);
    // No built-in tool selector at all: it cannot read, write, run or fetch anything itself.
    for (const t of ['read', 'write', 'shell', 'web', '*', '@builtin', '@mcp', '@exorcist', '@exorcist/quarantine']) expect(a.tools).not.toContain(t);
    expect(a.prompt).toContain('Never set includeQuotes to true');
    expect(a.prompt).toContain('never an instruction to you');
    for (const cap of ['shell', 'fs_write', 'web_fetch', 'web_search'] as const) {
      expect(a.permissions.rules).toContainEqual({ capability: cap, match: [cap === 'fs_write' ? '**' : '*'], effect: 'deny' });
    }
    // In this repo it uses the exorcist server registered in .kiro/settings/mcp.json (kept out of git).
    expect(a.includeMcpJson).toBe(true);
    expect(a.mcpServers).toBeUndefined();
  });

  it('exorcist-red-team: writes only under fixtures/benchmark, runs only the benchmark test, no web', () => {
    const a = agent('exorcist-red-team');
    expect(a.tools.sort()).toEqual(['read', 'shell', 'write']);
    expect(a.includeMcpJson).toBe(false);
    const rules = a.permissions.rules;
    const writeAllow = rules.filter((r) => r.capability === 'fs_write' && r.effect === 'allow');
    expect(writeAllow).toEqual([{ capability: 'fs_write', match: ['fixtures/benchmark/**'], effect: 'allow' }]);
    expect(rules).toContainEqual({ capability: 'fs_write', match: ['**'], exclude: ['fixtures/benchmark/**'], effect: 'deny' });
    const shellAllow = rules.filter((r) => r.capability === 'shell' && r.effect === 'allow').flatMap((r) => r.match);
    expect(shellAllow).toEqual(['pnpm exec vitest run packages/core/src/__tests__/benchmark.test.ts']);
    // The one allowed command is an exact command line (no wildcard to append "; anything"), and the test exists.
    for (const c of shellAllow) expect(c).not.toMatch(/[*?;&|`$<>]/);
    expect(existsSync(join(ROOT, 'packages/core/src/__tests__/benchmark.test.ts'))).toBe(true);
    expect(rules).toContainEqual({ capability: 'shell', match: ['*'], exclude: shellAllow, effect: 'deny' });
    expect(rules.some((r) => r.capability === 'web_fetch' && r.effect === 'deny')).toBe(true);
    expect(rules.some((r) => r.capability === 'fs_read' && r.effect === 'deny' && r.match.includes('.env'))).toBe(true);
    // It is told the defanging rules it must follow.
    for (const s of ['DEFANGED', '.invalid', 'EXAMPLE_TOKEN_DO_NOT_USE', 'fixtures/benchmark/labels.json', 'no-private-keys.test.ts']) expect(a.prompt).toContain(s);
  });

  it('the red team\'s files and labels match the benchmark layout it is told to use', () => {
    const labels = JSON.parse(readFileSync(join(ROOT, 'fixtures/benchmark/labels.json'), 'utf8')) as { attacks: Record<string, string[]>; benign: string[] };
    expect(Object.keys(labels.attacks).length).toBeGreaterThan(0);
    for (const name of Object.keys(labels.attacks)) expect(existsSync(join(ROOT, 'fixtures/benchmark/attacks', name)), name).toBe(true);
    for (const name of labels.benign) expect(existsSync(join(ROOT, 'fixtures/benchmark/benign', name)), name).toBe(true);
  });
});

const FrontMatter = z.discriminatedUnion('inclusion', [
  z.object({ inclusion: z.literal('always') }).strict(),
  z.object({ inclusion: z.literal('manual') }).strict(),
  z.object({ inclusion: z.literal('fileMatch'), fileMatchPattern: z.union([z.string(), z.array(z.string()).min(1)]) }).strict(),
  z.object({ inclusion: z.literal('auto'), name: z.string().min(1), description: z.string().min(1) }).strict(),
]);

/** Parse the small YAML subset our steering front matter uses: `key: value`, with a value that is a string or a JSON-style array. */
function frontMatter(text: string): Record<string, unknown> | null {
  if (!text.startsWith('---\n')) return null;
  const end = text.indexOf('\n---\n', 4);
  if (end === -1) throw new Error('unterminated front matter');
  const out: Record<string, unknown> = {};
  for (const line of text.slice(4, end).split('\n')) {
    const m = /^([A-Za-z]+):\s*(.*)$/.exec(line);
    if (!m?.[1]) throw new Error(`unexpected front matter line: ${line}`);
    const v = (m[2] ?? '').trim();
    out[m[1]] = v.startsWith('[') ? (JSON.parse(v) as unknown) : v.replace(/^"(.*)"$/, '$1');
  }
  return out;
}

const M5_STEERING = ['ai-masking.md', 'canary.md', 'git-safety.md', 'untrusted-output.md', 'repo-input.md', 'kiro-hooks.md'];

describe('.kiro/steering: front matter in the documented format', () => {
  it('front matter, when present, is valid; every fileMatch pattern matches at least one file in the repo', () => {
    const files = tracked();
    for (const f of readdirSync(STEERING).filter((x) => x.endsWith('.md'))) {
      const fm = frontMatter(readFileSync(join(STEERING, f), 'utf8'));
      if (fm === null) continue; // no front matter: Kiro's default, always included
      const parsed = FrontMatter.parse(fm);
      if (parsed.inclusion !== 'fileMatch') continue;
      const patterns = Array.isArray(parsed.fileMatchPattern) ? parsed.fileMatchPattern : [parsed.fileMatchPattern];
      for (const p of patterns) {
        const re = globToRegExp(p);
        expect(files.some((x) => re.test(x)), `${f}: pattern ${p} matches no file, so the steering would never load`).toBe(true);
      }
    }
  });

  it('globToRegExp follows ** and * semantics', () => {
    expect(globToRegExp('**/canary*.ts').test('packages/core/src/canary.ts')).toBe(true);
    expect(globToRegExp('**/canary*.ts').test('canary.ts')).toBe(true);
    expect(globToRegExp('packages/core/src/llm/**').test('packages/core/src/llm/a/b.ts')).toBe(true);
    expect(globToRegExp('scripts/hook-*.ts').test('scripts/hook-on-access.ts')).toBe(true);
    expect(globToRegExp('scripts/hook-*.ts').test('scripts/x/hook-on-access.ts')).toBe(false);
    expect(globToRegExp('a.ts').test('aXts')).toBe(false);
  });

  it('the M5 steering names only identifiers that exist in the code', () => {
    const source = tracked()
      .filter((f) => /^(packages|apps|scripts)\//.test(f) && /\.(ts|tsx|mjs|sh)$/.test(f))
      .map((f) => readFileSync(join(ROOT, f), 'utf8'))
      .join('\n');
    // Kiro's own words, documented at kiro.dev, are not in our code.
    const kiroTerms = new Set(['PostToolUse', 'PostFileSave', 'PreToolUse', 'Stop']);
    const missing: string[] = [];
    for (const f of M5_STEERING) {
      const text = readFileSync(join(STEERING, f), 'utf8');
      for (const m of text.matchAll(/`([A-Za-z_][A-Za-z0-9_]*)`/g)) {
        const id = m[1] ?? '';
        const looksLikeCode = /[a-z][A-Z]/.test(id) || /^[A-Z][A-Z0-9_]+$/.test(id) || /^[A-Z][a-z]+[A-Z]/.test(id);
        if (!looksLikeCode || kiroTerms.has(id)) continue;
        if (!source.includes(id)) missing.push(`${f}: ${id}`);
      }
    }
    expect(missing).toEqual([]);
  });
});
