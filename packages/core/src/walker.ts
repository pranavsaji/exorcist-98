import { opendir, stat, open } from 'node:fs/promises';
import { join, relative, extname, basename } from 'node:path';
import type { FileRole, RepoFile } from './types.js';

const MAX_FILE_SIZE = 1_048_576; // 1 MB
const BINARY_PROBE  = 512;       // bytes to read for binary detection

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', '.next', '.pnpm-store',
  '.turbo', 'coverage', '.nyc_output',
]);

// ── Classification ────────────────────────────────────────────────────────────

/**
 * Classify a repo-relative path into a FileRole.
 * Rules are evaluated in priority order; first match wins.
 */
export function classifyFile(rel: string): FileRole {
  const norm = rel.replace(/\\/g, '/');
  const base = basename(norm);
  const ext  = extname(norm).toLowerCase();

  // 1 — instruction: every file an AI coding agent reads as instructions.
  // The Rules File Backdoor research targets these (Cursor, Cline, Windsurf,
  // Copilot, Claude Code, Gemini, Kiro).
  if (
    base === 'AGENTS.md' ||
    base === 'AGENT.md' ||
    base === 'CLAUDE.md' ||
    base === 'CLAUDE.local.md' ||
    base === 'GEMINI.md' ||
    base === '.cursorrules' ||
    base === '.windsurfrules' ||
    base === '.clinerules' ||
    norm.startsWith('.clinerules/') ||
    norm.startsWith('.cursor/rules/') ||
    norm.startsWith('.windsurf/rules/') ||
    norm.startsWith('.amazonq/rules/') ||
    norm === '.github/copilot-instructions.md' ||
    norm.startsWith('.github/instructions/') ||
    norm.startsWith('.github/prompts/') ||
    /^\.claude\/(commands|agents|skills)\//.test(norm) ||
    base === 'SKILL.md' ||
    base.startsWith('README') ||
    norm.startsWith('.kiro/steering/')
  ) return 'instruction';

  // 2 — mcp-config
  if (
    norm.endsWith('.kiro/settings/mcp.json') ||
    norm.endsWith('.cursor/mcp.json')        ||
    norm.endsWith('.vscode/mcp.json')        ||
    norm.endsWith('.amazonq/mcp.json')       ||
    norm.endsWith('.gemini/settings.json')   ||
    norm.endsWith('.claude/settings.json')   ||
    norm.endsWith('.claude/settings.local.json') ||
    norm === 'mcp.json' || norm === '.mcp.json' ||
    base === 'claude_desktop_config.json'
  ) return 'mcp-config';

  // 3 — hook
  if (norm.startsWith('.kiro/hooks/') || base.endsWith('.hook.yaml')) return 'hook';

  // 4 — manifest
  if (base === 'package.json') return 'manifest';

  // 5 — definition
  if (norm.startsWith('definitions/') && ext === '.yaml') return 'definition';

  // 6 — memory
  if (
    base === 'MEMORY.md' ||
    norm.startsWith('.kiro/notes/') ||
    base.startsWith('agent-notes')
  ) return 'memory';

  // 7 — power
  if (norm.startsWith('power/')) return 'power';

  // 8 — docs
  if (ext === '.md' || ext === '.txt') return 'docs';

  // 9 — code
  if (['.ts', '.js', '.mjs', '.cjs', '.py', '.sh', '.bash'].includes(ext)) return 'code';

  // 10 — config
  if (['.json', '.yaml', '.yml', '.toml'].includes(ext)) return 'config';

  return 'unknown';
}

// ── Binary detection ──────────────────────────────────────────────────────────

async function isBinary(filePath: string): Promise<boolean> {
  const fh = await open(filePath, 'r');
  try {
    const buf = Buffer.alloc(BINARY_PROBE);
    const { bytesRead } = await fh.read(buf, 0, BINARY_PROBE, 0);
    return buf.slice(0, bytesRead).includes(0x00);
  } finally {
    await fh.close();
  }
}

// ── Walker ────────────────────────────────────────────────────────────────────

export async function* walkRepo(root: string): AsyncIterable<RepoFile> {
  yield* walkDir(root, root);
}

async function* walkDir(root: string, dir: string): AsyncIterable<RepoFile> {
  const dh = await opendir(dir);
  for await (const entry of dh) {
    const absPath = join(dir, entry.name);
    const rel     = relative(root, absPath).replace(/\\/g, '/');

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walkDir(root, absPath);
    } else if (entry.isFile()) {
      const info = await stat(absPath);
      if (info.size > MAX_FILE_SIZE) continue;
      if (await isBinary(absPath))   continue;
      yield {
        path:      absPath,
        rel,
        role:      classifyFile(rel),
        sizeBytes: info.size,
      };
    }
  }
}
