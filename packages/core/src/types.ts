/**
 * Central types for packages/core.
 * This file imports nothing from the rest of packages/core.
 */

// ── File classification ───────────────────────────────────────────────────────

export type FileRole =
  | 'instruction'  // steering, AGENTS.md, CLAUDE.md, .cursorrules, README*, etc.
  | 'mcp-config'   // mcp.json paths, claude_desktop_config.json
  | 'hook'         // .kiro/hooks/**, *.hook.yaml
  | 'manifest'     // package.json
  | 'definition'   // definitions/*.yaml
  | 'memory'       // MEMORY.md, .kiro/notes/**, agent-notes*
  | 'power'        // power/**
  | 'docs'         // *.md, *.txt (not matched above)
  | 'code'         // *.ts, *.js, *.py, *.sh
  | 'config'       // *.json, *.yaml, *.toml (not matched above)
  | 'unknown';

export type RepoFile = {
  path:      string;   // absolute path
  rel:       string;   // path relative to repo root
  role:      FileRole;
  sizeBytes: number;
};

// ── Severity ─────────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low';

// ── Findings ─────────────────────────────────────────────────────────────────

export type SignatureFinding = {
  source:   'signature';
  ruleId:   string;
  title:    string;
  severity: Severity;
  file:     string;    // rel path
  line:     number;    // 1-based
  col:      number;    // 1-based
  span:     string;    // exact quoted substring, max 120 chars
  owasp:    string[];
  fix:      string;
};

export type HeuristicFinding = Omit<SignatureFinding, 'source'> & {
  source:     'heuristic';
  rationale:  string;
  confidence: 'high' | 'medium' | 'low';
};

export type Finding = SignatureFinding | HeuristicFinding;

// ── Scan events ───────────────────────────────────────────────────────────────

export type ScanStats = {
  filesScanned:  number;
  filesSkipped:  number;
  findingsTotal: number;
  durationMs:    number;
};

export type ScanEvent =
  | { type: 'file';    file: RepoFile }
  | { type: 'finding'; finding: Finding }
  | { type: 'error';   file: string; message: string }
  | { type: 'done';    stats: ScanStats };

// ── Bedrock client interface ──────────────────────────────────────────────────

export type BedrockParams = {
  model:     'haiku' | 'sonnet';
  prompt:    string;
  maxTokens: number;
};

export type BedrockResult =
  | { ok: true;  raw: string }
  | { ok: false; error: string };

export interface BedrockClient {
  call(params: BedrockParams): Promise<BedrockResult>;
}

// ── Scan options ──────────────────────────────────────────────────────────────

export type ScanOptions = {
  definitionsDir:    string;
  bedrockClient?:    BedrockClient;
  maxFileSizeBytes?: number;
};
