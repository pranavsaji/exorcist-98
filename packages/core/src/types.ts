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
  | 'tool-result'  // text returned by an MCP tool (Shield only; never from the walker)
  | 'unknown';

export type RepoFile = {
  path:      string;   // absolute path
  rel:       string;   // path relative to repo root
  role:      FileRole;
  sizeBytes: number;
  /** An agent-facing file over the hard size limit: not read, reported as EX-026. */
  tooLarge?: true;
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
  /**
   * When a hidden run decodes (Ouija decoder), the message it carries, at
   * most 500 characters. Attacker text: displayed only, never prompted.
   */
  decoded?: string;
};

export type HeuristicFinding = Omit<SignatureFinding, 'source'> & {
  source:     'heuristic';
  rationale:  string;
  confidence: 'high' | 'medium' | 'low';
};

export type Finding = SignatureFinding | HeuristicFinding;

// ── Capabilities and the Haunted House Map (EX-023) ───────────────────────────

/** The three legs of the lethal trifecta. */
export type Capability = 'private-data' | 'untrusted-input' | 'exfiltration';

/** Why a server or ability sits on a leg: which capability rule matched, on what. */
export type CapabilityReason = {
  capability: Capability;
  ruleId:     string;   // CAP-NNN in definitions/capabilities.yaml
  label:      string;   // plain language, e.g. "reads web pages"
  evidence:   string;   // the package, tool or ability that matched
};

/** One enabled MCP server (or built-in agent ability) in a config: a ghost on the map. */
export type MapGhost = {
  name:         string;
  kind:         'server' | 'ability';
  capabilities: Capability[];
  reasons:      CapabilityReason[];
  /** Some of its tools run without asking the user (autoApprove, alwaysAllow, trust, permissions.allow). */
  autoApproved: boolean;
};

/** The Haunted House Map of one MCP config file. */
export type ConfigMap = {
  file:      string;   // rel path
  ghosts:    MapGhost[];
  /** Names of the ghosts on each leg, sorted. */
  legs:      Record<Capability, string[]>;
  trifecta:  boolean;
  /** EX-023 severity when `trifecta`, else null. */
  severity:  'critical' | 'high' | null;
};

export type HauntedMap = { configs: ConfigMap[] };

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
  /** Sent once before `done` when the scan found at least one MCP config. */
  | { type: 'map';     map: HauntedMap }
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

// ── Detonation Chamber client (m5-detonation) ────────────────────────────────

/** One content block of a sandbox conversation (Anthropic Messages format). */
export type ChamberBlock =
  | { type: 'text'; text: string }
  | { type: 'tool_use'; id: string; name: string; input: Record<string, unknown> }
  | { type: 'tool_result'; tool_use_id: string; content: string };

export type ChamberMessage = { role: 'user' | 'assistant'; content: ChamberBlock[] };

/** A fake tool offered to the sandboxed model. It is never executed. */
export type ChamberTool = { name: string; description: string; input_schema: Record<string, unknown> };

export type ChamberRequest = {
  system:      string;
  messages:    ChamberMessage[];
  tools:       ChamberTool[];
  maxTokens:   number;
  temperature: number;
};

/** The model's raw response body, unvalidated: the chamber checks it with zod. */
export type ChamberResult =
  | { ok: true;  body: unknown }
  | { ok: false; error: string };

/** A model that can be offered tools (Bedrock, or a fake in tests). */
export interface ChamberClient {
  converse(request: ChamberRequest): Promise<ChamberResult>;
}

// ── Scan options ──────────────────────────────────────────────────────────────

export type ScanOptions = {
  definitionsDir:    string;
  bedrockClient?:    BedrockClient;
  maxFileSizeBytes?: number;
  /**
   * Local scans only: report findings in verified Quarantine Vault backups at
   * low severity with a note (see vault-trust.ts). Never set for remote,
   * uploaded or MCP-server scans; there the vault folder is ordinary files.
   */
  trustVault?:       boolean;
};
