/**
 * The scan itself: the core scanner run on one document's text, in memory, so
 * unsaved edits are checked as they are typed. Reads only the bundled virus
 * definitions; never touches the network and never runs anything.
 *
 * What runs: every signature rule (scanText), and for MCP configs the
 * lethal-trifecta check (EX-023) on that config alone. What does not: the
 * optional AI judge (needs AWS), canary-trap matching (needs the per-install
 * records file) and Shield pins; use `exorcist scan` for those.
 *
 * No `vscode` import.
 */
import {
  analyzeConfig, loadCapabilityRules, loadDefinitions, parseMcpConfig, scanText, trifectaFinding,
} from '@exorcist-98/core';
import type { CapabilityRule, FileRole, Finding, Severity, VirusDefinition } from '@exorcist-98/core';

/**
 * An agent file past this size is not read; it is reported as EX-026, as the
 * CLI's walker does (AGENT_FILE_HARD_LIMIT in packages/core/src/walker.ts).
 */
export const HARD_LIMIT_CHARS = 10 * 1_048_576;

export const SEVERITY_ORDER: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function meetsThreshold(severity: Severity, minimum: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[minimum];
}

export function isSeverity(v: unknown): v is Severity {
  return v === 'low' || v === 'medium' || v === 'high' || v === 'critical';
}

export class GhostScanner {
  private constructor(
    readonly definitions: readonly VirusDefinition[],
    private readonly capabilityRules: readonly CapabilityRule[],
  ) {}

  /** Load the definitions (and the capability rules for EX-023) from a folder. */
  static async load(definitionsDir: string): Promise<GhostScanner> {
    const defs = await loadDefinitions(definitionsDir);
    if (defs.length === 0) throw new Error(`No virus definitions were found in ${definitionsDir}.`);
    const caps = await loadCapabilityRules(definitionsDir);
    return new GhostScanner(defs, caps.ok ? caps.rules : []);
  }

  /** Every finding in `text`, sorted by position. `rel` is the workspace-relative path. */
  scan(text: string, rel: string, role: FileRole): Finding[] {
    if (text.length > HARD_LIMIT_CHARS) return this.tooLarge(rel, text.length);
    const findings: Finding[] = scanText(text, role, [...this.definitions], rel);
    if (this.capabilityRules.length > 0) {
      const cfg = parseMcpConfig(rel, role, text);
      if (cfg) {
        const f = trifectaFinding(cfg, analyzeConfig(cfg, this.capabilityRules), this.definitions);
        if (f) findings.push(f);
      }
    }
    return dedupe(findings).sort((a, b) => a.line - b.line || a.col - b.col || a.ruleId.localeCompare(b.ruleId));
  }

  /** EX-026 for an agent file too large to read (size in characters or bytes). */
  tooLarge(rel: string, size: number): Finding[] {
    // Like the orchestrator: EX-026 is disabled as a signature (it never matches text) but is reported by code.
    const def = this.definitions.find((d) => d.id === 'EX-026');
    if (!def) return [];
    return [{
      source: 'signature', ruleId: def.id, title: def.title, severity: def.severity as Severity,
      file: rel, line: 1, col: 1, span: `${Math.round(size / 1_048_576)} MB, not checked`, owasp: def.owasp, fix: def.fix,
    }];
  }
}

/** One finding per rule and position. */
export function dedupe(findings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.ruleId}:${f.line}:${f.col}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
