import { readFile } from 'node:fs/promises';
import { loadDefinitions } from '../definitions/loader.js';
import { canariesPath, findCanaryInText, isCanaryHome, lineColOf, loadCanariesFile } from '../canary.js';
import type { Canary } from '../canary.js';
import type { VirusDefinition } from '../definitions/schema.js';
import { walkRepo } from '../walker.js';
import { normalize } from '../normalizer.js';
import { runSignatures } from './signature-engine.js';
import { runHeuristics } from './heuristic-engine.js';
import { loadCapabilityRules } from '../capabilities.js';
import type { CapabilityRule } from '../capabilities.js';
import { analyzeConfig, parseMcpConfig, readPins, trifectaFinding } from '../trifecta.js';
import type { ParsedMcpConfig } from '../trifecta.js';
import type { Finding, HauntedMap, ScanEvent, ScanOptions, SignatureFinding } from '../types.js';

export type { ScanOptions } from '../types.js';

function dedupeKey(f: Finding): string {
  return `${f.ruleId}:${f.file}:${f.line}:${f.col}`;
}

/**
 * One finding per rule and position, and no AI (heuristic) finding on a line a
 * signature already reported in the same file: the signature is exact and
 * explains itself, so the heuristic one would only repeat it (L-019).
 */
export function deduplicate(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const signatureLines = new Set(findings.filter((f) => f.source === 'signature').map((f) => `${f.file}:${f.line}`));
  return findings.filter(f => {
    if (f.source === 'heuristic' && signatureLines.has(`${f.file}:${f.line}`)) return false;
    const key = dedupeKey(f);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const EX022_DEFAULTS = {
  owasp: ['LLM02:2025 Sensitive Information Disclosure', 'ASI05 Sensitive Data Leakage'],
};

/**
 * EX-022: a canary token found in a scanned file. Each token is unique to one
 * install and lives only in its trap file and the records file, so a copy
 * anywhere else (raw or disguised) was made by something that read the trap.
 * The matching is in code, since only the records know the tokens; the
 * definition supplies the OWASP mapping and the encyclopedia text.
 */
export function canaryFindings(text: string, rel: string, canaries: readonly Canary[], def?: VirusDefinition): Finding[] {
  if (canaries.length === 0 || isCanaryHome(rel)) return [];
  return findCanaryInText(text, canaries).map((h) => {
    const { line, col } = lineColOf(text, h.index);
    return {
      source: 'signature' as const,
      ruleId: 'EX-022',
      title: 'Canary token copied out of its trap',
      severity: 'critical' as const,
      file: rel,
      line,
      col,
      // The exact text found, as it appears in the file.
      span: text.slice(h.index, Math.min(h.end, h.index + 120)),
      owasp: def?.owasp ?? EX022_DEFAULTS.owasp,
      fix:
        `A trap token has been copied out of its trap (${h.canary.file}${h.shape === 'raw' ? '' : `, ${h.shape}`}). ` +
        'Something that read the trap wrote it here: find the instruction that asked for it (a prompt injection in a file, a tool result or a dependency) and remove it, ' +
        'delete this copy, then replant fresh traps: exorcist canary --remove && exorcist canary plant',
    };
  });
}

/**
 * The Haunted House Map of the MCP configs found in a scan, and one EX-023
 * finding per config whose servers form the lethal trifecta. Configs are
 * sorted by file so the result does not depend on the walk order.
 */
export async function trifectaReport(
  root: string,
  configs: readonly ParsedMcpConfig[],
  rules: readonly CapabilityRule[],
  defs: readonly VirusDefinition[],
): Promise<{ map: HauntedMap; findings: SignatureFinding[] }> {
  const pins = await readPins(root);
  const sorted = [...configs].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  const findings: SignatureFinding[] = [];
  const maps = sorted.map((c) => {
    const m = analyzeConfig(c, rules, pins);
    const f = trifectaFinding(c, m, defs);
    if (f) findings.push(f);
    return m;
  });
  return { map: { configs: maps }, findings };
}

export type MapRepoResult =
  | { ok: true; map: HauntedMap; findings: SignatureFinding[] }
  | { ok: false; error: string };

/** Only the trifecta check, for `exorcist map`: reads MCP configs, not every file. */
export async function mapRepo(root: string, options: Pick<ScanOptions, 'definitionsDir' | 'maxFileSizeBytes'>): Promise<MapRepoResult> {
  const rules = await loadCapabilityRules(options.definitionsDir);
  if (!rules.ok) return { ok: false, error: rules.error };
  let defs: VirusDefinition[];
  try {
    defs = await loadDefinitions(options.definitionsDir);
  } catch (err) {
    return { ok: false, error: String(err).split('\n')[0] ?? 'The virus definitions could not be loaded.' };
  }
  const configs: ParsedMcpConfig[] = [];
  for await (const file of walkRepo(root, options.maxFileSizeBytes)) {
    if (file.role !== 'mcp-config' && file.role !== 'config') continue;
    const text = await readFile(file.path, 'utf8').catch(() => null);
    const cfg = text === null ? null : parseMcpConfig(file.rel, file.role, text);
    if (cfg) configs.push(cfg);
  }
  return { ok: true, ...(await trifectaReport(root, configs, rules.rules, defs)) };
}

export async function* scanRepo(
  root:    string,
  options: ScanOptions,
): AsyncIterable<ScanEvent> {
  const defs = await loadDefinitions(options.definitionsDir);
  const canaries = loadCanariesFile(canariesPath(root));
  if (!canaries.ok) {
    yield { type: 'error', file: '.exorcist/canaries.json', message: canaries.error };
  }
  const records: Canary[] = canaries.ok ? canaries.canaries : [];
  const ex022 = defs.find((d) => d.id === 'EX-022');
  const capabilities = await loadCapabilityRules(options.definitionsDir);
  const configs: ParsedMcpConfig[] = [];
  const start = Date.now();
  let filesScanned = 0;
  let filesSkipped = 0;
  let findingsTotal = 0;

  for await (const file of walkRepo(root, options.maxFileSizeBytes)) {
    yield { type: 'file', file };

    try {
      const text = await readFile(file.path, 'utf8');
      const cfg = parseMcpConfig(file.rel, file.role, text);
      if (cfg) configs.push(cfg);
      const norm = normalize(text, file.role);
      const sigs = runSignatures(file, norm, defs);
      const heurs = options.bedrockClient
        ? await runHeuristics(file, norm, sigs, options.bedrockClient)
        : [];
      const traps = canaryFindings(text, file.rel, records, ex022);

      const deduped = deduplicate([...sigs, ...heurs, ...traps]);

      for (const finding of deduped) {
        findingsTotal++;
        yield { type: 'finding', finding };
      }
      filesScanned++;
    } catch (err) {
      filesSkipped++;
      yield { type: 'error', file: file.rel, message: String(err) };
    }
  }

  // EX-023 looks at whole configs, so it runs after the walk (REQ-02).
  if (configs.length > 0) {
    if (capabilities.ok) {
      const { map, findings } = await trifectaReport(root, configs, capabilities.rules, defs);
      for (const finding of findings) {
        findingsTotal++;
        yield { type: 'finding', finding };
      }
      yield { type: 'map', map };
    } else if (!capabilities.missing) {
      yield { type: 'error', file: 'capabilities.yaml', message: capabilities.error };
    }
  }

  yield {
    type: 'done',
    stats: {
      filesScanned,
      filesSkipped,
      findingsTotal,
      durationMs: Date.now() - start,
    },
  };
}
