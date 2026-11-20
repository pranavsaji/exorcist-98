import { SCANNER_VERSION } from '../version.js';
import type { Finding } from '../types.js';

// Browser-safe: no Node imports, so the web app can build SARIF in the page.

/** A path relative to `root`, with forward slashes. Paths outside root are kept as given. */
function relativeTo(root: string, file: string): string {
  const norm = (p: string) => p.replace(/\\/g, '/').replace(/\/+$/, '');
  const r = norm(root);
  const f = norm(file);
  if (r && f.startsWith(`${r}/`)) return f.slice(r.length + 1);
  return f.replace(/^\/+/, '');
}

export type SarifLog = {
  version: '2.1.0';
  $schema: string;
  runs: SarifRun[];
};

type SarifRun = {
  tool: { driver: { name: string; version: string; rules: SarifRule[] } };
  results: SarifResult[];
};

type SarifRule = {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
};

type SarifResult = {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId: string };
      region: { startLine: number; startColumn: number };
    };
  }>;
};

function severityToLevel(severity: Finding['severity']): SarifResult['level'] {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

export function toSarif(findings: Finding[], repoRoot: string): SarifLog {
  const ruleMap = new Map<string, SarifRule>();

  const results: SarifResult[] = findings.map(f => {
    if (!ruleMap.has(f.ruleId)) {
      ruleMap.set(f.ruleId, {
        id:               f.ruleId,
        name:             f.title.replace(/\s+/g, ''),
        shortDescription: { text: f.title },
        fullDescription:  { text: `${f.title}\n\nFix: ${f.fix}` },
      });
    }

    // Make the URI relative to the repo root
    const uri = f.file.startsWith('/') ? relativeTo(repoRoot, f.file) : f.file;

    return {
      ruleId: f.ruleId,
      level:  severityToLevel(f.severity),
      message: { text: `${f.title}: ${f.span}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri, uriBaseId: '%SRCROOT%' },
          region: { startLine: f.line, startColumn: f.col },
        },
      }],
    };
  });

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'Exorcist 98',
          version: SCANNER_VERSION,
          rules: Array.from(ruleMap.values()),
        },
      },
      results,
    }],
  };
}
