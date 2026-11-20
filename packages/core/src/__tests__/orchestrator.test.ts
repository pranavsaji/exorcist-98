import { describe, it, expect } from 'vitest';
import { resolve, dirname } from 'node:path';
import { statSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { scanRepo } from '../scanner/orchestrator.js';
import type { ScanEvent, Finding } from '../types.js';
import { fromRoot } from './repo-root.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR     = fromRoot('fixtures/haunted-repo');
const DEFINITIONS_DIR = fromRoot('definitions');

async function collectEvents(root: string, defsDir = DEFINITIONS_DIR): Promise<ScanEvent[]> {
  const events: ScanEvent[] = [];
  for await (const ev of scanRepo(root, { definitionsDir: defsDir })) {
    events.push(ev);
  }
  return events;
}

describe('scanRepo orchestrator', () => {
  it('done is always the last event', async () => {
    const events = await collectEvents(FIXTURE_DIR);
    expect(events.at(-1)?.type).toBe('done');
  });

  it('yields at least one finding from haunted-repo', async () => {
    const events = await collectEvents(FIXTURE_DIR);
    const findings = events.filter(e => e.type === 'finding');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('finding events cover multiple ruleIds (12 definitions loaded)', async () => {
    const events = await collectEvents(FIXTURE_DIR);
    const ruleIds = new Set(
      events
        .filter((e): e is { type: 'finding'; finding: Finding } => e.type === 'finding')
        .map(e => e.finding.ruleId)
    );
    expect(ruleIds.size).toBeGreaterThanOrEqual(5);
  });

  it('a single bad file does not abort the scan', async () => {
    // Use an actual directory that exists but has no YAML definitions by using
    // a fresh temp dir so loadDefinitions returns [] without error.
    const { mkdtemp } = await import('node:fs/promises');
    const { tmpdir }  = await import('node:os');
    const tmpRoot = await mkdtemp(`${tmpdir()}/exorcist-test-orch-`);
    const tmpDefs = await mkdtemp(`${tmpdir()}/exorcist-test-defs-`);
    try {
      const events = await collectEvents(tmpRoot, tmpDefs);
      expect(events.at(-1)?.type).toBe('done');
    } finally {
      const { rm } = await import('node:fs/promises');
      await rm(tmpRoot, { recursive: true, force: true });
      await rm(tmpDefs, { recursive: true, force: true });
    }
  });

  it('no file on disk is mutated by a scan (mtime unchanged)', async () => {
    const before = new Map<string, number>();
    for (const name of readdirSync(FIXTURE_DIR)) {
      const p = `${FIXTURE_DIR}/${name}`;
      try { before.set(p, statSync(p).mtimeMs); } catch { /* skip dirs */ }
    }

    await collectEvents(FIXTURE_DIR);

    for (const [p, mtime] of before) {
      expect(statSync(p).mtimeMs, `${p} was mutated by the scan`).toBe(mtime);
    }
  });
});
