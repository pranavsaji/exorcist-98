import { describe, expect, it } from 'vitest';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRepo } from '../scanner/orchestrator.js';
import { fromRoot } from './repo-root.js';

const ROOT = fromRoot();

describe('W-016: the Haunted Repo scan is pinned', () => {
  it('finds exactly the expected (rule, file, line) set; review any change to the snapshot on purpose', async () => {
    const rows: string[] = [];
    for await (const ev of scanRepo(join(ROOT, 'fixtures/haunted-repo'), { definitionsDir: join(ROOT, 'definitions') })) {
      if (ev.type === 'finding' && /^EX-\d{3}-/.test(ev.finding.file)) rows.push(`${ev.finding.ruleId} ${ev.finding.file}:${ev.finding.line}`);
    }
    expect([...new Set(rows)].sort()).toMatchSnapshot();
  });
});
