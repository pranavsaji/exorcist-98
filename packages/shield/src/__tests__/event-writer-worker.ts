// Used by events.test.ts: one process appending events to a shared log.
//   tsx event-writer-worker.ts <dir> <writer name> <count> <maxBytes>
import { EventLog } from '../events.js';

const [dir, name, count, maxBytes] = process.argv.slice(2);
const log = new EventLog(dir as string, { server: name as string, maxBytes: Number(maxBytes) });
for (let i = 0; i < Number(count); i++) {
  log.write({ kind: 'call', tool: `tool_${i}`, decision: i % 3 === 0 ? 'blocked' : 'allowed', ruleId: 'EX-017', why: `${name} event ${i} ${'x'.repeat(i % 200)}` });
}
if (log.problem) { process.stderr.write(log.problem); process.exit(1); }
