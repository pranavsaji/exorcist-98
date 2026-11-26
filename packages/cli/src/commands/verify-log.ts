import { verifyLogDir } from '@exorcist-98/shield';
import type { ChainStatus, VerifyOptions } from '@exorcist-98/shield';
import { DEFAULT_DIR, parse, stateDir, str } from '../util.js';
import type { Io } from '../util.js';

export const VERIFY_LOG_HELP = `Usage: exorcist verify-log [--dir <folder>] [--expect <hash | seq:hash>] [--json]

Checks that the Shield's event log has not been changed, cut short or reordered
since it was written. Every event is linked to the one before it, so any edit
shows up as the first event that no longer fits.

  --dir <folder>   the Shield state folder (default: ${DEFAULT_DIR})
  --expect <x>     a head hash you saved earlier, kept outside the state folder.
                   "<hash>" must be the log's current head; "<seq>:<hash>" must be
                   the hash of event number <seq> (still valid after the log grows).
                   This is what catches a rewrite of the whole folder.
  --json           print the result as one JSON object instead of text

Exit codes: 0 the log is intact, or has no chain yet ("not chained", an old log);
            1 the log is broken, or --expect was given and could not be matched;
            2 usage error.
`;

const HEX64 = /^[0-9a-f]{64}$/;

type Expect = { kind: 'tip'; hash: string } | { kind: 'at'; seq: number; hash: string };

/** "<64 hex>" or "<seq>:<64 hex>"; anything else is a usage error. */
function parseExpect(raw: string): Expect | null {
  const v = raw.trim().toLowerCase();
  if (HEX64.test(v)) return { kind: 'tip', hash: v };
  const m = /^([1-9][0-9]{0,15}):([0-9a-f]{64})$/.exec(v);
  if (m === null) return null;
  const seq = Number(m[1]);
  return Number.isSafeInteger(seq) ? { kind: 'at', seq, hash: m[2] as string } : null;
}

/** Keep log-derived text from acting on the terminal. */
function plain(s: string): string {
  return s.replace(/[^\x20-\x7e]/g, '?');
}

function run(dir: string, expect: Expect | null): ChainStatus {
  const opts: VerifyOptions = expect?.kind === 'at' ? { expect: { seq: expect.seq, hash: expect.hash } } : {};
  const status = verifyLogDir(dir, opts);
  if (expect?.kind === 'tip' && status.status === 'intact' && status.head.hash !== expect.hash) {
    return { status: 'broken', atSeq: status.head.seq, reason: 'expect-mismatch', detail: "the log's head does not match the expected hash" };
  }
  return status;
}

const REASON: Record<string, string> = {
  changed: 'an event was changed',
  removed: 'an event was removed',
  inserted: 'an event was inserted',
  reordered: 'events were swapped',
  'head-mismatch': "the log's end does not match its head record",
  'expect-mismatch': "the log's head does not match the expected hash",
};

function describe(s: ChainStatus, expecting: boolean): string {
  switch (s.status) {
    case 'intact': {
      const tail = s.unchained ? ` ${s.unchained} later line${s.unchained === 1 ? ' is' : 's are'} not chained and were not checked.` : '';
      return `The log is intact: ${s.head.seq} events, none changed. Head hash: ${s.head.hash}${tail}`;
    }
    case 'not-chained':
      return expecting
        ? 'The log is not chained, so the expected head cannot be matched.'
        : 'The log is not chained: it has no hash chain (an old or empty log), so there is nothing to check.';
    case 'broken':
      return `The log is broken at event ${s.atSeq}: ${REASON[s.reason] ?? s.reason}. ${plain(s.detail)}`;
  }
}

export async function verifyLogCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, {
    dir: { type: 'string' }, expect: { type: 'string' }, json: { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${VERIFY_LOG_HELP}`); return 2; }
  if (p.values['help'] === true) { io.out(VERIFY_LOG_HELP); return 0; }
  if (p.positionals.length > 0) { io.err(`Unexpected argument "${plain(p.positionals[0] ?? '')}".\n\n${VERIFY_LOG_HELP}`); return 2; }

  let expect: Expect | null = null;
  const rawExpect = str(p.values['expect']);
  if (rawExpect !== undefined) {
    expect = parseExpect(rawExpect);
    if (expect === null) { io.err(`--expect needs a 64-character hash, or <seq>:<hash>.\n\n${VERIFY_LOG_HELP}`); return 2; }
  }

  const status = run(stateDir(str(p.values['dir'])), expect);
  io.out(p.values['json'] === true ? JSON.stringify(status) : describe(status, expect !== null));
  if (status.status === 'broken') return 1;
  if (status.status === 'not-chained' && expect !== null) return 1;
  return 0;
}
