# Feature brief: a Shield log you can prove nobody rewrote, and approvals that cannot be replayed

Write a Kiro spec in `.kiro/specs/m12-audit-chain/` (requirements, design,
tasks), then implement every task. Follow `.kiro/steering/`. Give every
requirement an ID (AC-1, AC-2, ...) and start the name of each test that checks
it with that ID, for example `it('AC-4: ...')`.

## 1. Hash-chained events

- Every event the Shield appends to `<stateDir>/events.jsonl` gets a sequence
  number, the SHA-256 of the previous event, and its own hash over a canonical
  form. The first event links to a random genesis value created with the log.
- A head file next to the log records the last sequence number and hash,
  written atomically after each append.
- Several Shield processes can write the same log. Read how appends happen now
  and keep them safe under that; say in the design how.
- Old logs without hashes still load; `verify-log` reports them as "not
  chained" instead of failing.

## 2. `exorcist verify-log`

`exorcist verify-log [--dir <stateDir>] [--expect <head hash>]` says, in plain
words, whether the log is intact, and if not exactly which event was changed,
removed, inserted or moved, or whether the end was cut off (the head file
disagrees). Exit 0 when intact, 1 when broken, 2 on usage errors. `--json` for
CI. Fast on a log of 100,000 events.

## 3. Be honest about the limit

Anyone who can write the state folder can rewrite the whole chain and the head
file. The chain catches partial edits, and it catches a full rewrite when the
person kept a head hash elsewhere. So: `exorcist alerts`, the Stop gate output
and the console show the current head hash, and `--expect` checks against a
saved one. Write this plainly in `docs/KNOWN_LIMITATIONS.md`.

## 4. Show it

- `exorcist console`: a chain status badge (intact, broken at event N, not
  chained) and the head hash.
- The web app: in the Shield demos (rug pull and Lethal Trifecta), a
  "Rewrite an event" control that changes one event in the in-browser log, and
  a "Verify the log" control that shows exactly where the chain breaks. Use
  the same verify code as the CLI. Keyboard only, screen reader announcements,
  0 axe violations, and an e2e step for it.

## 5. Approvals that run once

Read how `exorcist approve` and the OS release (Touch ID) work now. Make sure,
with a test for each:
- a release covers one held call and is used up by it;
- a terminal approval code expires (15 minutes by default) and works once;
- at release time the call is checked again in full, not just let through;
- nothing reachable by the agent or an MCP tool can grant an approval;
- every approval, refusal and expiry is a chained event.
Fix any gap you find and say what it was.

## 6. Properties

fast-check: changing, deleting, inserting or swapping any event in a chained
log is always detected, and an untouched log always verifies.

## 7. Finish

Update `docs/REFERENCE.md` (CLI commands, Shield), run
`node scripts/facts.mjs --run-tests --docs`, add a row to `docs/KIRO_LOG.md`
for this work by the Kiro IDE agent, and move this brief to
`docs/kiro-briefs/`. Run `pnpm -r typecheck` and `pnpm vitest run` until they
pass. Commit. Do not push.
