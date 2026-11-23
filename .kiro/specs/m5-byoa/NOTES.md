# Notes: m5-byoa

Decisions made while building this spec, where the spec left room or could not
be followed to the letter.

- **Ouija decoder.** REQ-02.1 asks for "the Ouija decoded message", but
  m5-ouija (`decodeHidden` in core) is not built yet. `findHidden` in
  `packages/shield/src/byoa.ts` is a small, linear decoder for Unicode tag
  characters only (U+E0020 to U+E007E to ASCII, runs of two or more), plus a
  count of zero-width and bidi characters. When m5-ouija lands, switch to
  `decodeHidden` and drop the local one. Variation-selector smuggling is not
  decoded here.
- **A third verdict, FLAGGED.** REQ-02.3 names two verdicts. When the scanner
  reports something (or there are hidden characters) but the Shield would let
  it through, neither "EXORCISED: the Shield would stop this" nor "CLEAN:
  nothing found" is true, so the result says "FLAGGED: something here looks
  wrong" and explains that the Shield would still pass it.
- **README / rules file.** The Shield guards MCP traffic, not files, so this
  placement has no Shield verdict; the result says so. A critical or high
  scanner finding gives EXORCISED ("the scanner flags this file before your
  agent reads it").
- **Tool description roles.** The text is scanned as `mcp-config` and as
  `tool-result`, the two ways the Shield's `inspectTool` reads a description.
- **Call arguments that are not a JSON object** are sent as `{ "input": text }`
  with a note. JSON nested more than 200 levels is refused without being
  copied (the real Shield refuses anything past 32 levels).
- **Quote limit.** Besides capping each field, `capQuotes` cuts any string in
  the result that would repeat more than 200 consecutive characters of the
  input (alerts can repeat a long host name; the decoded message repeats text;
  a visitor can paste a rule's own fix text back in).
- **Core bug found by PBT-BYO-01.** `scanText('false', 'mcp-config', ...)`
  threw (`json_path` rules iterated over a non-array JSONPath result). Fixed in
  `signature-engine.ts` with a regression test in `scan-text.test.ts`.
- **Rate limit.** New limiter kind `byoa`: 20 at once per visitor, then one
  every 6 seconds, 8 running at once.
- **Task 4 (`pnpm test` green) not ticked.** On the build machine (load
  average 100 to 190 from other jobs) the full run ended 830 to 835 passed,
  2 to 7 failed, every failure a timing test (5-second test timeouts on
  process-spawning tests, the regex time-limit test, a local fetch). The same
  timing test fails on the unmodified base code under the same load, and the
  MCP server tests pass with a longer timeout. All BYOA tests pass. Re-run on
  a quiet machine to tick it.
