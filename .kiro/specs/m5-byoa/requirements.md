# Spec: m5-byoa (Bring Your Own Attack)

Antivirus vendors gave everyone the EICAR test file so they could see their
scanner work. The Possession Lab gets the same: paste any text you are worried
about and watch the scanner and the real Shield decide.

## REQ-01 Input

1. A "Bring your own attack" tab in the Possession Lab with a textarea (max
   20,000 characters) and a choice of where the text goes:
   "a README / rules file the agent reads", "an MCP tool description",
   "a tool result", "tool call arguments (JSON)".
2. A few one-click samples (defanged), including one with hidden Unicode.

## REQ-02 Verdict

1. `POST /api/byoa { placement, text }` (zod-validated, rate-limited like the
   Haunted Repo scan) returns:
   - scanner findings (rule, severity, title, line, fix) from `scanText` with
     the file role that matches the placement;
   - for tool description / tool result / call arguments: what the real
     `ShieldEngine` does with it (pinned and passed, withheld, call blocked),
     with its alert text;
   - the Ouija decoded message when hidden text is present.
2. The text is never stored, logged or sent anywhere else. The response
   quotes at most 200 characters of it.
3. The UI shows a large verdict ("EXORCISED: the Shield would stop this" or
   "CLEAN: nothing found" with an honest note that a clean result is not proof
   of safety and that reworded attacks can get past patterns).

## Property-based tests

- PBT-BYO-01: any input up to the limit returns a valid response (no 500).
- PBT-BYO-02: the response never contains more than 200 consecutive
  characters of the input.
