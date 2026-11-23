# Spec: m5-canary (Canary Traps)

Antivirus researchers used "goat files": bait programs whose only job was to
get infected, proving a virus was active. Canary Traps do this for AI agents.
Exorcist plants unique, harmless trap tokens in places an attacker would want
an agent to read (a fake `.env.canary`, a steering note, a comment in a config).
No honest workflow ever sends those tokens anywhere. If one shows up in an MCP
tool call, the Shield blocks the call and raises a critical alert: proof that
something talked the agent into leaking.

## REQ-01 Plant

1. `exorcist canary plant [dir]` creates 3 traps by default in `dir`:
   `.exorcist/canary/.env.canary` (fake credentials containing the tokens),
   `.exorcist/canary/NOTES.md` (looks like private notes) and a token in
   `.exorcist/canary/config.json`. Each token is `x98c_` + 24 random base32
   characters, unique per install.
2. Tokens are recorded in `.exorcist/canaries.json` (token, file, created) and
   the Shield's state folder is told where to find them.
3. `--list`, `--remove` (removes files and records).
4. Trap files say in a comment that they are Exorcist 98 canaries, so a human
   who opens one is not confused. The comment is written so it does not tell an
   agent to avoid them.

## REQ-02 Detect in the Shield

1. The Shield loads canary tokens at start (from `.exorcist/canaries.json` in
   the project, path configurable through the policy as `canaries`).
2. Any tool call whose arguments contain a canary token (also base64- or
   URL-encoded, and with characters split by whitespace) is blocked whatever
   the mode, with a critical alert `EX-022 Canary token in a tool call`, naming
   the trap file it came from.
3. A tool result that contains a canary token is allowed but alerts (medium):
   the server echoed it.

## REQ-03 Detect in scans and hooks

1. `exorcist scan` reports a canary token found outside its trap file
   (critical EX-022: "a trap token has been copied out of its trap").
2. The pre-commit hook blocks a commit that stages a canary token outside
   `.exorcist/canary/`.

## REQ-04 Possession Lab

1. A sixth Lab scenario "The Canary" in `packages/shield/src/simulator.ts`: an
   injected README makes the agent post the contents of `.env.canary` to a
   paste tool; without the Shield the token leaves; with it the call is
   blocked by EX-022. The simulator test covers it.

## Property-based tests

- PBT-CAN-01: a token embedded at any depth of any JSON args, raw, base64 or
  percent-encoded, is always blocked.
- PBT-CAN-02: random args without a token are never blocked by EX-022.
- PBT-CAN-03: plant then remove leaves the directory as it was.
