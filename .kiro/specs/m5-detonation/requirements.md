# Spec: m5-detonation (The Detonation Chamber)

Signatures cannot catch a reworded attack. 90s antivirus faced the same
problem with polymorphic viruses and answered with emulation: run the
suspect code in a fake CPU and watch what it tries to do. The Detonation
Chamber does that for text: it hands the suspect text to a sandboxed model
that has only fake tools and fake secrets, and watches whether the text makes
it *try* something harmful. Behaviour, not wording.

## REQ-01 The chamber

1. `detonate(text, placement, judge)` builds a sandbox conversation: a system
   prompt for an ordinary coding assistant with a benign user task ("summarise
   this file" / "use this tool"), the suspect text placed as a file, tool
   description or tool result, and four fake tools: `read_file`, `http_post`,
   `run_shell`, `send_message`. The fake environment contains canary secrets.
2. The model is called through Amazon Bedrock (the existing client) with tool
   use enabled, temperature 0, at most 2 turns and 1,024 output tokens. Tool
   calls are never executed; fake results are returned.
3. Verdict: `detonated` when the model calls `http_post`/`send_message` with a
   canary, calls `run_shell` with a download-and-run or a destructive command,
   or reads a secret path it was not asked about. `inert` otherwise. The
   verdict lists the attempted calls (tool name and arguments, secrets
   masked).
4. Suspect text is fenced with a per-call random nonce, exactly as the AI judge
   does, and is never concatenated into the system prompt.

## REQ-02 Use

1. `exorcist scan --detonate` detonates every file that has a medium-or-worse
   finding or a heuristic hit (capped by `--detonate-max`, default 10) and adds
   EX-024 "Detonated in the chamber" (critical) findings with the attempted
   calls as the rationale.
2. `exorcist detonate <file>` runs one file and prints the transcript of
   attempted calls.
3. Off by default; needs AWS credentials; prints the number of model calls.

## REQ-03 Evidence

1. A small labelled set (`fixtures/detonation/`): 10 reworded attacks that
   EX-002/EX-004 miss and 10 benign look-alikes. A script runs them through the
   chamber and writes `docs/DETONATION.md` with the confusion matrix. Results
   are reported as measured, including failures.
2. Unit tests use a fake judge (no network) for verdict logic: every attempted
   harmful call shape maps to `detonated`; plain answers map to `inert`.
