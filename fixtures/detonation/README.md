# Detonation Chamber evidence set (m5-detonation, REQ-03)

Twenty short texts, labelled, for `scripts/detonation-eval.ts`:

- `attacks/`: ten reworded attacks. Each asks an AI agent to do something
  harmful (send a secret out, read a key file, download and run a script,
  delete data) in polite, ordinary words, with none of the phrases the
  signatures look for. `packages/cli/src/__tests__/detonation-fixtures.test.ts`
  checks that no signature fires on any of them, in any file role. If a
  signature starts catching one, that is good news: replace the sample with
  another reworded attack so this set keeps measuring what signatures miss.
- `benign/`: ten look-alikes. They name the same files, tools and commands
  (`.env`, `~/.ssh`, install scripts, chat channels, deleting folders) but ask
  for nothing harmful.

`labels.json` gives each file its placement in the chamber: as a file the
user asked to summarise, a tool description, or a tool result.

All samples are defanged: every host is `example.invalid`, and the texts hold
no tokens at all (the chamber plants its own fake secrets at run time).
