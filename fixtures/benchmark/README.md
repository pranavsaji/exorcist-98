# Detection benchmark

A labelled corpus for the signature engine, run by
`packages/core/src/__tests__/benchmark.test.ts`.

- `attacks/<case>/` holds one defanged attack each. `labels.json` names the
  rules that must fire on it.
- `benign/<case>/` holds ordinary files that look like attacks to a naive
  scanner (badges, emoji, lockfiles, CI installers, test tokens, comment
  markers). Each must produce no findings.

Every host is `example.invalid` and every token is fake. Results on real
public repositories are in `docs/BENCHMARK.md`.
