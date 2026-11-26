# Detection benchmark

A labelled corpus for the signature engine, run by
`packages/core/src/__tests__/benchmark.test.ts`.

- `attacks/<case>/` holds one defanged attack each. `labels.json` names the
  rules that must fire on it. The `mcp-source-poison-*` cases are small MCP
  server sources in TypeScript, Python and Go with a poisoned tool
  description (EX-005).
- `benign/<case>/` holds ordinary files that look like attacks to a naive
  scanner (badges, emoji, lockfiles, CI installers, test tokens, comment
  markers). Each must produce no findings. The `mcp-source-hints-*` cases are
  MCP server sources whose descriptions and comments carry ordinary hints such
  as "use search_files before calling this tool".

The m11 cases pair each config-tamper detection with a quiet look-alike:
wildcard trust in Claude and Cursor settings and in Copilot's terminal
auto-approve map (EX-033, EX-034), orders to change agent settings (EX-030),
weaken tests (EX-031) or push elsewhere (EX-032), AI-aimed meta tags and alt
text (EX-028), and a sandbox file with MCP sandboxing off (EX-035).

Every host is `example.invalid` and every token is fake. Results on real
public repositories are in `docs/BENCHMARK.md`.

The incident replicas (`cve-2026-10591-hidden-page`, `mindgard-possessed-filenames`,
`mindgard-steering-image-url`) are original wording, not researcher payloads.
Names with hidden characters are built by tests from code points, not stored
here, because git and editors alter them. The corpus has 38 attacks and 37
look-alikes.
