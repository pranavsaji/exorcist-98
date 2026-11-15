# Tech conventions

- TypeScript strict mode everywhere, Node 20+, pnpm workspaces.
- Layout: apps/web (Next.js App Router), packages/core, packages/shield, packages/mcp-server, packages/cli, definitions/, fixtures/, power/.
- Validate every boundary with zod: API input, LLM output, YAML rules, MCP messages.
- LLM calls go through one module in packages/core/llm using Amazon Bedrock; Haiku for triage, Sonnet for the judge. Always request strict JSON and validate it.
- Tests: Vitest for unit tests, fast-check for property-based tests. Every requirement in a spec maps to at least one test.
- No `any`. Errors are typed results, not thrown across package boundaries.
- Keep functions small and pure in packages/core so they are easy to test.
- Do not add dependencies without a reason written in the PR description.
