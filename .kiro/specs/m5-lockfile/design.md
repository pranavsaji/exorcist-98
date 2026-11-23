# Design: m5-lockfile

- `packages/shield/src/lockfile.ts`: zod schema, `buildLock`, `serializeLock`,
  `diffLock(old, new)` returning typed changes, `lockToPins`.
  Fingerprints reuse `toolFingerprint` and `launchFingerprint`.
- Listing tools: reuse the MCP SDK client already used in tests
  (`@modelcontextprotocol/sdk` client over stdio) in the CLI package; bounded
  by timeout; never runs servers marked disabled.
- Shield: `proxy.ts` reads `exorcist.lock` from the project root when present
  and seeds state pins from it (lock wins over a missing local pin; a local pin
  that disagrees with the lock is reported).
- CLI: `packages/cli/src/commands/lock.ts`; register in index.ts and help.
- Action: `action.yml` new input and step; keep the existing behaviour when the
  input is absent.
- Tests use `packages/shield/src/__tests__/fake-mcp-server.mjs` as the server.
