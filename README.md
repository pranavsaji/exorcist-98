# Exorcist 98

**The 90s antivirus, resurrected for AI coding agents.**

Your agent reads READMEs, steering files, MCP tool descriptions and pull requests, and anyone can write those. Exorcist 98 scans them for prompt injection, tool poisoning and dangerous hooks, and runs a real-time shield between Kiro and its MCP servers.

Built with [Kiro](https://kiro.dev) for **Kiroween 2026** (category: Resurrection).

## Status

Planning. See the full build plan in [`docs/PLAN.md`](docs/PLAN.md).

## The four parts

1. **Full System Scan**: paste a GitHub URL, get findings with the exact hidden line highlighted.
2. **Virus Definitions**: YAML signatures plus an LLM heuristic layer on Amazon Bedrock.
3. **Real-Time Shield**: an MCP firewall that pins tool hashes and blocks leaks.
4. **Quarantine Vault**: disable and restore infected servers, hooks and steering files.

## Related repo

- Kiro Crew app (nightly scans and a Crew dashboard): [pranavsaji/exorcist-98-crew](https://github.com/pranavsaji/exorcist-98-crew)

## Safety

All attack samples in `fixtures/` are defanged: no working endpoints, no real malware.

## License

Apache-2.0
