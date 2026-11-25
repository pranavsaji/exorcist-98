# Bug: an OS release skips the unknown-host check (EX-016)

Found by an automated security review of commit 7519f07 (m6-os-release).

In `packages/shield/src/engine.ts`, the Session Guard runs before the host
check. When `inspectCall` returns `action: 'ask'` (the call would reach a host
that is not on the allowed list) and the session is armed, the OS-release
branch stores the held call with `hosts: []`. The OS prompt text does not
mention the host. When the person verifies, `onOwnerVerified(ticket, 'ok')`
calls `sendCall` directly, so the call goes to the unknown host without the
EX-016 approval that the same call would need in any other path.

Calls with a secret (`action: 'block'`) are not affected: they never reach the
Session Guard.

Expected behaviour:

- Keep `verdict.hosts` in the held entry for the OS path.
- Name the hosts in the OS prompt reason (sanitised like the rest of it).
- After a successful OS verification, a call with hosts still has to pass
  EX-016 the normal way: if the client supports approval prompts, ask about the
  hosts (as `askUser` does); otherwise refuse with the usual
  `exorcist approve host ...` instructions. Verifying for the Session Guard must
  never count as approving a host.
- Tests: an armed session plus a call to an unknown host under `os` mode, with
  OS `ok`, must not send the call without host approval (both with and without
  client elicitation); the reason names the host; existing tests keep passing.

Fix it, run `pnpm -r typecheck` and `pnpm vitest run`, and add a line to the m6
entry in `docs/KIRO_LOG.md` saying this bug was found by a security review and
fixed by the Kiro agent. Do not push.
