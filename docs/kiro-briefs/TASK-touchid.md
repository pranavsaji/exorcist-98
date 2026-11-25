# Feature brief: OS-verified release for Session Guard (Touch ID)

Write a Kiro spec for this feature in `.kiro/specs/m6-os-release/` (requirements.md,
design.md, tasks.md, in the same style as the existing specs in `.kiro/specs/`),
then implement every task. Follow the steering files in `.kiro/steering/`.

## The problem (docs/KNOWN_LIMITATIONS.md, S-027)

Session Guard (rule EX-027, `packages/shield/src/session.ts`, used by
`packages/shield/src/engine.ts`) holds an outbound tool call once a session has
read both untrusted text and private data. Today the person releases it with
`exorcist approve session` in a real terminal (`packages/cli/src/commands/approve.ts`,
`personConfirms` in `on-access.ts`), which writes a grant into
`<stateDir>/sessions/<key>/cli.json`. Any program running as the same user can
write that file itself, so the release can be forged. A typed nonce or an
AppleScript dialog does not stop that either.

## The feature

On macOS, the Shield process itself asks the operating system to verify the
device owner (Touch ID, or the login password as the OS fallback) at the moment it
holds a call. Another program cannot answer that prompt.

- Use the LocalAuthentication framework with policy
  `LAPolicyDeviceOwnerAuthentication` (value 2). No compiled binary: run
  `osascript -l JavaScript` with a fixed script that uses the ObjC bridge
  (`ObjC.import('LocalAuthentication')`, `$.LAContext`,
  `evaluatePolicyLocalizedReasonReply`, then spin `$.NSRunLoop` until the reply
  arrives). `canEvaluatePolicyError(2, ...)` tells whether it is available.
- The reason text shown in the prompt names the MCP server, the tool and the two
  facts that armed the guard (use `sessionSummary`/`describeFact`). It is
  untrusted text: never interpolate it into the script source; pass it as an
  argument or environment variable, strip control and bidi characters, cap the
  length.
- While the prompt is open the call is held (the agent waits). Success: the held
  call goes through, once (this call only, not the rest of the session).
  Cancel, failure, error or a timeout (60 s): the call is refused with the existing
  held message, and nothing is granted.
- New policy option `sessionGuard.release` (or an equivalent shape that fits
  `policy.ts`): `os` | `terminal`. Default `os` when the platform is darwin and
  `canEvaluatePolicy` succeeds, else `terminal` (today's behaviour).
- With `os` in force, grants written to `cli.json` (or any other record) are
  ignored for Session Guard, which is what closes the forgery. `exorcist approve
  session` then explains that release happens in the system prompt, and changes
  nothing.
- Non-macOS, or no LocalAuthentication: keep today's behaviour and say so in the
  refusal text.
- Testability: put the OS call behind an injected interface (for example
  `OsAuth { available(): Promise<boolean>; verify(reason: string): Promise<'ok'|'denied'|'error'|'timeout'> }`).
  Tests use a fake. No test may ever start a real prompt: the real
  implementation must refuse to run when `VITEST` or `CI` is set or
  `EXORCIST_OS_AUTH=off`.

## Done when

- requirements, design and tasks exist and every task is ticked;
- unit tests cover: prompt success releases exactly one call; deny, error and
  timeout refuse; forged `cli.json` grants are ignored under `os`; `terminal`
  mode is unchanged; the reason text is sanitised; the real implementation is
  never invoked under test;
- `pnpm -r typecheck` and `pnpm vitest run` pass from the repository root;
- README (Session Guard row) and docs/KNOWN_LIMITATIONS.md (S-027) describe
  what is now closed and what is not (for example: a program with the user's
  rights can still kill the Shield or change the policy file);
- a row in docs/KIRO_LOG.md says this was specified and implemented by the
  Kiro IDE agent.
