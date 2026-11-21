# Publishing to npm

Both packages are ready: they build before packing, publish as public, carry a
README, and have no runtime dependencies (everything is bundled). A clean
install from the packed files was tested on 2026-11-20: scan, SARIF, `wrap` and
an exact `unwrap`, and the MCP server listing its four tools.

You need an npm account. Publishing a scoped package needs the scope to exist.

## Once

1. Sign in at https://www.npmjs.com (create an account if needed).
2. Create the organisation `exorcist-98` (free, public packages only):
   https://www.npmjs.com/org/create
3. In a terminal: `npm login`

## Publish

From the repository root:

```sh
pnpm --filter @exorcist-98/cli publish --no-git-checks
pnpm --filter @exorcist-98/mcp-server publish --no-git-checks
```

Use `pnpm publish`, not `npm publish`: pnpm rewrites the `workspace:*`
development dependencies. npm asks for a one-time password if your account has
two-factor authentication.

## Check

```sh
npx -y @exorcist-98/cli@0.1.0 scan .
```

Then the Kiro Power (`power/mcp.json`) and the Crew app's default scanner work
without a local checkout.
