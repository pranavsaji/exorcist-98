# Deploying the web app

The web app (`apps/web`) is a Next.js server. It needs no `git` binary, no
cloud credentials and no AI service: GitHub repositories are downloaded as
tarballs over HTTPS, and only signature rules run. It reads `definitions/` and
`fixtures/haunted-repo/` from disk, and the standalone build ships both.

No host has been chosen yet. Each option below needs your account.

## Option 1: any Node 22 host (tested)

```sh
pnpm install --frozen-lockfile
pnpm --filter @exorcist-98/web build
# Copy the self-contained server and its static files:
cp -r apps/web/.next/standalone/ /srv/exorcist-98/
cp -r apps/web/.next/static /srv/exorcist-98/apps/web/.next/static
cd /srv/exorcist-98 && PORT=3000 HOSTNAME=0.0.0.0 node apps/web/server.js
```

This is the path the deployment rehearsal used: the copy ran from a folder
outside the repository and passed the full browser suite (24 steps, 0 axe
violations), including a real GitHub scan.

## Option 2: Docker (not yet built)

```sh
docker build -t exorcist-98 .
docker run -p 3000:3000 exorcist-98
```

The `Dockerfile` runs the same build as option 1 and starts the server as the
`node` user. It has not been built yet because Docker was not running on the
development machine.

## Option 3: Vercel (not yet tried)

Import the repository, set the root directory to `apps/web`, and keep the
default install and build commands (pnpm is detected from `packageManager`).
The tracing includes in `apps/web/next.config.mjs` should bring
`definitions/` and the Haunted Repo along. GitHub scans write to the
function's temporary disk, which serverless hosts allow.

## Environment

| Variable | Needed | Purpose |
|----------|--------|---------|
| `PORT`, `HOSTNAME` | Optional | Where the server listens. |
| `EXORCIST_ROOT` | Optional | Folder that contains `definitions/` and `fixtures/haunted-repo/`, if they are not next to the server. |

## Before going public

- `POST /api/scan` has no rate limit or concurrency cap (W-003). Put the app
  behind a host or proxy that rate-limits per IP.
- Check the deployed URL with `E2E_BASE=https://your-url pnpm e2e`.
