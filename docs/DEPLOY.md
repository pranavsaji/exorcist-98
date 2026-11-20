# Deploying the web app

The web app (`apps/web`) is a Next.js server. It needs no `git` binary, no
cloud credentials and no AI service: GitHub repositories are downloaded as
tarballs over HTTPS, and only signature rules run. It reads `definitions/` and
`fixtures/haunted-repo/` from disk, and the standalone build ships both.

**Live:** https://exorcist-98.vercel.app (Vercel Hobby, project `exorcist-98`,
root directory `apps/web`, Node 22). Deployed 2026-11-20 with `vercel deploy`;
the full browser suite passed against it (24 of 24 steps, 0 axe violations),
including a real GitHub scan. Redeploy with `vercel deploy --prod` from the
repository root.

Each option below needs your account.

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

## Option 2: Docker (tested)

```sh
docker build -t exorcist-98 .
docker run -p 3000:3000 exorcist-98
```

The `Dockerfile` runs the same build as option 1 and starts the server as the
`node` user. Built and tested on 2026-11-19 (Docker 29.1.2, 377 MB image, no
`git` inside): the browser suite passed against the container, 24 of 24 steps,
0 axe violations. This is the simplest way to run it on any container host.

## Option 3: Vercel (live)

Link the repository root with `vercel link`, then set the root directory to
`apps/web` (`vercel project update exorcist-98 --root-directory apps/web
--framework nextjs --node-version 22.x`). Keep the default install and build
commands (pnpm is detected from `packageManager`). Set
`EXORCIST_CLIENT_IP_HEADER=x-real-ip` so the rate limiter can tell visitors
apart.
The tracing includes in `apps/web/next.config.mjs` should bring
`definitions/` and the Haunted Repo along. GitHub scans write to the
function's temporary disk, which serverless hosts allow.

## Environment

| Variable | Needed | Purpose |
|----------|--------|---------|
| `PORT`, `HOSTNAME` | Optional | Where the server listens. |
| `EXORCIST_ROOT` | Optional | Folder that contains `definitions/` and `fixtures/haunted-repo/`, if they are not next to the server. |
| `EXORCIST_CLIENT_IP_HEADER` | Recommended | The header your host's proxy sets to the visitor's address, used by the rate limiter: `x-real-ip` on Vercel, `fly-client-ip` on Fly (the default). Without it every visitor shares one bucket. |

## Before going public

- `POST /api/scan` has a per-visitor rate limit and a cap on scans running at
  once (W-003, `apps/web/src/lib/limits.ts`): 6 GitHub scans per visitor, then
  one every 2 minutes; 3 GitHub scans at once. The limits live in one server
  process, so several instances each keep their own.
- Check the deployed URL with `E2E_BASE=https://your-url pnpm e2e`.

## Option 4: Fly.io (prepared, not deployed)

`fly.toml` runs the Docker image on one small machine that stops when idle.
`fly apps create` refused until a payment method is added to the Fly account,
so it has not been deployed there.
