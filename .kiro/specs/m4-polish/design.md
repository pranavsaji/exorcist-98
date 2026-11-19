# Design: m4-polish

## Sound (`apps/web/src/lib/sound.ts`)

A table of notes per cue (`CUES`), played with oscillators and gain envelopes on
one shared `AudioContext`. `play()` is a no-op unless sound is on. The desktop
plays `threat` when `threatSeq` changes and a done cue on the running-to-done
transition. Preference key: `exorcist-98-sound` in `localStorage`.

## Browser-safe reporters (`packages/core/src/browser.ts`)

SARIF (path handling rewritten without `node:path`), Markdown, the badge and the
plain-language text. The web app converts its protocol findings to engine
findings (`toEngineFinding`) and builds files with `buildReport`, then downloads
them through a Blob URL.

## Tarball fetch (`packages/core/src/remote/tarball.ts`)

```
fetch codeload.github.com/<owner>/<repo>/tar.gz/HEAD   (30 s timeout)
  -> gunzip with running byte counts (compressed and unpacked caps)
  -> readTar: 512-byte headers; pax "x" and GNU "L" long names; "g" skipped;
     only types 0/NUL/7 kept; safeRelativePath drops the top folder and refuses
     absolute, "..", backslash and NUL paths; per-file and file-count caps
  -> writeEntries: re-checks each target is inside the folder; never overwrites
```

The web scan service uses it in place of `git clone`; failures that are safe to
show (not found, too large, too slow) reach the user, anything else is generic.

## Standalone deployment

`next.config.mjs`: `output: 'standalone'`, tracing root at the monorepo,
`outputFileTracingIncludes` for `definitions/` and `fixtures/haunted-repo/`.
`repoRoot()` accepts either `pnpm-workspace.yaml` or the traced folders.
Rehearsal: copy `.next/standalone` and `.next/static` to a folder outside the
repo, run `node apps/web/server.js`, run the browser suite against it.

## Hosting

Any Node 22 host. Vercel: project root `apps/web`, pnpm workspace detected.
Container hosts: the root `Dockerfile`. See `docs/DEPLOY.md`.
