# Design: m2-ui

## 1. Layout

```
apps/web/
  next.config.mjs        transpile core, map .js to .ts, externalize simple-git
  tailwind.config.ts, postcss.config.mjs
  tsconfig.json          Next settings, "@/*" alias
  vitest.config.ts       esbuild automatic JSX, "@" alias
  src/
    app/
      layout.tsx, globals.css
      page.tsx                       desktop (client component inside)
      api/scan/route.ts              POST: streams NDJSON
      encyclopedia/page.tsx          index
      encyclopedia/[id]/page.tsx     one page per definition
    lib/
      protocol.ts      zod schemas: request, events, snippet
      ndjson.ts        parseNdjsonStream (client)
      github.ts        parseGithubUrl
      snippet.ts       revealHidden, buildSnippet
      severity.ts      levels, labels, shapes, sortFindings
      plain.ts         plain-language text per rule
      paths.ts         repo root, definitions dir, fixtures dir
      scan-service.ts  scanTarget(): async generator of protocol events
    components/
      Desktop.tsx, Window.tsx, Taskbar.tsx, DesktopIcon.tsx, Icons.tsx
      ScanWindow.tsx, ResultsWindow.tsx, FindingDetail.tsx
      SeverityBadge.tsx, ProgressBar.tsx, RetroFrame.tsx
    hooks/useScan.ts
```

## 2. Data flow

```
ScanWindow --POST /api/scan--> route.ts
                                  | zod validate request
                                  v
                              scan-service.scanTarget()
                                  | haunted-repo: fixtures dir
                                  | repoUrl: simple-git clone to tmp
                                  v
                              core.scanRepo() events
                                  | for each finding: read the file, build snippet
                                  v
                          NDJSON stream  --->  parseNdjsonStream  --> useScan state
```

The route never forwards raw `ScanEvent`s. `scan-service` maps them to protocol
events, adds snippets, and replaces any thrown error with a generic `fatal`
event. The snippet is built before the clone is removed.

## 3. Protocol (zod)

- Request: `{ target: 'haunted-repo' } | { repoUrl: string }`.
- Events: `start { target }`, `file { rel, role }`, `finding { finding, snippet }`,
  `error { file, message }`, `done { stats }`, `fatal { message }`.
- `snippet`: `{ startLine, lines: [{ n, before, match, after }] }`. Only lines
  that contain the span have a non-empty `match`. All text has hidden
  characters revealed as `[U+XXXX]`.

## 4. Hidden character display

`revealHidden(text)` replaces every code point in the engine's hidden classes
(zero-width, bidi, tag block) with `[U+XXXX]` (4 to 6 hex digits). `buildSnippet`
splits the original line into before, match and after, then reveals each part
separately, so `before + match + after` maps back to the original line and the
highlight is exact. For `unicode_class` findings the span is an escape such as
`\u200B`; the highlight covers the single real character at the finding column.

## 5. Severity display

Infection level labels and shapes (colour is a third signal):

| Severity | Label | Shape |
|----------|-------|-------|
| critical | CRITICAL | filled diamond |
| high | HIGH | filled triangle |
| medium | MEDIUM | filled square |
| low | LOW | filled circle |

## 6. Windows

`Desktop` keeps a list of `{ id, open, minimized, z, x, y }`. Focusing a window
raises its `z`. Dragging uses pointer events on the title bar; keyboard users
move focus with Tab and use the taskbar to restore windows. Each window has
`role="dialog"` and `aria-labelledby` its title.

## 7. Streaming scan hook

`useScan` owns an `AbortController`, reads the response body with
`parseNdjsonStream`, and exposes `{ status, log, findings, filesSeen, stats,
start(target), cancel() }`. Starting a scan aborts the previous one.

## 8. Dependencies added to `apps/web` (reasons)

| Package | Reason |
|---------|--------|
| next, react, react-dom | App framework required by the plan |
| tailwindcss, postcss, autoprefixer | Styling required by the plan |
| @exorcist-98/core | The scan engine (workspace) |
| simple-git | Clone GitHub repos (already used by the Lambda handler) |
| zod | Validate request, events and snippets (`tech.md`) |

## 9. Build notes

- `@exorcist-98/core` ships TypeScript source with `.js` import specifiers. The
  Next config sets `transpilePackages` and a webpack `extensionAlias` so those
  resolve to `.ts`.
- The route uses the Node runtime and `dynamic = 'force-dynamic'`.
- `definitions/` and `fixtures/` are located relative to the repo root. Deployment
  must include them (see `docs/KNOWN_LIMITATIONS.md`).
