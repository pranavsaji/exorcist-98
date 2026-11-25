# Brief: presentation polish from a judge's review

A strict review of the project as a hackathon judge found these problems. Fix
them all. Rule: never claim anything that is not true, and never say or imply
that Kiro did work it did not do.

## 1. One source for every number

The numbers disagree across files (tests: README badge "1,500+", README "about
1,600 / 123 fast-check", SUBMISSION "1,755 / 127", its table "71", KIRO_LOG
"2,008 / 140"; definitions: SUBMISSION "18", repository 25; Kiro setup:
SUBMISSION "5 specs, 4 steering", repository 17 and 10; field report: "421 repos
in two rounds" but FIELD_REPORT has three rounds and 483 repos; Haunted Repo:
46, 47 and 51 in different places; "Round 3" means different things in
BENCHMARK and FIELD_REPORT).

- Add `scripts/facts.mjs` that computes the facts from the repository (test
  count from a vitest JSON run or a cached file it writes, fast-check
  properties, definitions, specs, steering, hooks, Haunted Repo findings,
  benchmark result, field-report totals) and writes `docs/facts.json`.
- Make README, SUBMISSION, KIRO_LOG counts and the web pages use those numbers
  (the web app can import the JSON). A test fails when a document disagrees
  with `docs/facts.json`.
- Rename the BENCHMARK "round" names so they cannot be confused with the
  field-report rounds.

## 2. README: short, sharp, Kiro-first

Cut README to about 150 lines. First screen: one sentence on the problem, one
on the product, a 30-second "try it" (the live site link and one `npx`
command), and a GIF or image of the Session Guard holding a call while the
Touch ID prompt is open (use `docs/media/` images; if no GIF exists, use the
best existing image and leave a clearly marked placeholder for a GIF the owner
records). Avoid jargon on the first screen (explain "rug pull" and "lethal
trifecta" in plain words or move them down). Move detail into docs. Remove the
"Pending" install rows; list only what is published today (npm 0.1.3 when it is
out, Open VSX, the Action from the repository, the Power from the repository).
Replace stale caveats: the Power was installed through Kiro's Powers panel and
the on-access hook was seen firing in Kiro (see KIRO_LOG).

## 3. The web app

- Home: a visible button for the Lethal Trifecta demo (`/?demo=trifecta`), the
  most novel feature, next to the main scan button.
- `/product`: bring it up to date (Session Guard with OS release, console,
  editor extension, Power, Crew app; the AI judge and audit log are not
  "planned" if they exist) and fix the 7px horizontal overflow at 390px.
- The Haunted Repo result says "1 fixable threat could not be fixed safely here
  (a version could not be looked up)": explain it in plain words or avoid it in
  the demo.

## 4. Console and messages

- `exorcist console` banner and `console --help` still say a held session is
  released only with `exorcist approve session`; say that under OS release it
  happens in the system prompt.
- The withheld-result message for EX-002 repeats itself; show each reason once.

## 5. Video script and submission text

- Rewrite `docs/VIDEO_SCRIPT.md` for a video under 3 minutes with this story:
  0:00 a poisoned steering file in Kiro, the extension shows the hidden
  characters, the hover decodes them, Exorcise removes them; 0:30 the Haunted
  Repo scan on the site; 1:00 a rug pull blocked; 1:30 the lethal trifecta: an
  issue, a .env read, then an outgoing message held while the Touch ID prompt is
  open, cancel, and the console shows held and blocked live; 2:15 the field
  report numbers; 2:35 Kiro's own on-access hook blocking Kiro's read of a brief
  that quoted an injection; 2:50 end card. Remove every stale line (npm not
  published, Bedrock never run, old test counts).
- `docs/SUBMISSION.md`: current numbers from facts.json, "What's next" without
  items that already shipped (OS-prompt release), and the Kiro section true and
  specific.
- Linux and Windows: state plainly in README and KNOWN_LIMITATIONS that the
  system-prompt release is macOS only, and what happens elsewhere.

Run `pnpm -r typecheck`, `pnpm vitest run` and the browser suite
(`pnpm --filter @exorcist-98/web build`, start it, then `E2E_BASE=... node
scripts/e2e-chrome.mjs`). Commit. Do not push.
