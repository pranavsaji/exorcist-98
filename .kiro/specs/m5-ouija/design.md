# Design: m5-ouija

- `packages/core/src/ouija.ts`: `decodeHidden(text: string): HiddenMessage[]`.
  Single pass over code points. Tag run: collect 0xE0020-0xE007E (skip E0001,
  E007F). Variation-selector run: FE00-FE0F -> 0-15, E0100-E01EF -> 16-255.
  UTF-8 decode with `new TextDecoder('utf-8', { fatal: true })` inside try;
  fall back to hex `0x..` pairs. Cap 100 runs, 500 chars per message.
- Export from `packages/core/src/index.ts` and `packages/core/src/browser.ts`.
- Signature engine: for `unicode_class` matches of class `tag-block`, attach
  `decoded` to the finding (extend the Finding type with optional
  `decoded?: string`; the web protocol's WebFinding gains the same optional
  field and `toWebFinding` copies it).
- EX-021: implement as a `unicode_class`-style rule if the definition schema
  allows a `variation-selector-run` class; otherwise add a small built-in check
  in the signature engine keyed by rule id, following the pattern of other
  structural checks. Add the class to the normalizer's class list.
- Web: `apps/web/src/components/FindingDetail.tsx` adds an `OuijaPanel` when
  `finding.decoded` is set: a bordered box, heading "Ouija board: the invisible
  text says", the message in a `<pre>` with text content only.
- CLI pretty reporter: one extra indented line `hidden message: "<msg>"`.
- Fixture: `fixtures/haunted-repo/EX-021-smuggled-bytes.md` with a sentence
  followed by an emoji carrying the bytes of "DEFANGED: placeholder message".
  Update fixture tests that enumerate EX ids.
