# Spec: m5-ouija (Ouija Decoder)

Invisible-text smuggling hides a whole message from people while the model
still reads it. EX-001 already flags hidden characters; it does not say what
they *say*. The Ouija Decoder reads the hidden message back in plain text, the
way 90s antivirus "virus info" showed what a virus actually did.

## REQ-01 Decode Unicode tag smuggling

1. Characters U+E0020 to U+E007E map to ASCII 0x20 to 0x7E (U+E0001 and
   U+E007F are begin/cancel tags and are dropped).
2. A run of two or more tag characters decodes to a string. Runs are found
   anywhere in a text, including inside ordinary words.

## REQ-02 Decode variation-selector byte smuggling

1. "Emoji smuggling" hides bytes after a base character using variation
   selectors: U+FE00 to U+FE0F carry byte values 0 to 15, U+E0100 to U+E01EF
   carry 16 to 255.
2. A run of 4 or more variation selectors decodes to bytes, then to UTF-8 text
   when valid; otherwise it is shown as hex.
3. One or two variation selectors (ordinary emoji presentation, e.g. U+FE0F
   after a heart) are never reported.

## REQ-03 Where the decoded message appears

1. `decodeHidden(text)` in `@exorcist-98/core` returns a list of
   `{ kind: 'tag' | 'variation-selector', start, end, message }`. Pure, no
   Node imports, exported from the browser entry too.
2. EX-001 findings carry `decoded` (the first message, at most 500 characters)
   when the hidden run decodes to something.
3. A new rule EX-021 "Smuggled bytes in variation selectors" (critical) fires
   on REQ-02 runs, mapped to OWASP LLM01.
4. The web finding detail shows a "Ouija board" panel: "The invisible text
   says:" followed by the message, rendered as text (never HTML).
5. The CLI's pretty output prints the decoded message under the finding.
6. The Haunted Repo gains a defanged sample for EX-021 whose hidden message is
   harmless placeholder text.

## REQ-04 Safety

1. A decoded message is attacker text. It is displayed only, never placed in a
   prompt, and is truncated to 500 characters.
2. Decoding is linear time and bounded: at most 100 runs per file.

## Property-based tests

- PBT-OUI-01: for any printable ASCII string s, encoding s as tag characters
  inside random visible text decodes back to s.
- PBT-OUI-02: for any byte array (length 4 to 64), encoding with variation
  selectors after a random base character decodes back to the same bytes.
- PBT-OUI-03: text with no tag characters and at most two adjacent variation
  selectors decodes to an empty list.
