/**
 * Ouija Decoder: reads back the messages hidden with invisible-text
 * smuggling (M5 spec m5-ouija).
 *
 * Two techniques, one pass:
 * - Unicode tag characters (U+E0000 block) carry printable ASCII directly.
 * - Variation selectors (U+FE00-FE0F, U+E0100-E01EF) after a base character
 *   carry bytes 0-255, which are then read as UTF-8 (or hex when invalid).
 *
 * The decoded text is attacker-controlled. It is displayed only, never
 * interpolated into a prompt, and every message is truncated (REQ-04).
 */

export type HiddenMessageKind = 'tag' | 'variation-selector';

export type HiddenMessage = {
  kind:    HiddenMessageKind;
  /** UTF-16 offset of the first hidden character. */
  start:   number;
  /** UTF-16 offset just past the last hidden character. */
  end:     number;
  /** The message, at most 500 characters. */
  message: string;
  /** For 'variation-selector': the smuggled bytes (the first MAX_VS_BYTES of them). */
  bytes?:  number[];
};

/** At most this many runs are reported per text (REQ-04). */
export const MAX_HIDDEN_RUNS = 100;
/** A decoded message is truncated to this many characters (REQ-04). */
export const MAX_DECODED_CHARS = 500;

export function isTagCodePoint(cp: number): boolean {
  return cp >= 0xE0000 && cp <= 0xE007F;
}

/** Tag characters that map to printable ASCII (U+E0020-U+E007E). */
export function tagToAscii(cp: number): number | null {
  return cp >= 0xE0020 && cp <= 0xE007E ? cp - 0xE0000 : null;
}

export function isVariationSelector(cp: number): boolean {
  return (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF);
}

/** The byte a variation selector carries: U+FE00-U+FE0F are 0-15, U+E0100-U+E01EF are 16-255. */
export function variationSelectorByte(cp: number): number | null {
  if (cp >= 0xFE00 && cp <= 0xFE0F) return cp - 0xFE00;
  if (cp >= 0xE0100 && cp <= 0xE01EF) return cp - 0xE0100 + 16;
  return null;
}

/** Encode an ASCII string as Unicode tag characters (used by tests and demos). */
export function encodeAsTags(s: string): string {
  return Array.from(s, (ch) => {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp < 0x20 || cp > 0x7e) throw new Error('encodeAsTags needs printable ASCII');
    return String.fromCodePoint(cp + 0xE0000);
  }).join('');
}

/** Encode bytes as variation selectors (used by tests and demos). */
export function encodeAsVariationSelectors(bytes: number[] | Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    if (b < 0 || b > 255) throw new Error('encodeAsVariationSelectors needs bytes 0-255');
    out += String.fromCodePoint(b < 16 ? 0xFE00 + b : 0xE0100 + (b - 16));
  }
  return out;
}

/**
 * At most this many smuggled bytes are kept from one run: enough for a full
 * 500-character message in any script (4 bytes per character), so memory
 * stays bounded however long the run is.
 */
export const MAX_VS_BYTES = MAX_DECODED_CHARS * 4;

function hexPairs(bytes: Uint8Array): string {
  const out: string[] = [];
  for (const b of bytes) out.push(`0x${b.toString(16).padStart(2, '0')}`);
  return out.join(' ');
}

/**
 * UTF-8 bytes to text, or hex `0x..` pairs when the bytes are not valid UTF-8.
 * With `cut`, the bytes are the start of a longer run, so a character split at
 * the end is dropped instead of making the whole message invalid.
 */
export function decodeVsBytes(bytes: number[], cut = false): string {
  const arr = new Uint8Array(bytes);
  try {
    // A fresh decoder per call: with `stream`, it keeps state between calls.
    // ignoreBOM keeps a leading U+FEFF: it is part of what was smuggled.
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(arr, { stream: cut });
  } catch {
    return hexPairs(arr);
  }
}

/**
 * Cut a message to at most MAX_DECODED_CHARS UTF-16 units, ending in an
 * ellipsis when cut, and never splitting a surrogate pair.
 */
export function truncateMessage(s: string): string {
  if (s.length <= MAX_DECODED_CHARS) return s;
  let cut = MAX_DECODED_CHARS - 1;
  const last = s.charCodeAt(cut - 1);
  if (last >= 0xD800 && last <= 0xDBFF) cut -= 1;
  return `${s.slice(0, cut)}…`;
}

/** Invisible, control and direction characters a decoded message may carry. */
const UNSAFE_FOR_DISPLAY = /[\p{Cc}\p{Cf}\u2028\u2029\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu;

/**
 * A decoded message made safe to show: every control, format (zero-width,
 * bidi, tag) and variation-selector character becomes a visible marker such
 * as [U+202E], so a terminal escape or a direction override hidden inside the
 * message cannot act on the screen it is shown on. With `keepNewlines`, line
 * feeds and tabs stay as they are (the web panel renders them in a <pre>).
 */
export function displayMessage(s: string, opts: { keepNewlines?: boolean } = {}): string {
  return s.replace(UNSAFE_FOR_DISPLAY, (c) => {
    if (opts.keepNewlines === true && (c === '\n' || c === '\t')) return c;
    const hex = (c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0');
    return `[U+${hex}]`;
  });
}

/**
 * Find and decode every hidden message in `text`. Pure, no Node imports, so it
 * is safe for the browser entry. One pass over the code points with bounded
 * buffers (linear time); at most MAX_HIDDEN_RUNS runs are reported, and the
 * scan stops as soon as that many are found (REQ-04).
 */
export function decodeHidden(text: string): HiddenMessage[] {
  const out: HiddenMessage[] = [];
  let offset = 0;
  // State of the run being collected.
  let runKind: HiddenMessageKind | null = null;
  let runStart = 0;
  let runEnd = 0;
  let tagChars = '';
  let tagCount = 0;
  let vsBytes: number[] = [];
  let vsCount = 0;

  const flush = (): void => {
    if (runKind === 'tag') {
      // U+E0001 and U+E007F (begin/cancel tags) carry no character and are
      // dropped; two or more mapped characters make a message (REQ-01).
      if (tagCount >= 2) {
        out.push({ kind: 'tag', start: runStart, end: runEnd, message: truncateMessage(tagChars) });
      }
    } else if (runKind === 'variation-selector') {
      // A run of 4 or more selectors carries bytes; one or two are ordinary
      // emoji presentation and never reported (REQ-02).
      if (vsCount >= 4) {
        out.push({
          kind: 'variation-selector', start: runStart, end: runEnd,
          message: truncateMessage(decodeVsBytes(vsBytes, vsCount > vsBytes.length)),
          bytes: vsBytes,
        });
      }
    }
    runKind = null;
    tagChars = '';
    tagCount = 0;
    vsBytes = [];
    vsCount = 0;
  };

  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (isTagCodePoint(cp)) {
      if (runKind !== 'tag') { flush(); runKind = 'tag'; runStart = offset; }
      const ascii = tagToAscii(cp);
      if (ascii !== null) {
        tagCount += 1;
        // One past the limit is kept so truncateMessage adds the ellipsis.
        if (tagChars.length <= MAX_DECODED_CHARS) tagChars += String.fromCharCode(ascii);
      }
      runEnd = offset + ch.length;
    } else if (isVariationSelector(cp)) {
      if (runKind !== 'variation-selector') { flush(); runKind = 'variation-selector'; runStart = offset; }
      const b = variationSelectorByte(cp);
      if (b !== null) {
        vsCount += 1;
        if (vsBytes.length < MAX_VS_BYTES) vsBytes.push(b);
      }
      runEnd = offset + ch.length;
    } else if (runKind !== null) {
      flush();
      if (out.length >= MAX_HIDDEN_RUNS) return out;
    }
    offset += ch.length;
  }
  flush();
  return out.slice(0, MAX_HIDDEN_RUNS);
}
