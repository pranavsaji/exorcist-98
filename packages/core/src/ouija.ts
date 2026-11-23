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
  /** For 'variation-selector': the smuggled bytes. */
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

const utf8 = new TextDecoder('utf-8', { fatal: true });

/** UTF-8 bytes to text, or hex `0x..` pairs when the bytes are not valid UTF-8. */
export function decodeVsBytes(bytes: number[]): string {
  const arr = new Uint8Array(bytes);
  try {
    return utf8.decode(arr);
  } catch {
    return arr.reduce((acc, b) => `${acc}${acc === '' ? '' : ' '}0x${b.toString(16).padStart(2, '0')}`, '');
  }
}

function truncate(s: string): string {
  return s.length <= MAX_DECODED_CHARS ? s : `${s.slice(0, MAX_DECODED_CHARS)}…`;
}

/**
 * Find and decode every hidden message in `text`. Pure, no Node imports, so it
 * is safe for the browser entry. Linear in the length of the text; at most
 * 100 runs are reported.
 */
export function decodeHidden(text: string): HiddenMessage[] {
  const out: HiddenMessage[] = [];
  let offset = 0;
  // State of the run being collected.
  let runKind: 'tag' | 'variation-selector' | null = null;
  let runStart = 0;
  let runEnd = 0;
  let tagChars = '';
  let vsBytes: number[] = [];

  const flush = (): void => {
    if (runKind === 'tag') {
      // U+E0001 and U+E007F (begin/cancel tags) are dropped by tagToAscii.
      if (tagChars.length >= 2) {
        out.push({ kind: 'tag', start: runStart, end: runEnd, message: truncate(tagChars) });
      }
    } else if (runKind === 'variation-selector') {
      // A run of 4 or more selectors carries bytes; one or two are ordinary
      // emoji presentation and never reported (REQ-02).
      if (vsBytes.length >= 4) {
        out.push({
          kind: 'variation-selector', start: runStart, end: runEnd,
          message: truncate(decodeVsBytes(vsBytes)), bytes: vsBytes.slice(0, MAX_DECODED_CHARS),
        });
      }
    }
    runKind = null;
    tagChars = '';
    vsBytes = [];
  };

  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (isTagCodePoint(cp)) {
      if (runKind !== 'tag') { flush(); runKind = 'tag'; runStart = offset; }
      const ascii = tagToAscii(cp);
      if (ascii !== null) tagChars += String.fromCharCode(ascii);
      runEnd = offset + ch.length;
    } else if (isVariationSelector(cp)) {
      if (runKind !== 'variation-selector') { flush(); runKind = 'variation-selector'; runStart = offset; }
      const b = variationSelectorByte(cp);
      if (b !== null) vsBytes.push(b);
      runEnd = offset + ch.length;
    } else {
      flush();
    }
    offset += ch.length;
    if (out.length >= MAX_HIDDEN_RUNS) { flush(); return out.slice(0, MAX_HIDDEN_RUNS); }
  }
  flush();
  return out;
}
