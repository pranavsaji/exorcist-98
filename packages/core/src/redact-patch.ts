import { gitQuotePath } from './exorcise.js';
import { PRIVATE_KEY_LINE_MARKER, privateKeyLines } from './redact-secrets.js';

/**
 * Blanking of private-key lines in a unified diff (m7 security review).
 *
 * A hunk can open in the middle of a key block, so the BEGIN line is not in the
 * diff text and a search of the diff alone finds no key block. The block is
 * therefore located in the ORIGINAL file text, and the line numbers found there
 * are blanked in every hunk. Browser-safe is not required: this runs on the server.
 */

/** A changed file as the patch was built from it. */
export type PatchSource = { file: string; before: string; after: string };

const HUNK = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;
// A lone BEGIN or END marker line (the other half of the block is outside the hunk).
const PEM = ['PRIVATE', 'KEY'].join(' ');
const MARKER_LINE = new RegExp(`^-----(?:BEGIN|END) [A-Z ]*${PEM}(?: BLOCK)?-----\\s*$`);
// Key bodies are base64, wrapped at 64 or 76 columns. 40 keeps short ordinary words out.
const BASE64_LINE = /^[A-Za-z0-9+/=]{40,}$/;

function blank(line: string): string {
  return `${/^[-+ ]/.test(line) ? line.slice(0, 1) : ''}${PRIVATE_KEY_LINE_MARKER}`;
}

/**
 * The patch with every line that belongs to a private-key block replaced by a
 * marker. The line count and the hunk headers are unchanged.
 *
 * 1. Lines whose number (old side for context and removed lines, new side for
 *    context and added lines) is inside a key block of the original or fixed text.
 * 2. Backstop: any run of long
 *    base64-only lines touching a blanked line or a BEGIN/END marker line, whatever the numbers say.
 */
export function redactPatchKeyLines(patch: string, sources: readonly PatchSource[] = []): string {
  const byHeader = new Map<string, { old: Set<number>; new: Set<number> }>();
  for (const s of sources) {
    byHeader.set(`diff --git ${gitQuotePath(`a/${s.file}`)} ${gitQuotePath(`b/${s.file}`)}`, {
      old: privateKeyLines(s.before),
      new: privateKeyLines(s.after),
    });
  }

  const lines = patch.split('\n');
  const inHunk: boolean[] = new Array<boolean>(lines.length).fill(false);
  const blanked: boolean[] = new Array<boolean>(lines.length).fill(false);
  const anchor: boolean[] = new Array<boolean>(lines.length).fill(false);
  let keys: { old: Set<number>; new: Set<number> } | undefined;
  let oldN = 0; let newN = 0; let oldLeft = 0; let newLeft = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (oldLeft <= 0 && newLeft <= 0) {
      if (line.startsWith('diff --git ')) { keys = byHeader.get(line); continue; }
      const h = HUNK.exec(line);
      if (h) {
        oldN = Number(h[1]); newN = Number(h[3]);
        oldLeft = h[2] === undefined ? 1 : Number(h[2]);
        newLeft = h[4] === undefined ? 1 : Number(h[4]);
      }
      continue;
    }
    const c = line.slice(0, 1);
    if (c === '\\') continue; // "\ No newline at end of file"
    inHunk[i] = true;
    let hit = false;
    if (c === ' ') { hit = !!(keys?.old.has(oldN) || keys?.new.has(newN)); oldN++; newN++; oldLeft--; newLeft--; }
    else if (c === '-') { hit = !!keys?.old.has(oldN); oldN++; oldLeft--; }
    else if (c === '+') { hit = !!keys?.new.has(newN); newN++; newLeft--; }
    else { oldLeft = 0; newLeft = 0; inHunk[i] = false; continue; } // malformed hunk: stop trusting counts
    // BEGIN and END lines hold no secret and stay, so the diff-text pass that follows
    // can still pair them; they only anchor the backstop below.
    if (MARKER_LINE.test(line.slice(1))) anchor[i] = true;
    else if (hit) blanked[i] = true;
  }

  // Backstop: spread over base64-only lines that touch a blanked line, both ways.
  const isB64 = (i: number): boolean => inHunk[i] === true && BASE64_LINE.test((lines[i] ?? '').slice(1));
  for (const dir of [1, -1]) {
    let prev = false;
    for (let k = 0; k < lines.length; k++) {
      const i = dir === 1 ? k : lines.length - 1 - k;
      if (!inHunk[i]) { prev = false; continue; }
      if (!blanked[i] && prev && isB64(i)) blanked[i] = true;
      prev = blanked[i] === true || anchor[i] === true;
    }
  }

  return lines.map((l, i) => (blanked[i] ? blank(l) : l)).join('\n');
}
