/**
 * Hidden text (EX-028, m8-incidents): an HTML element styled so a person cannot
 * see it, whose text talks to the AI or asks for an action. Pure functions; the
 * signature engine calls `findHiddenText` for rules with `match.hidden_text`.
 */

export type HidingMethod =
  | 'colour' | 'font-size' | 'display-none' | 'visibility-hidden' | 'opacity-zero' | 'off-screen' | 'zero-box';

export type HiddenText = {
  /** Offset of the element's opening tag in the scanned text. */
  index:  number;
  /** Length from the opening tag to the end of the element's text. */
  length: number;
  method: HidingMethod;
  /** The element's visible-to-a-model text, tags removed, whitespace collapsed. */
  text:   string;
};

/** The longest element text read (characters). */
export const MAX_HIDDEN_ELEMENT = 2000;

const VOID_TAGS = new Set(['img', 'input', 'br', 'hr', 'meta', 'link', 'area', 'base', 'col', 'embed', 'source', 'track', 'wbr']);

// Names an AI. "AI" is case-sensitive; "model" counts only as "language model", "the model", "this model".
const AI_NAME_UPPER = /\bAI\b/;
const AI_WORDS = /\b(?:assistants?|agents?|llms?|kiro|claude|copilot|chatgpt|gemini|cursor|language\s+models?|(?:the|this)\s+model)\b/i;
const ACTION_VERB = '(?:write|rewrite|edit|modify|overwrite|run|execute|fetch|download|send|upload|start|launch|add|append|install|delete|remove|exfiltrate|forward|email)';
const ACTION_OBJECT = '(?:files?|config(?:uration)?s?|servers?|commands?|scripts?|mcp|credentials?|secrets?|tokens?|api\\s+keys?|\\.env|\\S*\\.json|~\\/\\S+)';
const ACTION = new RegExp(`\\b${ACTION_VERB}\\b[^.\\n!?]{0,60}?(?:\\b${ACTION_OBJECT}(?![\\w-])|${'~\\/'}|\\.env\\b)`, 'i');
const OVERRIDE = /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\b/i;

/** True when the text names the AI or tells the reader to do something with a file, config, server or command. */
export function addressesAi(text: string): boolean {
  if (text.length === 0) return false;
  return AI_NAME_UPPER.test(text) || AI_WORDS.test(text) || OVERRIDE.test(text) || ACTION.test(text);
}

type Rgb = [number, number, number];

function parseColour(raw: string): Rgb | null {
  const v = raw.trim().toLowerCase().replace(/\s*!important$/, '');
  if (v === 'white') return [255, 255, 255];
  if (v === 'black') return [0, 0, 0];
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/.exec(v);
  if (hex) {
    const h = hex[1] as string;
    const f = h.length === 3 ? h.split('').map((c) => c + c).join('') : h;
    return [parseInt(f.slice(0, 2), 16), parseInt(f.slice(2, 4), 16), parseInt(f.slice(4, 6), 16)];
  }
  const rgb = /^rgba?\(\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*(?:[,/]\s*[\d.]+%?\s*)?\)$/.exec(v);
  if (rgb) return [Number(rgb[1]), Number(rgb[2]), Number(rgb[3])];
  return null;
}

function distance(a: Rgb, b: Rgb): number {
  return Math.max(Math.abs(a[0] - b[0]), Math.abs(a[1] - b[1]), Math.abs(a[2] - b[2]));
}

/** Pixels of a CSS length (`0`, `1px`, `0.5em`, `-9999px`), or null when it is not one this check understands. */
function px(raw: string): number | null {
  const m = /^(-?\d*\.?\d+)\s*(px|pt|em|rem|%|vw|vh)?$/.exec(raw.trim().toLowerCase());
  if (!m) return null;
  const n = Number(m[1]);
  const unit = m[2] ?? '';
  if (n === 0) return 0;
  if (unit === 'px' || unit === '') return n;
  if (unit === 'pt') return n * 1.333;
  if (unit === 'em' || unit === 'rem') return n * 16;
  return null; // %, vw, vh: not a size in pixels
}

function parseStyle(style: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of style.split(';')) {
    const i = part.indexOf(':');
    if (i < 1) continue;
    out.set(part.slice(0, i).trim().toLowerCase(), part.slice(i + 1).trim().replace(/\s*!important$/i, ''));
  }
  return out;
}

/** The first hiding method a style attribute uses, or null. */
export function hidingMethod(style: string): HidingMethod | null {
  const css = parseStyle(style);
  if (css.get('display')?.toLowerCase() === 'none') return 'display-none';
  if (css.get('visibility')?.toLowerCase() === 'hidden') return 'visibility-hidden';
  const opacity = css.get('opacity');
  if (opacity !== undefined && /^0*\.?0+%?$/.test(opacity.trim())) return 'opacity-zero';
  const size = css.get('font-size');
  if (size !== undefined) { const n = px(size); if (n !== null && n <= 2) return 'font-size'; }
  for (const key of ['left', 'top', 'right', 'bottom', 'text-indent', 'margin-left']) {
    const v = css.get(key);
    if (v !== undefined) { const n = px(v); if (n !== null && n <= -999) return 'off-screen'; }
  }
  const w = css.get('width'); const h = css.get('height');
  const clipped = /^(hidden|clip)$/i.test(css.get('overflow') ?? '');
  if (clipped && ((w !== undefined && px(w) === 0) || (h !== undefined && px(h) === 0))) return 'zero-box';
  const colour = css.get('color');
  if (colour !== undefined) {
    const c = parseColour(colour);
    if (c) {
      const bg = parseColour(css.get('background-color') ?? css.get('background') ?? '');
      if (bg ? distance(c, bg) <= 8 : distance(c, [255, 255, 255]) <= 5) return 'colour';
    }
  }
  return null;
}

const OPEN_TAG = /<([a-zA-Z][a-zA-Z0-9-]*)\b([^<>]*?)\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')[^<>]*>/g;

function plainElementText(html: string): string {
  return html.replace(/<[^>]*>/g, ' ').replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/\s+/g, ' ').trim();
}

/** Every hidden element in `text` whose own text addresses the AI or asks for an action. */
export function findHiddenText(text: string): HiddenText[] {
  const out: HiddenText[] = [];
  OPEN_TAG.lastIndex = 0;
  let lastEnd = -1;
  let m: RegExpExecArray | null;
  while ((m = OPEN_TAG.exec(text)) !== null) {
    const name = (m[1] as string).toLowerCase();
    if (VOID_TAGS.has(name) || m.index < lastEnd) continue;
    const method = hidingMethod(m[3] ?? m[4] ?? '');
    if (method === null) continue;
    const start = m.index + m[0].length;
    const window = text.slice(start, start + MAX_HIDDEN_ELEMENT);
    const close = window.toLowerCase().indexOf(`</${name}`);
    const inner = close === -1 ? window : window.slice(0, close);
    const body = plainElementText(inner);
    if (!addressesAi(body)) continue;
    const end = start + inner.length;
    out.push({ index: m.index, length: end - m.index, method, text: body });
    lastEnd = end;
  }
  return out;
}
