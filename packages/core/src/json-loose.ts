/**
 * Parse JSON the way editors read their settings files: line comments, block
 * comments and trailing commas are allowed (JSON with comments). Used for config files
 * such as `.vscode/settings.json`, which are often not strict JSON.
 *
 * Returns `undefined` when the text cannot be parsed even after cleaning.
 * Strict JSON is tried first, so valid input is never changed.
 */
export function parseJsonLoose(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    // fall through to the lenient reading
  }
  try {
    return JSON.parse(stripJsonComments(text));
  } catch {
    return undefined;
  }
}

/** Remove comments and trailing commas outside of string literals. */
export function stripJsonComments(text: string): string {
  let out = '';
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  while (i < text.length) {
    const c = text[i] as string;
    const next = text[i + 1];
    if (c === '"') {
      // Copy a string literal as is, honouring escapes.
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (c === '/' && next === '/') {
      while (i < text.length && text[i] !== '\n') i++;
    } else if (c === '/' && next === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? text.length : end + 2;
      out += ' ';
    } else {
      out += c;
      i++;
    }
  }
  return dropTrailingCommas(out);
}

function dropTrailingCommas(text: string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const c = text[i] as string;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (c === ',') {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j] as string)) j++;
      if (text[j] !== '}' && text[j] !== ']') out += c;
      i++;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}
