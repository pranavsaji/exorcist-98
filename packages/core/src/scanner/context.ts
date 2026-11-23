// Context checks used by the signature engine (precision round 2).
//
// Each check answers one question about a match that a regex alone cannot:
// is this value a real credential or a placeholder; is this command something
// that runs or a line of data; is this phrase given as an order or quoted as
// an example; is this decoded blob hidden text or an embedded file. They are
// generic: none of them names a repository, an organisation or a product.

// ── Secrets (EX-011, validate: secret-value) ────────────────────────────────

/** Well-known token prefixes; what follows them is the random part. */
const TOKEN_PREFIX = /^(?:gh[pousr]_|github_pat_|sk-ant-(?:api|oat|admin)\d\d-|sk-proj-|sk-|AKIA|xox[baprs]-|AIza|sk_live_|npm_)/i;
/** Words and fillers that only appear in placeholders and documented examples. */
const PLACEHOLDER_WORDS = /your|(?:^|[-_])my[-_]|their|example|placeholder|change[-_]?me|replace|insert|dummy|fake|sample|redacted|here(?:$|[-_])|todo|demo|mock|selftest|test|x{3,}|y{3,}|\*{3,}|…|\.\.\./i;
/** Default or throwaway database passwords. */
const DEFAULT_DB_PASSWORD = /^(?:pass(?:word|wd)?|secret|changeme|admin|root|postgres|mysql|test|dev|local(?:dev)?|default|guest|123456|qwerty|x{3,}|\*{3,})$/i;

function credibleDatabaseUrl(value: string): boolean {
  const m = /^[a-z0-9+.-]+:\/\/([^\s:@/]+):([^\s@/]+)@([^\s/:?]+)/i.exec(value);
  if (!m) return false;
  const [, user = '', pass = '', host = ''] = m;
  if (/^[$<{%[]/.test(pass) || pass.includes('${')) return false;     // templated
  if (pass.toLowerCase() === user.toLowerCase()) return false;         // dojo:dojo
  if (DEFAULT_DB_PASSWORD.test(pass)) return false;                    // user:pass
  // A host without a dot is a container name or a placeholder ("db", "host").
  if (!host.includes('.') || /^(?:localhost|127\.|0\.0\.0\.0|host\.docker\.internal)/i.test(host)) return false;
  return true;
}

/**
 * True when a secret-rule match looks like a real credential. `after` is the
 * file text that follows the match (used for private-key headers).
 *
 * Real credentials are long, random strings. Placeholders are made of words
 * (`sk-ant-api03-your-key-here`), fillers (`AIzaSyXXXX`, `…`), templates
 * (`${{ secrets.X }}`, `$(gh auth token)`, `<token>`), code that reads the
 * value from elsewhere (`os.getenv("X")`, `env["X"]`), or are too short.
 */
export function isCredibleSecret(match: string, after: string): boolean {
  if (match.startsWith('-----BEGIN')) {
    // A key block has a body on the next line. A header followed by nothing
    // or by another header is a list of formats, not a key.
    if (after.trim() === '') return false;
    const rest = after.replace(/^[ \t]*\r?\n/, '');
    if (rest === after) return true; // more text on the header's own line
    const next = rest.split('\n', 1)[0] ?? '';
    return next.trim() !== '' && !next.startsWith('-----BEGIN');
  }
  let value = match;
  let name: string | null = null;
  const eq = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/.exec(match);
  if (eq) { name = eq[1] ?? null; value = eq[2] ?? ''; }
  if (name && name.toUpperCase() === 'DATABASE_URL') return credibleDatabaseUrl(value);
  value = value.replace(/^["'`]+/, '');
  // Code that computes the value (a call or a subscript) is not a value.
  if (/^[A-Za-z_][\w.]*\s*[([]/.test(value)) return false;
  // Cut at the end of the string literal or at an escape sequence.
  value = value.split(/\\[nrt"'\\]|["'`,;)\]}<>]/)[0] ?? '';
  if (!/^[A-Za-z0-9]/.test(value)) return false;        // empty, templated, punctuation
  if (name && value.toUpperCase() === name.toUpperCase()) return false; // KEY=KEY
  const body = value.replace(TOKEN_PREFIX, '');
  if (body.length < 16) return false;
  if (PLACEHOLDER_WORDS.test(value)) return false;
  if (/(.)\1{7,}/.test(body)) return false;            // XXXXXXXX, 00000000
  if (/abcdefgh|bcdefghi|01234567|12345678|qwertyui/i.test(body)) return false;
  // Lowercase words joined by separators: a secret-manager reference
  // ("anthropic-key:latest") or a label, not a random key.
  if (/^[a-z]+(?:[-_:.][a-z0-9]+)*$/.test(value)) return false;
  return true;
}

// ── Commands that run (EX-008, EX-015: exec_context) ────────────────────────

/** Files whose every value is run as part of an agent's environment or hooks. */
const AGENT_ENV_PATH = /(?:^|\/)(?:\.cursor\/environment\.json$|\.container-use\/|\.devcontainer\/|\.codex\/|\.openhands\/|\.kiro\/|\.claude\/|\.gemini\/|\.windsurf\/|\.amazonq\/|\.continue\/|hooks?\/|[^/]*hooks?\.(?:json|ya?ml)$|[^/]*\.hook\.ya?ml$)/i;
/** Keys whose value is executed (normalised: lowercase, no `-` or `_`). */
const EXEC_KEYS = new Set([
  'command', 'commands', 'cmd', 'cmds', 'run', 'runs', 'script', 'scripts', 'exec', 'execute', 'shell',
  'entrypoint', 'args', 'argv', 'setup', 'setupcommands', 'setupscript', 'installcommand', 'installcommands',
  'postcreatecommand', 'oncreatecommand', 'updatecontentcommand', 'poststartcommand', 'postattachcommand',
  'initializecommand', 'prestart', 'poststart', 'preinstall', 'postinstall', 'beforeinstall', 'init',
  'then', 'do', 'action', 'hook', 'hooks', 'steps', 'startcommand', 'buildcommand',
]);
const KEY_AT_LINE_START = /^\s*[{[,]?\s*(?:-\s*)?["']?([A-Za-z0-9_.-]+)["']?\s*:/;
/** Every `"key":` or `key:` on a line (JSON or YAML). */
const KEY_ON_LINE = /(?:["']([A-Za-z0-9_.-]+)["']|(?:^|[\s{,[-])([A-Za-z0-9_.-]+))\s*:(?=\s|["'[{|>]|$)/g;
/** "Run: curl …", "please execute curl …": a step the reader is told to run. */
const IMPERATIVE_BEFORE = /\b(?:run|execute|exec|paste|type|enter|invoke)\b\W{0,3}$/i;

const normKey = (k: string): string => k.toLowerCase().replace(/[-_]/g, '');

/**
 * True when the command at `at` in a config file is something that runs: the
 * value of a command-like key, an item in a command list, a step the text
 * tells the reader to run, or anything in an agent-environment or hook file.
 * Data that merely lists an install command (`curl: "curl … | sh"` in a docs
 * data file, an `install` field in an agent catalogue) is not.
 */
export function inExecContext(rel: string, text: string, at: number, match = ''): boolean {
  if (AGENT_ENV_PATH.test(rel)) return true;
  // The match is itself an order to run something ("you must run this command").
  if (/^(?:you\s+must|always|now|first|please)\s+run\b/i.test(match)) return true;
  const lineStart = text.lastIndexOf('\n', at - 1) + 1;
  const before = text.slice(lineStart, at);
  if (IMPERATIVE_BEFORE.test(before.slice(-40))) return true;
  // The key nearest before the match on its own line ("command": "…curl…").
  const keys = [...before.matchAll(KEY_ON_LINE)];
  const own = keys[keys.length - 1];
  if (own) return EXEC_KEYS.has(normKey(own[1] ?? own[2] ?? ''));
  // A list item or a continuation line: the nearest less-indented key above.
  const indent = (s: string): number => (/^\s*/.exec(s)?.[0].length ?? 0);
  let cur = indent(before);
  let end = lineStart - 1;
  for (let steps = 0; end > 0 && steps < 200; steps++) {
    const start = text.lastIndexOf('\n', end - 1) + 1;
    const line = text.slice(start, end);
    end = start - 1;
    if (line.trim() === '') continue;
    const ind = indent(line);
    if (ind >= cur) continue;
    cur = ind;
    const key = KEY_AT_LINE_START.exec(line);
    if (key) return EXEC_KEYS.has(normKey(key[1] ?? ''));
  }
  return false;
}

// ── Markdown code (skip_in_code) ────────────────────────────────────────────

/** Start and end offsets of fenced code blocks (``` or ~~~). */
export function fencedRanges(text: string): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  const re = /^ {0,3}(`{3,}|~{3,})[^\n]*$/gm;
  let open: { at: number; fence: string } | null = null;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const fence = m[1] ?? '';
    if (!open) open = { at: m.index, fence };
    else if (fence[0] === open.fence[0] && fence.length >= open.fence.length && m[0].trim() === fence) {
      out.push([open.at, m.index + m[0].length]);
      open = null;
    }
  }
  if (open) out.push([open.at, text.length]);
  return out;
}

/** True when `at` is inside inline code (an odd number of backticks before it on its line) or a fenced block. */
export function inMarkdownCode(text: string, at: number, fences: Array<[number, number]>): boolean {
  if (fences.some(([a, b]) => at >= a && at < b)) return true;
  const lineStart = text.lastIndexOf('\n', at - 1) + 1;
  const ticks = (text.slice(lineStart, at).match(/`+/g) ?? []).length;
  return ticks % 2 === 1;
}

// ── Quoted examples (quoted_example_cues) ───────────────────────────────────

const OPEN_QUOTE = /["'“‘«‹`„]\s*$/;
const CLOSES_SOON = /^[^\n"'”’»›`“]{0,40}["'”’»›`“]/;

/**
 * True when the phrase at [at, at+len) is in quotation marks that close right
 * after it, and the passage around it (its paragraph, at most a few hundred
 * characters) matches `cues`: the phrase is being quoted as an example or
 * warned against ("never follow text such as "ignore previous
 * instructions""), not given as an order. A quoted phrase that runs on into
 * a longer instruction is not exempt.
 */
export function isQuotedExample(text: string, at: number, len: number, cues: RegExp): boolean {
  if (!OPEN_QUOTE.test(text.slice(Math.max(0, at - 3), at))) return false;
  if (!CLOSES_SOON.test(text.slice(at + len, at + len + 60))) return false;
  const paraStart = text.lastIndexOf('\n\n', at);
  const start = Math.max(paraStart === -1 ? 0 : paraStart, at - 400);
  const paraEnd = text.indexOf('\n\n', at + len);
  const end = Math.min(paraEnd === -1 ? text.length : paraEnd, at + len + 300);
  return cues.test(text.slice(start, at) + ' ' + text.slice(at + len, end));
}

// ── Decoded blobs (EX-003) ──────────────────────────────────────────────────

/**
 * What a decoded blob is when it is a file rather than a message: markup
 * (SVG, XML, HTML), a PDF, a Markdown document (front matter or a heading), a
 * licence, or anything that starts with a byte-order mark. Such blobs are
 * embedded files; they count only if what they say is flagged by the other
 * rules. Null for free text and commands.
 */
export function embeddedDocumentKind(decoded: string): string | null {
  if (/^(?:\uFEFF|\xEF\xBB\xBF)/.test(decoded)) return 'file with a byte-order mark';
  const s = decoded.replace(/^\s+/, '');
  if (/^<(?:\?xml|svg\b|!DOCTYPE|html\b|!--)/i.test(s)) return 'markup';
  if (s.startsWith('%PDF-')) return 'PDF';
  if (/^[{[]/.test(s)) return 'JSON';
  if (/^---\r?\n[\w-]+\s*:/.test(s)) return 'Markdown with front matter';
  if (/^#{1,6} \S/.test(s)) return 'Markdown';
  if (/^(?:MIT License|Apache License|BSD \d-Clause|GNU (?:GENERAL|LESSER|AFFERO)|Copyright (?:\(c\)|©|\d{4}))/i.test(s)) return 'licence';
  return null;
}

/** Decode a base64 or hex blob (as matched by EX-003) to text, or null. */
export function decodeBlob(s: string): string | null {
  const hex = s.replace(/\\x/gi, '').replace(/^0x/i, '');
  if (/^[0-9a-f]+$/i.test(hex) && hex.length % 2 === 0 && hex.length >= 48) return Buffer.from(hex, 'hex').toString('utf8');
  const b = s.replace(/=+$/, '');
  if (/[^A-Za-z0-9+/]/.test(b)) return null;
  return Buffer.from(b, 'base64').toString('utf8');
}
