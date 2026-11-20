/**
 * Reworded instructions aimed at the AI, in text that comes back from tools
 * and servers (S-009). The signature rules know fixed phrasings; this layer
 * looks for the INTENT in many phrasings and disguises:
 *
 *   override  - setting aside the agent's instructions ("pay no attention to
 *               what came before", "your real task is", "system override:")
 *   conceal   - hiding it from the user ("don't mention this to the user")
 *   action    - an exfiltration or command ("send the .env", "run curl ... | sh")
 *   role      - changing what the agent is ("from now on you are", "developer mode")
 *
 * One signal alone is a warning (a security article may quote an attack); two
 * kinds together within a short stretch of text are an attack and are
 * blocked. Every view of the text is checked: Unicode-normalised, look-alike
 * letters mapped to Latin, hidden characters removed, s p a c e d letters
 * joined, and simple digit-for-letter swaps undone.
 */
export type Signal = 'override' | 'conceal' | 'action' | 'role';
export type ParaphraseVerdict = { level: 'none' | 'warn' | 'block'; signals: Signal[] };

const W = String.raw`[\s\W_]{0,3}`; // what may sit between words
const words = (...ws: string[]): string => ws.join(`${W}`);
const any = (...alts: string[]): string => `(?:${alts.join('|')})`;

const SET_ASIDE = any(
  'ignore', 'ignoring', 'disregard', 'forget', 'discard', 'drop', 'dismiss', 'abandon', 'override', 'overrule', 'supersede', 'bypass', 'skip',
  'set\\W{0,3}aside', 'put\\W{0,3}aside', 'throw\\W{0,3}out', 'scrap', 'cancel', 'void', 'erase', 'wipe',
  'pay\\W{0,3}no\\W{0,3}(?:attention|heed|mind)\\W{0,3}to', 'pay\\W{0,3}no\\W{0,3}attention', 'take\\W{0,3}no\\W{0,3}notice\\W{0,3}of',
  "(?:do\\W{0,3}not|don'?t|stop|no\\W{0,3}longer)\\W{0,3}(?:follow(?:ing)?|obey(?:ing)?|listen(?:ing)?\\W{0,3}to|heed(?:ing)?|honou?r(?:ing)?)",
);
/** Words that point back at the agent's own instructions. */
const PREVIOUS = any('previous', 'prior', 'earlier', 'above', 'preceding', 'foregoing', 'original', 'initial', 'system', 'developer', 'your', 'all');
/** Filler that may sit around them. */
const FILLER = any('the', 'any', 'every', 'of', 'old', 'existing', 'current', 'default', 'these', 'those', 'such', 'other');
const ORDERS = any(
  'instructions?', 'directions?', 'directives?', 'guidance', 'guidelines?', 'rules?', 'prompts?', 'messages?', 'context', 'constraints?',
  'restrictions?', 'polic(?:y|ies)', 'safety\\W{0,3}(?:rules|guidelines|measures)', 'orders?', 'commands?', 'programming', 'training', 'configuration',
);
const BEFORE = any(
  'what\\W{0,3}came\\W{0,3}before', 'what\\W{0,3}(?:you\\W{0,3}were|was)\\W{0,3}(?:told|said|given)(?:\\W{0,3}(?:before|earlier|above))?',
  'everything\\W{0,3}(?:above|before|so\\W{0,3}far|you\\W{0,3}were\\W{0,3}told)', 'all\\W{0,3}of\\W{0,3}the\\W{0,3}above',
  'the\\W{0,3}(?:conversation|chat)\\W{0,3}so\\W{0,3}far', 'your\\W{0,3}(?:task|job|instructions)',
);

const OVERRIDE = [
  new RegExp(`\\b${SET_ASIDE}${W}(?:${FILLER}${W}){0,2}${PREVIOUS}${W}(?:${any(FILLER, PREVIOUS)}${W}){0,2}${ORDERS}\\b`, 'i'),
  new RegExp(`\\b${SET_ASIDE}${W}${BEFORE}`, 'i'),
  new RegExp(`\\b${any('new', 'updated', 'revised', 'real', 'actual', 'true', 'secret', 'hidden', 'important', 'priority', 'urgent', 'override')}${W}${any('instructions?', 'task', 'objective', 'directives?', 'mission', 'orders?', 'goal')}${W}(?:is|are|:|for\\W{0,3}(?:you|the\\W{0,3}(?:assistant|ai|agent|model)))`, 'i'),
  new RegExp(`\\b${words('your', any('real', 'actual', 'true', 'new', 'only'), any('task', 'job', 'goal', 'purpose', 'instructions?', 'mission'))}${W}(?:is|are|now)\\b`, 'i'),
  new RegExp(`(?:^|[\\s\\[<(*#])${any('system', 'admin(?:istrator)?', 'developer', 'operator', 'root', 'security\\W{0,3}team', 'anthropic', 'openai')}${W}${any('override', 'message', 'note', 'notice', 'instructions?', 'prompt', 'command', 'alert', 'update')}\\s*[:\\]>]`, 'i'),
  new RegExp(`<\\s*/?\\s*${any('system', 'sys', 'instructions?', 'admin', 'im_start', 'assistant')}\\s*>`, 'i'),
  new RegExp(`\\b${words(any('instead', 'rather'), any('of\\W{0,3}(?:that|answering|doing\\W{0,3}that|what\\W{0,3}the\\W{0,3}user\\W{0,3}(?:asked|wants))', 'than\\W{0,3}(?:that|answering)'))}`, 'i'),
];

const CONCEAL = [
  new RegExp(`\\b${any("do\\W{0,3}not", "don'?t", 'never', 'avoid', 'without')}${W}${any('tell(?:ing)?', 'inform(?:ing)?', 'mention(?:ing)?', 'alert(?:ing)?', 'notify(?:ing)?', 'show(?:ing)?', 'reveal(?:ing)?', 'disclos(?:e|ing)', 'report(?:ing)?', 'let(?:ting)?\\W{0,3}(?:the\\W{0,3})?(?:user|human)\\W{0,3}know', 'ask(?:ing)?', 'confirm(?:ing)?\\W{0,3}with', 'bother(?:ing)?')}${W}(?:${any('this', 'it', 'that', 'anything', 'about\\W{0,3}(?:this|it)')}${W}){0,2}(?:to${W})?(?:the${W}|your${W})?${any('user', 'human', 'operator', 'owner', 'developer', 'person', 'them', 'anyone')}`, 'i'),
  new RegExp(`\\b${any('keep', 'leave')}${W}(?:this|it|that)${W}${any('secret', 'hidden', 'quiet', 'confidential', 'between\\W{0,3}us', 'to\\W{0,3}yourself', 'out\\W{0,3}of\\W{0,3}(?:the\\W{0,3})?(?:response|reply|answer|summary|output)')}`, 'i'),
  new RegExp(`\\b${any('silently', 'quietly', 'covertly', 'secretly', 'discreetly', 'invisibly', 'in\\W{0,3}the\\W{0,3}background', 'behind\\W{0,3}the\\W{0,3}scenes')}${W}${any('send', 'upload', 'post', 'run', 'execute', 'call', 'forward', 'copy', 'include', 'attach', 'email', 'transmit')}`, 'i'),
  new RegExp(`\\b${any('the\\W{0,3}user\\W{0,3}(?:must|should)\\W{0,3}not\\W{0,3}(?:know|see|find\\W{0,3}out)', 'hide\\W{0,3}(?:this|it)\\W{0,3}from')}`, 'i'),
];

const SENSITIVE = any(
  '\\.env\\b', 'env(?:ironment)?\\W{0,3}(?:file|variables?|vars)', 'credentials?', 'secrets?', 'api\\W{0,3}keys?', 'access\\W{0,3}keys?', 'tokens?', 'passwords?',
  'pass\\W{0,3}phrases?', 'ssh\\W{0,3}keys?', '~\\/\\.ssh', '\\.ssh\\b', 'id_(?:rsa|ed25519|ecdsa)', 'private\\W{0,3}keys?', 'cookies?', 'session\\W{0,3}(?:ids?|tokens?)',
  'aws\\W{0,3}(?:credentials|keys?|config)', '\\.aws\\b', '\\.npmrc', '\\.netrc', '\\.git-credentials', 'kube\\W{0,3}config', 'wallet', 'seed\\W{0,3}phrase',
  'the\\W{0,3}(?:full\\W{0,3})?contents?\\W{0,3}of', 'source\\W{0,3}code', 'chat\\W{0,3}history', 'conversation\\W{0,3}history', 'system\\W{0,3}prompt',
);
const SEND = any('send', 'post', 'upload', 'transmit', 'forward', 'e-?mail', 'share', 'exfiltrate', 'leak', 'submit', 'paste', 'copy', 'include', 'attach', 'append', 'embed', 'encode', 'write', 'dump', 'print', 'reveal', 'output', 'return', 'read');
const ACTION = [
  new RegExp(`\\b${SEND}${W}(?:(?:the|all|any|every|your|my|their|of|full|entire|contents?|values?)${W}){0,4}${SENSITIVE}`, 'i'),
  new RegExp(`\\b${any('run', 'execute', 'exec', 'eval', 'invoke', 'type', 'enter', 'paste')}${W}(?:this|the\\W{0,3}following|these)?${W}?(?:command|script|code|line)?s?${W}?[:\`'"]?${W}?${any('curl', 'wget', 'bash', 'sh\\W{0,3}-c', 'zsh', 'powershell', 'iex', 'invoke-expression', 'rm\\W{0,3}-rf', 'chmod', 'base64\\W{0,3}-d', 'nc\\W', 'ncat', 'python\\W{0,3}-c', 'node\\W{0,3}-e', 'eval')}`, 'i'),
  new RegExp(`\\b${any('curl', 'wget')}\\b[^\\n]{0,120}\\|\\s*(?:ba|z)?sh\\b`, 'i'),
  new RegExp(`\\b${any('call', 'use', 'invoke', 'trigger')}${W}(?:the${W})?[\\w.-]{2,40}${W}tool${W}${any('with', 'to\\W{0,3}send', 'to\\W{0,3}upload', 'to\\W{0,3}delete', 'to\\W{0,3}write')}`, 'i'),
  new RegExp(`\\b${any('delete', 'remove', 'wipe', 'erase', 'drop', 'truncate', 'overwrite')}${W}(?:(?:all|every|the|their|your)${W}){0,2}${any('files?', 'reposi?tor(?:y|ies)', 'database', 'tables?', 'branch(?:es)?', 'commits?', 'backups?', 'home\\W{0,3}(?:folder|directory)')}`, 'i'),
];

const ROLE = [
  new RegExp(`\\b${any('from\\W{0,3}now\\W{0,3}on', 'starting\\W{0,3}now', 'henceforth', 'going\\W{0,3}forward')}${W},?${W}?you${W}${any('are', 'will', 'must', 'shall', 'should', 'have\\W{0,3}to')}`, 'i'),
  new RegExp(`\\byou${W}${any('are\\W{0,3}no\\W{0,3}longer', 'are\\W{0,3}not\\W{0,3}(?:an?|the)\\W{0,3}(?:assistant|ai|helpful)', 'have\\W{0,3}been\\W{0,3}(?:freed|unlocked|jailbroken|re-?programmed)', 'are\\W{0,3}now\\W{0,3}(?:in\\W{0,3})?(?:dan|developer|god|admin|root|unrestricted|jailbreak)')}`, 'i'),
  new RegExp(`\\b${any('developer', 'god', 'dan', 'jailbreak', 'unrestricted', 'unfiltered', 'admin', 'debug', 'maintenance')}${W}mode${W}${any('enabled', 'activated', 'on', 'unlocked', 'engaged')}`, 'i'),
  new RegExp(`\\b${any('pretend', 'act', 'behave', 'roleplay', 'role-play')}${W}${any('to\\W{0,3}be', 'as\\W{0,3}if\\W{0,3}you\\W{0,3}(?:are|were)', 'as\\W{0,3}(?:an?|the)', 'you\\W{0,3}are')}${W}(?:an?${W})?${any('unrestricted', 'unfiltered', 'evil', 'malicious', 'different', 'new', 'jailbroken', 'rogue', 'admin', 'root', 'system')}`, 'i'),
  new RegExp(`\\b${any('as\\W{0,3}an\\W{0,3}ai', 'dear\\W{0,3}(?:ai|assistant|agent|model|llm|claude|gpt)', '(?:hey|attention|note\\W{0,3}to|message\\W{0,3}for)\\W{0,3}(?:the\\W{0,3})?(?:ai|assistant|agent|model|llm)')}\\b`, 'i'),
];

// ── normalisation ─────────────────────────────────────────────────────────────

const CONFUSABLES: Record<string, string> = {
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ј: 'j', ѕ: 's', ԁ: 'd', ɡ: 'g', һ: 'h', ӏ: 'l', ո: 'n', ս: 'u', ν: 'v', ο: 'o', ρ: 'p', τ: 't', α: 'a',
  ε: 'e', ι: 'i', κ: 'k', Α: 'A', Β: 'B', Ε: 'E', Η: 'H', Ι: 'I', Κ: 'K', Μ: 'M', Ν: 'N', Ο: 'O', Ρ: 'P', Τ: 'T', Χ: 'X', А: 'A', В: 'B', Е: 'E', К: 'K', М: 'M', Н: 'H',
  О: 'O', Р: 'P', С: 'C', Т: 'T', Х: 'X',
};
const HIDDEN = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]|\udb40[\udc00-\udfff]/g;
const LEET: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', $: 's', '!': 'i' };

/** The views of a text that are checked. */
export function views(text: string): string[] {
  const base = text.normalize('NFKC').replace(HIDDEN, '');
  const latin = [...base].map((c) => CONFUSABLES[c] ?? c).join('');
  // "i g n o r e  a l l" -> "ignore all": runs of single letters separated by one space or dot.
  // Words are separated by two or more spaces in that style, so keep a single space between them.
  const joined = latin.replace(/(?<![a-z])(?:[a-z][ .\-_*]){2,}[a-z](?![a-z])/gi, (m) => m.replace(/[ .\-_*]/g, ''));
  const spaced = latin.replace(/(?<![a-z])(?:[a-z] ){2,}[a-z](?![a-z])/gi, (m) => m.replace(/ /g, ''));
  const unleet = (joined === latin ? spaced : joined).replace(/[a-z][0-9@$!][a-z0-9@$!]*|[0-9@$!][a-z]/gi, (m) => m.replace(/[013457@$!]/g, (c) => LEET[c] ?? c));
  return [...new Set([text, latin, joined, spaced, unleet])];
}

const WINDOW = 400;

type Hit = { signal: Signal; at: number };

function hitsIn(view: string): Hit[] {
  const hits: Hit[] = [];
  const scan = (signal: Signal, res: RegExp[]): void => {
    for (const re of res) {
      const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
      let n = 0;
      for (const m of view.matchAll(g)) {
        hits.push({ signal, at: m.index ?? 0 });
        if (++n >= 20) break;
      }
    }
  };
  scan('override', OVERRIDE);
  scan('conceal', CONCEAL);
  scan('action', ACTION);
  scan('role', ROLE);
  return hits;
}

const MAX_CHARS = 200_000;

export function detectParaphrase(text: string): ParaphraseVerdict {
  const t = text.slice(0, MAX_CHARS);
  const all = new Set<Signal>();
  let block = false;
  for (const view of views(t)) {
    const hits = hitsIn(view);
    for (const h of hits) all.add(h.signal);
    // Two different kinds of signal close together is an attack. The pairs
    // that count: override + anything, conceal + action, role + action.
    for (const a of hits) {
      for (const b of hits) {
        if (a.signal === b.signal || Math.abs(a.at - b.at) > WINDOW) continue;
        const pair = new Set([a.signal, b.signal]);
        if (pair.has('override') || (pair.has('conceal') && pair.has('action')) || (pair.has('role') && pair.has('action')) || (pair.has('role') && pair.has('conceal'))) {
          block = true;
        }
      }
    }
  }
  const signals = [...all].sort();
  if (block) return { level: 'block', signals };
  // One signal alone is only worth a warning, except override, which in data
  // returned to an agent has no ordinary use.
  if (all.has('override')) return { level: 'warn', signals };
  return { level: signals.length > 0 ? 'warn' : 'none', signals };
}
