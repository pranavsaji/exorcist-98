/**
 * The live Shield console page: one self-contained HTML document with its CSS
 * and script inline (allowed by a per-response CSP nonce). No external assets,
 * no network beyond its own event stream.
 *
 * Every string from the event log or the session records is attacker-
 * reachable (tool and server names come from MCP servers), so the script only
 * ever puts data into the page with textContent and attributes it sets
 * itself; it never parses data as HTML. The server puts no data in the HTML.
 *
 * The page is a read-only view: it has no form, no button that changes
 * anything and no endpoint to call. A held session is released by a person:
 * in the system prompt (Touch ID or login password) when a Shield runs with
 * `sessionRelease: os`, otherwise with `exorcist approve session <key>` in a
 * real terminal. The page only says which.
 */

/** Short names for the rules the console shows most, next to the rule id. */
export const RULE_NAMES: Record<string, string> = {
  'EX-002': 'Prompt injection',
  'EX-005': 'Poisoned tool',
  'EX-006': 'Rug pull',
  'EX-010': 'Changed program',
  'EX-011': 'Secrets file',
  'EX-016': 'Unknown host',
  'EX-017': 'Secret',
  'EX-022': 'Canary',
  'EX-025': 'Loader variable',
  'EX-027': 'Session Guard',
  'AI-JUDGE': 'AI judge',
  SHIELD: 'Shield',
};

const CSS = String.raw`
:root {
  --desk: #23163d; --desk2: #2e1d50; --face: #cfc8dc; --hilite: #f4f0fa; --shade: #6b6180; --ink: #120b22;
  --muted: #3b3250; --title: #4b2a8a; --title2: #8a3fb0; --phosphor: #39ff88;
  --crit: #ff3b6b; --high: #ff9a3c; --med: #ffd93c; --ok: #8dffb4; --low: #6bd0ff; --paper: #ffffff;
  --focus: #120b22;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --ui: ui-sans-serif, system-ui, "Segoe UI", Helvetica, Arial, sans-serif;
  color-scheme: light;
}
* { box-sizing: border-box; }
html, body { margin: 0; min-height: 100%; }
body {
  background: var(--desk);
  background-image:
    radial-gradient(circle at 18% 12%, rgba(138, 63, 176, 0.35), transparent 40%),
    radial-gradient(circle at 85% 80%, rgba(57, 255, 136, 0.08), transparent 35%),
    repeating-linear-gradient(0deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 3px);
  color: var(--ink); font-family: var(--ui); font-size: 15px; line-height: 1.4;
}
:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
.on-dark { --focus: #ffffff; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
.skip { position: absolute; left: 8px; top: -40px; z-index: 10; background: var(--face); color: var(--ink); padding: 6px 10px; font-weight: 700; }
.skip:focus { top: 8px; }
code, .mono { font-family: var(--mono); font-size: 0.86em; }
h1, h2, h3, h4, p { margin: 0; }

.desk { max-width: 1440px; margin: 0 auto; padding: 16px 16px 72px; display: flex; flex-direction: column; gap: 14px; }

.win {
  background: var(--face); color: var(--ink); padding: 3px; min-width: 0;
  box-shadow: inset -2px -2px 0 var(--shade), inset 2px 2px 0 var(--hilite), 0 0 0 1px var(--ink), 6px 6px 0 rgba(0,0,0,0.45);
}
.titlebar {
  display: flex; align-items: center; gap: 8px; padding: 3px 6px; color: #fff; font-weight: 700;
  background: linear-gradient(90deg, var(--title), var(--title2));
}
.titlebar h1, .titlebar h2 { font-size: 0.95rem; font-weight: 700; flex: 1; min-width: 0; overflow-wrap: anywhere; }
.titlebar .count { font-family: var(--mono); font-size: 0.8rem; font-weight: 600; }
.chrome { display: flex; gap: 3px; }
.chrome span { width: 18px; height: 16px; background: var(--face); box-shadow: inset -1px -1px 0 var(--shade), inset 1px 1px 0 var(--hilite), 0 0 0 1px var(--ink); }
.ghost { width: 20px; height: 20px; flex: none; }
.body { padding: 10px; display: flex; flex-direction: column; gap: 10px; }
.inset { background: var(--paper); box-shadow: inset 2px 2px 0 var(--shade), inset -2px -2px 0 var(--hilite), 0 0 0 1px var(--ink); }

.head-body { display: grid; grid-template-columns: 1fr auto; gap: 10px 16px; align-items: start; }
.lede { font-size: 1rem; }
.readonly {
  grid-column: 1 / -1; display: flex; gap: 10px; align-items: flex-start; padding: 8px 10px;
  background: #fff7c2; box-shadow: inset 0 0 0 1px var(--ink);
}
.readonly strong { white-space: nowrap; }
.conn { display: inline-flex; align-items: center; gap: 6px; padding: 3px 10px; font-weight: 800; letter-spacing: 0.04em; font-size: 0.8rem; background: var(--ink); color: var(--phosphor); white-space: nowrap; }
.conn .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--phosphor); }
.conn[data-live="false"] { color: var(--med); }
.conn[data-live="false"] .dot { background: transparent; border: 2px solid var(--med); border-radius: 0; }
.where { grid-column: 1 / -1; font-size: 0.85rem; color: var(--muted); overflow-wrap: anywhere; }

.stats { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; list-style: none; margin: 0; padding: 0; }
.stat { padding: 8px 10px; display: flex; flex-direction: column; gap: 2px; }
.stat .n { font-family: var(--mono); font-size: 1.7rem; font-weight: 800; line-height: 1.1; }
.stat .l { display: flex; align-items: center; gap: 6px; font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; }

.grid { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(0, 1fr); gap: 14px; align-items: start; }
.side { display: flex; flex-direction: column; gap: 14px; min-width: 0; }

.toolbar { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.toolbar .label { font-size: 0.85rem; font-weight: 700; margin-right: 4px; }
.btn {
  font: inherit; font-size: 0.85rem; font-weight: 700; color: var(--ink); background: var(--face); border: 0; padding: 4px 10px; cursor: pointer; min-height: 30px;
  box-shadow: inset -2px -2px 0 var(--shade), inset 2px 2px 0 var(--hilite), 0 0 0 1px var(--ink);
}
.btn[aria-pressed="true"] { background: #e9e4f2; box-shadow: inset 2px 2px 0 var(--shade), inset -2px -2px 0 var(--hilite), 0 0 0 1px var(--ink); }

.feed { list-style: none; margin: 0; padding: 0; max-height: 70vh; overflow: auto; }
.ev { display: grid; grid-template-columns: 9.5rem minmax(0, 1fr) auto; gap: 4px 12px; padding: 9px 10px; border-bottom: 1px solid #ddd6e8; align-items: start; }
.ev:last-child { border-bottom: 0; }
.ev[hidden], [hidden] { display: none !important; }
.ev .t { font-family: var(--mono); font-size: 0.8rem; color: var(--muted); white-space: nowrap; }
.ev-title { font-weight: 700; overflow-wrap: anywhere; }
.ev-title .on { font-weight: 400; color: var(--muted); }
.why { font-size: 0.88rem; color: #2a2238; overflow-wrap: anywhere; margin-top: 2px; }
.tag { display: inline-block; font-size: 0.72rem; font-weight: 800; padding: 0 5px; margin-left: 4px; border: 1px solid var(--ink); background: var(--paper); vertical-align: 1px; }
.empty { padding: 18px 14px; color: var(--muted); }
.empty strong { color: var(--ink); display: block; margin-bottom: 4px; }

.badge { display: inline-flex; align-items: center; gap: 6px; padding: 2px 7px; font-size: 0.74rem; font-weight: 800; letter-spacing: 0.04em; border: 1px solid var(--ink); color: var(--ink); white-space: nowrap; justify-self: start; }
.badge.allowed { background: var(--ok); }
.badge.held { background: var(--med); }
.badge.blocked, .badge.critical, .badge.armed { background: var(--crit); }
.badge.withheld { background: #ff8fb0; }
.badge.flagged, .badge.high, .badge.cautious { background: var(--high); }
.badge.medium, .badge.watching { background: var(--med); }
.badge.calm { background: var(--ok); }
.badge.chain-none { background: var(--paper); }
.badge.monitor { background: repeating-linear-gradient(135deg, var(--ok) 0 6px, #d6ffe4 6px 12px); }
.shape { width: 11px; height: 11px; flex: none; background: var(--ink); display: inline-block; }
.shape.circle { border-radius: 50%; }
.shape.diamond { transform: rotate(45deg) scale(0.85); }
.shape.square { border-radius: 0; }
.shape.octagon { clip-path: polygon(30% 0, 70% 0, 100% 30%, 100% 70%, 70% 100%, 30% 100%, 0 70%, 0 30%); }
.shape.triangle { clip-path: polygon(50% 0, 100% 100%, 0 100%); }
.shape.ring { background: transparent; border: 2px solid var(--ink); border-radius: 50%; }
.rule { display: inline-block; font-family: var(--mono); font-size: 0.76rem; font-weight: 700; padding: 0 5px; background: var(--ink); color: #fff; margin-left: 6px; white-space: nowrap; vertical-align: 1px; }

.sess { padding: 10px; display: flex; flex-direction: column; gap: 8px; }
.sess + .sess { border-top: 2px dashed #b9b0c9; }
.sess h3 { font-size: 0.95rem; display: flex; flex-wrap: wrap; gap: 6px; align-items: center; overflow-wrap: anywhere; }
.verdict { font-size: 0.92rem; }
.legs { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 6px; list-style: none; margin: 0; padding: 0; }
.leg { padding: 6px 8px; font-size: 0.8rem; box-shadow: inset 0 0 0 1px var(--ink); background: #ece8f3; display: flex; flex-direction: column; gap: 2px; }
.leg b { font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.04em; }
.leg[data-on="true"] { background: #2a1a47; color: #fff; }
.leg[data-on="true"] .shape { background: var(--crit); }
.leg .st { display: flex; gap: 5px; align-items: center; font-weight: 700; }
.facts h4 { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 3px; }
.facts ul, .plain { list-style: none; margin: 0; padding: 0; }
.facts li { font-size: 0.86rem; padding: 3px 0; overflow-wrap: anywhere; }
.facts li .when { font-family: var(--mono); font-size: 0.76rem; color: var(--muted); margin-left: 4px; }
.release { font-size: 0.86rem; padding: 7px 9px; background: #120b22; color: #e8e2f3; }
.release code { color: var(--phosphor); font-size: 0.9em; overflow-wrap: anywhere; }
.problem { font-size: 0.85rem; padding: 6px 8px; background: #ffe1b8; box-shadow: inset 0 0 0 1px var(--ink); overflow-wrap: anywhere; }

.shield { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 2px 10px; padding: 7px 10px; border-bottom: 1px solid #ddd6e8; font-size: 0.88rem; }
.shield:last-child { border-bottom: 0; }
.shield .nm { font-weight: 700; overflow-wrap: anywhere; }
.shield .meta { grid-column: 2; color: var(--muted); font-size: 0.8rem; overflow-wrap: anywhere; }
.alerts { list-style: none; margin: 0; padding: 0; max-height: 42vh; overflow: auto; }
.alert { padding: 8px 10px; border-bottom: 1px solid #ddd6e8; display: flex; flex-direction: column; gap: 4px; }
.alert:last-child { border-bottom: 0; }
.alert .top { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; font-size: 0.82rem; }
.alert .msg { font-size: 0.85rem; overflow-wrap: anywhere; }

.taskbar {
  position: fixed; left: 0; right: 0; bottom: 0; height: 44px; display: flex; align-items: center; gap: 10px; padding: 0 10px;
  background: var(--face); box-shadow: inset 0 2px 0 var(--hilite), 0 -1px 0 var(--ink); z-index: 5; font-size: 0.85rem;
}
.taskbar .start { display: inline-flex; align-items: center; gap: 6px; font-weight: 800; padding: 3px 8px; box-shadow: inset -2px -2px 0 var(--shade), inset 2px 2px 0 var(--hilite), 0 0 0 1px var(--ink); }
.taskbar .grow { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.taskbar .clock { font-family: var(--mono); padding: 3px 8px; box-shadow: inset 1px 1px 0 var(--shade), inset -1px -1px 0 var(--hilite); }

@media (prefers-reduced-motion: no-preference) {
  .ev.fresh { animation: flash 1.6s ease-out; }
  .conn[data-live="true"] .dot { animation: pulse 1.8s ease-in-out infinite; }
}
@keyframes flash { from { background: #fff2a8; } to { background: transparent; } }
@keyframes pulse { 50% { opacity: 0.35; } }

@media (max-width: 1100px) {
  .stats { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 860px) {
  .grid { grid-template-columns: minmax(0, 1fr); }
  .feed { max-height: none; }
  .alerts { max-height: none; }
}
@media (max-width: 560px) {
  .desk { padding: 10px 10px 64px; gap: 10px; }
  .head-body { grid-template-columns: 1fr; }
  .ev { grid-template-columns: minmax(0, 1fr) auto; }
  .ev .main { grid-column: 1 / -1; grid-row: 2; }
  .legs { grid-template-columns: minmax(0, 1fr); }
  .readonly { flex-direction: column; gap: 2px; font-size: 0.88rem; }
  .lede { font-size: 0.92rem; }
  .conn { justify-self: start; }
  .stats { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 6px; }
  .stat { padding: 6px; }
  .stat .l .badge { white-space: normal; font-size: 0.66rem; padding: 2px 4px; gap: 4px; }
  .stat .n { font-size: 1.25rem; }
  .chrome { display: none; }
  .taskbar .grow { display: none; }
}
`;

// A small pixel ghost. Decorative.
const GHOST = `<svg class="ghost" viewBox="0 0 10 10" aria-hidden="true" focusable="false" shape-rendering="crispEdges"><path fill="#f4f0fa" d="M3 0h4v1h1v1h1v8H8V9H7v1H6V9H4v1H3V9H2v1H1V2h1V1h1z"/><path fill="#120b22" d="M3 3h1v2H3zM6 3h1v2H6z"/></svg>`;

const SCRIPT = String.raw`
(() => {
  'use strict';
  const RULES = __RULES__;
  const base = location.pathname.endsWith('/') ? location.pathname : location.pathname + '/';
  const $ = (id) => document.getElementById(id);
  const MAX_ROWS = 300;
  const MAX_ALERTS = 60;

  // Every piece of data goes in through textContent: never parsed as HTML.
  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function kids(parent, ...children) { for (const c of children) if (c) parent.append(c); return parent; }
  function shape(kind) { const s = el('span', 'shape ' + kind); s.setAttribute('aria-hidden', 'true'); return s; }
  function badge(cls, shapeKind, label) { return kids(el('span', 'badge ' + cls), shape(shapeKind), document.createTextNode(label)); }
  function ruleChip(id) {
    if (!id) return null;
    const name = Object.prototype.hasOwnProperty.call(RULES, id) ? RULES[id] : '';
    return el('span', 'rule', name ? id + ' · ' + name : id);
  }
  function clock(iso) {
    const d = new Date(iso);
    return isNaN(d.getTime()) ? '' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }
  function timeEl(iso) { const t = el('time', 't', clock(iso)); t.setAttribute('datetime', String(iso)); return t; }
  function ago(iso) {
    const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    if (!isFinite(s)) return '';
    if (s < 60) return s + ' s ago';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    return Math.round(s / 3600) + ' h ago';
  }

  const DECISION = {
    allowed:  { cls: 'allowed',  shape: 'circle',   label: 'ALLOWED' },
    held:     { cls: 'held',     shape: 'diamond',  label: 'HELD' },
    blocked:  { cls: 'blocked',  shape: 'octagon',  label: 'BLOCKED' },
    withheld: { cls: 'withheld', shape: 'triangle', label: 'RESULT WITHHELD' },
    flagged:  { cls: 'flagged',  shape: 'triangle', label: 'RESULT FLAGGED' },
  };
  const SEVERITY = {
    critical: { shape: 'octagon', label: 'CRITICAL' },
    high:     { shape: 'triangle', label: 'HIGH' },
    medium:   { shape: 'diamond', label: 'MEDIUM' },
  };
  // What each filter shows. Filters only change the view.
  const FILTERS = {
    all: () => true,
    blocked: (e) => e.decision === 'blocked' || e.decision === 'withheld',
    held: (e) => e.decision === 'held',
    allowed: (e) => e.decision === 'allowed' || e.decision === 'flagged',
  };
  let filter = 'all';

  function row(e, fresh) {
    const d = DECISION[e.decision] || DECISION.blocked;
    const monitor = e.monitor === true;
    const li = el('li', 'ev' + (fresh ? ' fresh' : ''));
    li.dataset.decision = e.decision;
    const b = monitor ? badge('monitor', 'ring', 'ALLOWED · MONITOR') : badge(d.cls, d.shape, d.label);
    const main = el('div', 'main');
    const title = el('p', 'ev-title');
    kids(title, el('span', 'tool', e.kind === 'result' ? 'result of ' + e.tool : e.tool), el('span', 'on', ' on '), el('span', 'srv', e.server), ruleChip(e.ruleId));
    if (e.by === 'user') title.append(el('span', 'tag', 'YOUR ANSWER'));
    main.append(title);
    if (e.why) main.append(el('p', 'why', e.why));
    kids(li, b, main, timeEl(e.time));
    if (!FILTERS[filter](e)) li.hidden = true;
    return li;
  }

  function renderFeed(events) {
    const feed = $('feed');
    const items = events.filter((e) => e.kind === 'call' || e.kind === 'result').slice(-MAX_ROWS).reverse();
    feed.replaceChildren(...items.map((e) => row(e, false)));
    updateEmpty();
  }
  function addToFeed(events) {
    const feed = $('feed');
    for (const e of events) {
      if (e.kind !== 'call' && e.kind !== 'result') continue;
      feed.prepend(row(e, true));
    }
    while (feed.children.length > MAX_ROWS) feed.lastElementChild.remove();
    updateEmpty();
  }
  function updateEmpty() {
    const feed = $('feed');
    const shown = [...feed.children].filter((c) => !c.hidden).length;
    $('feed-empty').hidden = shown > 0;
    $('feed-empty-filtered').hidden = !(shown === 0 && feed.children.length > 0);
    $('feed-count').textContent = feed.children.length + ' shown';
  }

  function alertRow(a) {
    const s = SEVERITY[a.severity] || SEVERITY.medium;
    const li = el('li', 'alert');
    const top = el('div', 'top');
    kids(top, badge(a.severity, s.shape, s.label), ruleChip(a.ruleId), el('span', 'mono', a.server + (a.tool ? ' / ' + a.tool : '')), timeEl(a.time));
    kids(li, top, el('p', 'msg', a.message));
    return li;
  }
  let alerts = [];
  function renderAlerts() {
    const list = $('alerts');
    list.replaceChildren(...alerts.slice(-MAX_ALERTS).reverse().map(alertRow));
    list.hidden = alerts.length === 0;
    $('alerts-empty').hidden = alerts.length > 0;
  }

  function renderStats(c) {
    $('n-allowed').textContent = c.allowed;
    $('n-held').textContent = c.held;
    $('n-blocked').textContent = c.blocked;
    $('n-withheld').textContent = c.withheld + c.flagged;
    $('n-alerts').textContent = c.alerts;
  }

  function factList(title, facts, none) {
    const box = el('div', 'facts');
    box.append(el('h4', null, title + ' (' + facts.length + ')'));
    if (facts.length === 0) { box.append(el('p', 'why', none)); return box; }
    const ul = el('ul');
    for (const f of facts) {
      const li = el('li');
      kids(li, el('strong', null, f.tool), document.createTextNode(' on '), el('strong', null, f.server), document.createTextNode(' ' + f.text), ruleChip(f.ruleId), el('span', 'when', ago(f.time)));
      ul.append(li);
    }
    box.append(ul);
    return box;
  }
  function leg(name, on, yes, no) {
    const li = el('li', 'leg');
    li.dataset.on = on ? 'true' : 'false';
    kids(li, el('b', null, name), kids(el('span', 'st'), shape(on ? 'square' : 'ring'), document.createTextNode(on ? yes : no)));
    return li;
  }
  // Whether the Shields of a session hold outbound calls (not monitor mode or guard off).
  function holds(key) {
    const mine = (state ? state.shields : []).filter((x) => x.session === key && x.running);
    return mine.length === 0 || mine.some((x) => x.mode === 'enforce' && (x.guard === 'hold' || x.guard === 'block'));
  }
  function sessionCard(s) {
    const card = el('article', 'sess');
    const status = s.armed
      ? { cls: 'armed', shape: 'octagon', label: 'ARMED', text: 'Untrusted text and private data both reached the agent in this session, so every Shield of the session holds calls that could send data out.' }
      : s.cautious
        ? { cls: 'cautious', shape: 'triangle', label: 'CAUTIOUS', text: 'Part of the shared session state could not be read and one half is known, so data going out is held to be safe.' }
        : (s.untrusted.length || s.private.length)
          ? { cls: 'watching', shape: 'diamond', label: 'WATCHING', text: 'One half of the trifecta so far. Each step alone is allowed.' }
          : { cls: 'calm', shape: 'circle', label: 'CALM', text: 'Nothing risky noted in this session.' };
    const h = el('h3');
    kids(h, document.createTextNode('Session '), el('code', null, s.key), badge(status.cls, status.shape, status.label));
    card.append(h, el('p', 'verdict', status.text));
    const legs = el('ol', 'legs');
    legs.setAttribute('aria-label', 'The lethal trifecta in this session');
    kids(legs,
      leg('1. Untrusted text', s.untrusted.length > 0, 'seen', 'not seen'),
      leg('2. Private data', s.private.length > 0, 'seen', 'not seen'),
      leg('3. Data going out', s.armed || s.cautious, holds(s.key) ? 'held' : 'sent (monitor mode)', 'allowed'));
    card.append(legs);
    card.append(factList('Untrusted text seen', s.untrusted, 'None yet.'), factList('Private data seen', s.private, 'None yet.'));
    if (s.waiting.length) {
      const box = el('div', 'facts');
      box.append(el('h4', null, 'Calls waiting for your answer (' + s.waiting.length + ')'));
      const ul = el('ul');
      for (const w of s.waiting) {
        const li = el('li');
        kids(li, el('strong', null, w.tool), document.createTextNode(' on '), el('strong', null, w.server), ruleChip(w.ruleId), el('span', 'when', ago(w.time)));
        ul.append(li);
      }
      box.append(ul, el('p', 'why', s.waiting.some((w) => w.via === 'os') ? 'Answer in the system prompt on this computer (Touch ID or your login password). This page cannot answer it.' : "Answer in your agent's approval prompt. This page cannot answer it."));
      card.append(box);
    }
    if (s.releasedAt) card.append(el('p', 'why', 'Last released from a terminal ' + ago(s.releasedAt) + '. Newer facts arm it again.'));
    for (const p of s.problems) card.append(el('p', 'problem', 'Could not read: ' + p));
    if (s.armed || s.cautious) {
      const r = el('p', 'release');
      if (s.release === 'os') kids(r, document.createTextNode('Only you can release it: the Shield opens a system prompt on this computer (Touch ID or your login password) for each held call, and one verification releases that one call only. Nothing is released from a terminal or from this page.'));
      else kids(r, document.createTextNode('Only you can release it: run '), el('code', null, 'exorcist approve session ' + s.key), document.createTextNode(' in your own terminal. It asks you to confirm. A release given in one server\'s prompt counts for that server only.'));
      card.append(r);
    }
    return card;
  }
  function renderSessions(list) {
    $('sessions').replaceChildren(...list.map(sessionCard));
    $('sessions').hidden = list.length === 0;
    $('sessions-empty').hidden = list.length > 0;
    $('sessions-count').textContent = String(list.length);
  }

  function renderShields(list) {
    const ul = $('shields');
    ul.replaceChildren(...list.map((s) => {
      const li = el('li', 'shield');
      const st = s.running ? badge('allowed', 'circle', 'RUNNING') : badge('calm', 'ring', 'EXITED');
      if (!s.running) st.className = 'badge';
      const meta = [s.mode === 'monitor' ? 'monitor mode' : 'enforce', 'Session Guard ' + s.guard, s.remote ? 'remote' : 'local', 'pid ' + s.pid, s.session ? 'session ' + s.session : null, 'seen ' + ago(s.lastSeen)].filter(Boolean).join(' · ');
      kids(li, st, el('span', 'nm', s.server), el('span', 'meta', meta));
      return li;
    }));
    ul.hidden = list.length === 0;
    $('shields-empty').hidden = list.length > 0;
    const n = list.filter((s) => s.running).length;
    $('shields-count').textContent = n + ' running';
    $('n-shields').textContent = n;
  }

  // The label is the signal; the colour class only adds to it.
  function renderChain(c, head) {
    const b = $('chain-badge');
    let cls = 'chain-none'; let shapeKind = 'ring'; let label = 'not chained';
    if (c && c.status === 'intact') { cls = 'calm'; shapeKind = 'circle'; label = 'intact'; }
    else if (c && c.status === 'broken') { cls = 'critical'; shapeKind = 'octagon'; label = 'broken at event ' + c.atSeq; }
    b.className = 'badge ' + cls;
    b.replaceChildren(shape(shapeKind), document.createTextNode(label));
    $('chain-head').textContent = head ? 'event ' + head.seq + ', head hash ' + head.hash : 'no head hash yet';
    $('chain-why').textContent = c && c.status === 'broken' ? ' ' + String(c.detail || c.reason) : '';
  }

  const RELEASE_TEXT = {
    terminal: 'a held session is released only by running exorcist approve session <key> in your own terminal.',
    os: 'a held session is released only in the system prompt on this computer (Touch ID or your login password), never from a terminal command or from this page.',
    mixed: 'a held session is released in the system prompt (Touch ID or your login password) for Shields set to sessionRelease os, and by running exorcist approve session <key> in your own terminal for the others.',
  };
  let state = null;
  function renderState(s) {
    state = s;
    renderStats(s.counts);
    renderSessions(s.sessions);
    renderShields(s.shields);
    $('where').textContent = s.stateDir;
    $('release-how').textContent = RELEASE_TEXT[s.release] || RELEASE_TEXT.terminal;
    renderChain(s.chain, s.chainHead);
    $('skipped').textContent = s.skipped > 0 ? ' · ' + s.skipped + ' damaged log line' + (s.skipped === 1 ? '' : 's') + ' skipped' : '';
  }

  // Announce new decisions to screen readers, at most every 2 seconds.
  let pending = [];
  let timer = null;
  function announce(events) {
    pending.push(...events.filter((e) => e.kind === 'call' || e.kind === 'result'));
    if (timer || pending.length === 0) return;
    timer = setTimeout(() => {
      timer = null;
      const list = pending; pending = [];
      if (list.length === 0) return;
      const words = (e) => (DECISION[e.decision] || DECISION.blocked).label.toLowerCase() + ': ' + e.tool + ' on ' + e.server + (e.ruleId ? ' (' + e.ruleId + ')' : '');
      $('announce').textContent = list.length === 1 ? words(list[0]) : list.length + ' new tool calls. Latest ' + words(list[list.length - 1]);
    }, 2000);
  }

  for (const b of document.querySelectorAll('[data-filter]')) {
    b.addEventListener('click', () => {
      filter = b.dataset.filter;
      for (const o of document.querySelectorAll('[data-filter]')) o.setAttribute('aria-pressed', o === b ? 'true' : 'false');
      for (const li of $('feed').children) {
        const e = { decision: li.dataset.decision };
        li.hidden = !FILTERS[filter](e);
      }
      updateEmpty();
    });
  }

  function setLive(live) {
    const c = $('conn');
    c.dataset.live = live ? 'true' : 'false';
    $('conn-text').textContent = live ? 'LIVE' : 'RECONNECTING';
  }

  setInterval(() => {
    $('clock').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
    if (state) { renderSessions(state.sessions); renderShields(state.shields); }
  }, 15000);
  $('clock').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });

  const es = new EventSource(base + 'api/stream');
  es.addEventListener('hello', (m) => {
    const d = JSON.parse(m.data);
    alerts = d.events.filter((e) => e.kind === 'alert');
    renderFeed(d.events);
    renderAlerts();
    renderState(d.state);
    setLive(true);
    document.body.dataset.ready = 'true';
  });
  es.addEventListener('events', (m) => {
    const list = JSON.parse(m.data);
    addToFeed(list);
    const fresh = list.filter((e) => e.kind === 'alert');
    if (fresh.length) { alerts = alerts.concat(fresh).slice(-MAX_ALERTS); renderAlerts(); }
    announce(list);
  });
  es.addEventListener('state', (m) => renderState(JSON.parse(m.data)));
  es.addEventListener('open', () => setLive(true));
  es.addEventListener('error', () => setLive(false));
})();
`;

const stat = (id: string, cls: string, shapeKind: string, label: string): string =>
  `<li class="win stat"><span class="l"><span class="badge ${cls}"><span class="shape ${shapeKind}" aria-hidden="true"></span>${label}</span></span><span class="n" id="${id}">0</span></li>`;

/** The page. `nonce` must be fresh per response and match the CSP header. No data is put in the HTML. */
export function consolePage(nonce: string): string {
  if (!/^[A-Za-z0-9+/=_-]{16,64}$/.test(nonce)) throw new Error('bad nonce');
  const script = SCRIPT.replace('__RULES__', JSON.stringify(RULE_NAMES).replace(/</g, '\\u003c'));
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Shield Console · Exorcist 98</title>
<link rel="icon" href="data:,">
<style nonce="${nonce}">${CSS}</style>
</head>
<body>
<a class="skip" href="#activity">Skip to tool calls</a>
<main class="desk">
  <header class="win">
    <div class="titlebar on-dark">${GHOST}<h1>Exorcist 98 · Real-Time Shield Console</h1><span class="chrome" aria-hidden="true"><span></span><span></span><span></span></span></div>
    <div class="body head-body">
      <p class="lede">What the Shield is doing right now with your agent's MCP tool calls: allowed, held or blocked, by which rule, on which server, and what the Session Guard has seen.</p>
      <span class="conn" id="conn" data-live="false" role="status"><span class="dot" aria-hidden="true"></span><span id="conn-text">CONNECTING</span></span>
      <div class="readonly" role="note"><strong>Read-only view.</strong><span>Nothing on this page can approve, allow or release anything. Calls held for a host are answered in your agent's approval prompt; <span id="release-how">a held session is released only by running exorcist approve session &lt;key&gt; in your own terminal.</span></span></div>
      <p class="where">State folder: <span class="mono" id="where"></span><span id="skipped"></span></p>
      <p class="where" id="chain">Event log chain: <span id="chain-badge" class="badge chain-none" role="status" aria-label="Event log chain status"><span class="shape ring" aria-hidden="true"></span>not chained</span> <span class="mono" id="chain-head">no head hash yet</span><span id="chain-why"></span></p>
    </div>
  </header>

  <section aria-labelledby="totals-h">
    <h2 id="totals-h" class="sr-only">Totals since the log began</h2>
    <ul class="stats">
      ${stat('n-allowed', 'allowed', 'circle', 'Allowed')}
      ${stat('n-held', 'held', 'diamond', 'Held')}
      ${stat('n-blocked', 'blocked', 'octagon', 'Blocked')}
      ${stat('n-withheld', 'withheld', 'triangle', 'Results withheld')}
      ${stat('n-alerts', 'high', 'triangle', 'Alerts')}
      ${stat('n-shields', 'calm', 'circle', 'Shields running')}
    </ul>
  </section>

  <div class="grid">
    <section class="win" id="activity" aria-labelledby="activity-h" tabindex="-1">
      <div class="titlebar on-dark"><h2 id="activity-h">Tool calls</h2><span class="count" id="feed-count">0 shown</span></div>
      <div class="body">
        <div class="toolbar" role="group" aria-label="Show tool calls">
          <span class="label" aria-hidden="true">Show:</span>
          <button type="button" class="btn" data-filter="all" aria-pressed="true">All</button>
          <button type="button" class="btn" data-filter="blocked" aria-pressed="false">Blocked</button>
          <button type="button" class="btn" data-filter="held" aria-pressed="false">Held</button>
          <button type="button" class="btn" data-filter="allowed" aria-pressed="false">Allowed</button>
        </div>
        <div class="inset">
          <ol class="feed" id="feed" aria-label="Tool calls, newest first" tabindex="0"></ol>
          <div class="empty" id="feed-empty"><strong>All quiet. No spirits stirring.</strong>No tool calls yet. Wrap your MCP servers with <code>exorcist wrap &lt;mcp.json&gt;</code> and use your agent; every call through a Shield that uses this state folder shows up here.</div>
          <div class="empty" id="feed-empty-filtered" hidden>No tool calls match this filter.</div>
        </div>
      </div>
    </section>

    <div class="side">
      <section class="win" aria-labelledby="sessions-h">
        <div class="titlebar on-dark"><h2 id="sessions-h">Session Guard (EX-027)</h2><span class="count" id="sessions-count">0</span></div>
        <div class="body">
          <div class="inset" id="sessions"></div>
          <p class="empty inset" id="sessions-empty">No live session. Facts last 2 hours after they happen.</p>
        </div>
      </section>
      <section class="win" aria-labelledby="shields-h">
        <div class="titlebar on-dark"><h2 id="shields-h">Shields</h2><span class="count" id="shields-count">0 running</span></div>
        <div class="body">
          <ul class="inset plain" id="shields"></ul>
          <p class="empty inset" id="shields-empty">No Shield has started with this state folder since the log began.</p>
        </div>
      </section>
      <section class="win" aria-labelledby="alerts-h">
        <div class="titlebar on-dark"><h2 id="alerts-h">Alerts</h2></div>
        <div class="body">
          <ul class="inset alerts" id="alerts" aria-label="Alerts, newest first" tabindex="0"></ul>
          <p class="empty inset" id="alerts-empty">No alerts.</p>
        </div>
      </section>
    </div>
  </div>
</main>
<footer class="taskbar">
  <span class="start">${GHOST}Exorcist 98</span>
  <span class="grow">Shield Console · read-only · this machine only (127.0.0.1)</span>
  <span class="clock" id="clock"></span>
</footer>
<div class="sr-only" id="announce" aria-live="polite" aria-atomic="true"></div>
<script nonce="${nonce}">${script}</script>
</body>
</html>
`;
}
