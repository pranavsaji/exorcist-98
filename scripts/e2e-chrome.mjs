// End-to-end check of the web app in a real Chrome, plus an axe accessibility scan.
//
//   pnpm --filter @exorcist-98/web build
//   pnpm --filter @exorcist-98/web exec next start -p 3113 &
//   E2E_BASE=http://localhost:3113 pnpm e2e
//
// Environment:
//   E2E_BASE     app URL (default http://localhost:3000)
//   CHROME_PATH  Chrome executable (default: found in the usual install path)
//   E2E_OUT      output folder for screenshots and results.json (default e2e-output)
//
// The GitHub steps clone public repos (octocat/Hello-World, expressjs/express),
// so they need network access. Exit code is 1 if any step fails.
import { chromium } from 'playwright-core';
import { existsSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

const BASE = process.env.E2E_BASE ?? 'http://localhost:3000';
// W-017: CHROME_PATH, else the usual install path for this platform.
const CHROME_CANDIDATES = {
  darwin: ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Chromium.app/Contents/MacOS/Chromium'],
  linux: ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser'],
  win32: ['C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'],
};
const CHROME = process.env.CHROME_PATH ?? (CHROME_CANDIDATES[process.platform] ?? []).find((p) => existsSync(p));
if (!CHROME) {
  console.error('No Chrome found. Install Chrome or set CHROME_PATH to its executable.');
  process.exit(2);
}
const OUT = process.env.E2E_OUT ?? 'e2e-output';
const SHOTS = join(OUT, 'shots');
mkdirSync(SHOTS, { recursive: true });
const axeSource = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8');

const results = [];
const consoleErrors = [];
async function step(name, fn) {
  try {
    const detail = await fn();
    results.push({ name, ok: true, detail: detail ?? '' });
  } catch (e) {
    results.push({ name, ok: false, detail: String(e.message ?? e).split('\n')[0].slice(0, 300) });
  }
}

const browser = await chromium.launch({ executablePath: CHROME, headless: true });
const ctx = await browser.newContext({ viewport: { width: 1366, height: 768 } });
const page = await ctx.newPage();
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 200)); });
page.on('pageerror', (e) => consoleErrors.push('pageerror: ' + String(e.message).slice(0, 200)));
page.on('requestfailed', (r) => consoleErrors.push('requestfailed: ' + r.url() + ' ' + (r.failure()?.errorText ?? '')));
page.on('response', (r) => { if (r.status() >= 400) consoleErrors.push(`HTTP ${r.status()} ${r.url()}`); });

async function axe(label) {
  await page.addScriptTag({ content: axeSource });
  const r = await page.evaluate(async () => {
    const res = await window.axe.run(document, { resultTypes: ['violations'] });
    return res.violations.map((v) => ({
      id: v.id, impact: v.impact, nodes: v.nodes.length,
      sample: v.nodes[0]?.target?.join(' ').slice(0, 120),
      msg: (v.nodes[0]?.any?.[0]?.message ?? v.help).slice(0, 160),
    }));
  });
  return { label, violations: r };
}

const axeReports = [];

await step('home loads with heading, taskbar and four desktop icons', async () => {
  await page.goto(BASE, { waitUntil: 'networkidle' });
  await page.waitForSelector('h1');
  const n = await page.locator('main button, main a').filter({ hasText: /Full System Scan|Scan the Haunted Repo|Virus Definitions|About/ }).count();
  const taskbar = await page.locator('nav[aria-label="Taskbar"]').count();
  await page.screenshot({ path: `${SHOTS}/01-home.png` });
  if (!taskbar) throw new Error('no taskbar');
  return `icon-ish controls: ${n}`;
});

await step('axe scan: home (before scanning)', async () => {
  const r = await axe('home-initial');
  axeReports.push(r);
  return `${r.violations.length} violation types`;
});

await step('validation: bad URL shows an alert and does not scan', async () => {
  await page.getByLabel('GitHub repository to scan').fill('https://gitlab.com/o/r');
  await page.getByRole('button', { name: 'Scan', exact: true }).click();
  const alert = await page.locator('p[role=alert]').innerText();
  if (!/github\.com/.test(alert)) throw new Error('alert text: ' + alert);
  return alert;
});

await step('validation: typing clears the error', async () => {
  await page.getByLabel('GitHub repository to scan').fill('https://github.com/o/r');
  if (await page.locator('p[role=alert]').count()) throw new Error('error still visible after typing');
  await page.getByLabel('GitHub repository to scan').fill('nope');
  await page.getByRole('button', { name: 'Scan', exact: true }).click();
  if (!(await page.locator('p[role=alert]').count())) throw new Error('error did not come back');
  return 'cleared on input, returns on bad submit';
});

await step('Haunted Repo scan completes and fills the log', async () => {
  await page.getByRole('button', { name: 'Scan the Haunted Repo' }).first().click();
  await page.getByText('Scan complete.').first().waitFor({ timeout: 20000 });
  const log = await page.getByRole('log', { name: 'Scan log' }).innerText();
  if (await page.locator('p[role=alert]').count()) throw new Error('stale URL error still showing after the scan');
  await page.screenshot({ path: `${SHOTS}/02-scanned.png` });
  const files = (log.match(/scanning EX-/g) || []).length;
  const threats = (log.match(/\[(CRITICAL|HIGH|MEDIUM|LOW)\]/g) || []).length;
  if (files < 20) throw new Error('only ' + files + ' files logged');
  return `${files} files, ${threats} threat lines in log`;
});

await step('results window lists threats worst first', async () => {
  const items = page.getByRole('list', { name: 'Threats found, worst first' }).getByRole('button');
  const n = await items.count();
  const labels = await items.evaluateAll((els) => els.map((e) => (e.querySelector('.sev')?.textContent || '').trim()));
  const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  for (let i = 1; i < labels.length; i++) if (rank[labels[i]] < rank[labels[i - 1]]) throw new Error('out of order at ' + i);
  const shapes = await page.locator('ul[aria-label="Threats found, worst first"] .sev svg[data-shape]').count();
  if (shapes !== n) throw new Error(`shapes ${shapes} != rows ${n}`);
  return `${n} rows, order ok, every row has a shape (${[...new Set(labels)].join(', ')})`;
});

await step('click an EX-001 result opens details with hidden characters revealed', async () => {
  const row = page.getByRole('list', { name: 'Threats found, worst first' }).getByRole('button').filter({ hasText: 'EX-001' }).first();
  await row.click();
  await page.getByRole('dialog', { name: 'Threat Details' }).waitFor();
  const dlg = page.getByRole('dialog', { name: 'Threat Details' });
  const heading = await dlg.getByRole('heading', { level: 3 }).innerText();
  const marks = await dlg.locator('mark.hit').allInnerTexts();
  await page.screenshot({ path: `${SHOTS}/03-detail.png` });
  if (heading !== 'This file hides instructions for your AI') throw new Error('heading: ' + heading);
  if (!marks.some((m) => /\[U\+[0-9A-F]{4,6}\]/.test(m))) throw new Error('no revealed marker in highlight: ' + JSON.stringify(marks));
  const text = await dlg.innerText();
  for (const need of ['Where it is', 'line', 'How to fix it', 'Technical details', 'OWASP', 'EX-001']) {
    if (!text.includes(need)) throw new Error('missing section text: ' + need);
  }
  return `heading ok, highlight=${JSON.stringify(marks.slice(0, 2))}`;
});

await step('every finding row opens a detail with a quoted span and a snippet line', async () => {
  const list = page.getByRole('list', { name: 'Threats found, worst first' });
  const n = await list.getByRole('button').count();
  let noHighlight = 0;
  const noHighlightRows = [];
  for (let i = 0; i < n; i++) {
    await list.getByRole('button').nth(i).click();
    const dlg = page.getByRole('dialog', { name: 'Threat Details' });
    const span = await dlg.getByText('Quoted span:').innerText();
    if (!span.trim()) throw new Error('row ' + i + ' has no quoted span');
    if ((await dlg.locator('mark.hit').count()) === 0) {
      noHighlight++;
      const row = await list.getByRole('button').nth(i).innerText();
      noHighlightRows.push(row.replace(/\n+/g, ' | ') + ' :: ' + span.trim());
    }
  }
  if (noHighlight > 0) throw new Error(`${noHighlight} of ${n} findings have no highlight: ${noHighlightRows.join(' ;; ')}`);
  return `${n} rows opened; all ${n} have a highlighted quoted span`;
});

await step('axe scan: home after scan (results + detail open)', async () => {
  const r = await axe('home-after-scan');
  axeReports.push(r);
  return `${r.violations.length} violation types`;
});

await step('keyboard: Tab moves focus and a visible focus ring is drawn', async () => {
  await page.reload({ waitUntil: 'networkidle' });
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  const info = await page.evaluate(() => {
    const el = document.activeElement;
    const cs = el ? getComputedStyle(el) : null;
    return { tag: el?.tagName, text: (el?.textContent || '').trim().slice(0, 40), outline: cs?.outlineStyle + ' ' + cs?.outlineWidth };
  });
  if (!info.tag || info.tag === 'BODY') throw new Error('focus stayed on body');
  await page.screenshot({ path: `${SHOTS}/04-focus.png` });
  return JSON.stringify(info);
});

await step('Escape closes the focused window', async () => {
  const dlg = page.getByRole('dialog', { name: /Full System Scan/ });
  await dlg.focus();
  await page.keyboard.press('Escape');
  await dlg.waitFor({ state: 'detached', timeout: 3000 });
  return 'scan window closed';
});

await step('desktop icon reopens it; Start menu opens, lists items, Escape closes', async () => {
  await page.locator('main').getByRole('button', { name: 'Full System Scan' }).click();
  await page.getByRole('dialog', { name: /Full System Scan/ }).waitFor();
  await page.getByRole('button', { name: /Start/ }).click();
  const items = await page.getByRole('menuitem').allInnerTexts();
  await page.screenshot({ path: `${SHOTS}/05-start.png` });
  await page.keyboard.press('Escape');
  const stillOpen = await page.getByRole('menu').count();
  if (stillOpen) throw new Error('menu did not close on Escape');
  return items.map((s) => s.trim()).join(' | ');
});

await step('minimize via window button, restore from taskbar', async () => {
  await page.getByRole('button', { name: /Minimize Exorcist 98/ }).click();
  const hidden = await page.getByRole('dialog', { name: /Full System Scan/ }).isHidden();
  if (!hidden) throw new Error('window still visible after minimize');
  await page.locator('nav[aria-label="Taskbar"]').getByRole('button', { name: /Full System Scan/ }).click();
  await page.getByRole('dialog', { name: /Full System Scan/ }).waitFor({ state: 'visible' });
  return 'minimized then restored';
});

await step('drag: moving the title bar moves the window', async () => {
  const dlg = page.getByRole('dialog', { name: /Full System Scan/ });
  const before = await dlg.boundingBox();
  const tb = dlg.locator('.titlebar');
  const b = await tb.boundingBox();
  await page.mouse.move(b.x + 150, b.y + 10);
  await page.mouse.down();
  await page.mouse.move(b.x + 250, b.y + 90, { steps: 8 });
  await page.mouse.up();
  const after = await dlg.boundingBox();
  const dx = Math.round(after.x - before.x), dy = Math.round(after.y - before.y);
  if (Math.abs(dx - 100) > 3 || Math.abs(dy - 80) > 3) throw new Error(`moved (${dx},${dy}), expected about (100,80)`);
  return `moved (${dx},${dy})`;
});

await step('keyboard: Alt+arrow keys move the focused window', async () => {
  const dlg = page.getByRole('dialog', { name: /Full System Scan/ });
  await dlg.focus();
  const before = await dlg.boundingBox();
  await page.keyboard.press('Alt+ArrowRight');
  await page.keyboard.press('Alt+ArrowDown');
  await page.keyboard.press('Alt+Shift+ArrowRight');
  const after = await dlg.boundingBox();
  const dx = Math.round(after.x - before.x), dy = Math.round(after.y - before.y);
  if (dx !== 80 || dy !== 20) throw new Error(`moved (${dx},${dy}), expected (80,20)`);
  return `moved (${dx},${dy})`;
});

await step('sound is muted by default, toggles, and the choice persists', async () => {
  const btn = page.locator('nav[aria-label="Taskbar"]').getByRole('button', { name: /Sound (off|on)/ });
  const first = await btn.getAttribute('aria-pressed');
  if (first !== 'false') throw new Error('sound was not muted by default: aria-pressed=' + first);
  await btn.click();
  if ((await btn.getAttribute('aria-pressed')) !== 'true') throw new Error('toggle did not turn sound on');
  await page.reload({ waitUntil: 'networkidle' });
  const again = page.locator('nav[aria-label="Taskbar"]').getByRole('button', { name: /Sound (off|on)/ });
  await page.waitForFunction(() => [...document.querySelectorAll('nav[aria-label="Taskbar"] button[aria-pressed="true"]')].some((b) => b.textContent?.includes('Sound on')));
  await again.click();
  if ((await again.getAttribute('aria-pressed')) !== 'false') throw new Error('toggle did not turn sound off');
  return 'muted by default; on; persisted across reload; off';
});

await step('reports: SARIF, Markdown, JSON and badge download from the results window', async () => {
  await page.getByRole('button', { name: 'Scan the Haunted Repo' }).first().click();
  await page.getByText('Scan complete.').first().waitFor({ timeout: 20000 });
  const got = [];
  for (const label of ['SARIF (code scanning)', 'Markdown (pull request)', 'JSON', 'README badge (SVG)']) {
    const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: label, exact: true }).click()]);
    const path = join(OUT, dl.suggestedFilename());
    await dl.saveAs(path);
    const body = readFileSync(path, 'utf8');
    if (label.startsWith('SARIF') && JSON.parse(body).version !== '2.1.0') throw new Error('bad SARIF');
    if (label.startsWith('README') && !body.includes('possessed')) throw new Error('badge does not say possessed');
    got.push(`${dl.suggestedFilename()} (${body.length} bytes)`);
  }
  await page.screenshot({ path: `${SHOTS}/09-reports.png` });
  return got.join(', ');
});

await step('product page loads, links back to the desktop, and passes axe', async () => {
  await page.goto(`${BASE}/product`, { waitUntil: 'networkidle' });
  const h1 = await page.locator('h1').innerText();
  if (!/virus/i.test(h1)) throw new Error('h1: ' + h1);
  if ((await page.locator('a[href="/"]').count()) === 0) throw new Error('no link back to the desktop');
  await page.screenshot({ path: `${SHOTS}/10-product.png`, fullPage: true });
  const r = await axe('product'); axeReports.push(r);
  await page.goto(BASE, { waitUntil: 'networkidle' });
  return `"${h1}", ${r.violations.length} axe violation types`;
});

await step('real GitHub scan through the UI (octocat/Hello-World)', async () => {
  await page.getByLabel('GitHub repository to scan').fill('https://github.com/octocat/Hello-World');
  await page.getByRole('button', { name: 'Scan', exact: true }).click();
  await page.getByText('Scan complete.').first().waitFor({ timeout: 60000 });
  const log = await page.getByRole('log', { name: 'Scan log' }).innerText();
  return log.split('\n').slice(-2).join(' / ');
});

await step('cancel: Cancel stops a larger scan', async () => {
  await page.getByLabel('GitHub repository to scan').fill('https://github.com/expressjs/express');
  await page.getByRole('button', { name: 'Scan', exact: true }).click();
  const cancel = page.getByRole('button', { name: 'Cancel', exact: true });
  await cancel.waitFor({ state: 'visible' });
  await page.waitForTimeout(150);
  if (await cancel.isDisabled()) {
    const txt = await page.getByRole('log', { name: 'Scan log' }).innerText();
    return 'scan had already finished before Cancel could be clicked: ' + txt.split('\n').slice(-1)[0];
  }
  await cancel.click();
  await page.getByText('Scan cancelled.').first().waitFor({ timeout: 5000 });
  return 'cancelled';
});

await step('reduced motion: the running progress bar does not animate', async () => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const name = await page.evaluate(() => {
    const d = document.createElement('div');
    d.className = 'progress-fill';
    d.setAttribute('data-state', 'running');
    document.body.appendChild(d);
    const v = getComputedStyle(d).animationName;
    d.remove();
    return v;
  });
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  const name2 = await page.evaluate(() => {
    const d = document.createElement('div');
    d.className = 'progress-fill';
    d.setAttribute('data-state', 'running');
    document.body.appendChild(d);
    const v = getComputedStyle(d).animationName;
    d.remove();
    return v;
  });
  if (name !== 'none') throw new Error('animation still on with reduced motion: ' + name);
  if (name2 === 'none') throw new Error('animation missing without reduced motion');
  return `reduce -> ${name}, normal -> ${name2}`;
});

await step('encyclopedia index lists every definition; EX-001 page shows markers', async () => {
  await page.goto(`${BASE}/encyclopedia`, { waitUntil: 'networkidle' });
  const links = await page.locator('a[href^="/encyclopedia/EX-"]').count();
  await page.screenshot({ path: `${SHOTS}/06-encyclopedia.png` });
  const r1 = await axe('encyclopedia-index'); axeReports.push(r1);
  await page.locator('a[href="/encyclopedia/EX-001"]').click();
  await page.waitForURL(/EX-001/);
  const pre = await page.locator('pre').innerText();
  await page.screenshot({ path: `${SHOTS}/07-encyclopedia-ex001.png` });
  const r2 = await axe('encyclopedia-ex001'); axeReports.push(r2);
  if (links < 13) throw new Error('links: ' + links);
  if (!/\[U\+200B\]/.test(pre) || !/\[U\+202E\]/.test(pre) || !/\[U\+E00/.test(pre)) throw new Error('markers missing');
  return `${links} links; markers present`;
});

await step('unknown encyclopedia id gives a 404 page', async () => {
  const r = await page.goto(`${BASE}/encyclopedia/EX-999`);
  if (r.status() !== 404) throw new Error('status ' + r.status());
  return '404';
});

await step('narrow screen (390x844): screenshot only, checks horizontal overflow', async () => {
  const m = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const p = await m.newPage();
  await p.goto(BASE, { waitUntil: 'networkidle' });
  await p.screenshot({ path: `${SHOTS}/08-mobile.png` });
  const o = await p.evaluate(() => {
    const w = document.querySelector('section[role=dialog]');
    const r = w?.getBoundingClientRect();
    return { win: r ? `${Math.round(r.left)}..${Math.round(r.right)}` : 'none', vw: innerWidth };
  });
  await m.close();
  const [l, r] = o.win.split('..').map(Number);
  if (l < 0 || r > o.vw) throw new Error('window does not fit: ' + JSON.stringify(o));
  return 'fits: ' + JSON.stringify(o);
});

await browser.close();
writeFileSync(join(OUT, 'results.json'), JSON.stringify({ results, consoleErrors, axeReports }, null, 2));
for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.ok ? '' : '\n      -> ' + r.detail}`);
const axeTotal = axeReports.reduce((n, a) => n + a.violations.length, 0);
console.log(`axe violation types: ${axeTotal}`);
const failed = results.filter((r) => !r.ok).length;
if (failed || axeTotal) process.exit(1);
