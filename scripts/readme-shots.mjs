// Capture the README screenshots from a running web app.
//   BASE=http://localhost:3098 node scripts/readme-shots.mjs   (writes docs/media/*.png)
import { chromium } from 'playwright-core';
import { existsSync } from 'node:fs';
const BASE = process.env.BASE ?? 'http://localhost:3000';
const OUT = process.env.OUT ?? 'docs/media';
const CHROME = process.env.CHROME_PATH ?? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome'].find((p) => existsSync(p));
const browser = await chromium.launch({ executablePath: CHROME, headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1.25, reducedMotion: 'reduce' });
const page = await ctx.newPage();
const shot = async (name, el) => { await page.waitForTimeout(400); await (el ?? page).screenshot({ path: `${OUT}/${name}.png` }); console.log('wrote', name); };

await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
await page.waitForTimeout(1800);
await shot('home');

await page.goto(`${BASE}/?demo=haunted`, { waitUntil: 'networkidle' });
await page.getByText('POSSESSED').first().waitFor({ timeout: 20000 });
await shot('results');

// Open EX-001 findings until one shows the Ouija board (a decodable hidden message).
const list = page.getByRole('list', { name: 'Threats found, worst first' });
const detail = page.getByRole('dialog', { name: 'Threat Details' });
const rows = list.getByRole('button').filter({ hasText: 'EX-001' });
for (let i = 0; i < (await rows.count()); i++) {
  await rows.nth(i).click();
  const board = detail.getByRole('region', { name: 'Ouija board' });
  if (await board.count()) { await board.scrollIntoViewIfNeeded(); break; }
}
await shot('ouija-board', detail);

await page.goto(`${BASE}/?open=map`, { waitUntil: 'networkidle' });
const results = page.getByRole('dialog', { name: /Threats Found/ });
await results.getByText('POSSESSED').first().waitFor({ timeout: 20000 });
const toggle = results.getByRole('button', { name: /Haunted House Map/ }).or(results.getByRole('tab', { name: /Haunted House Map/ })).or(results.getByRole('radio', { name: /Haunted House Map/ }));
if (await toggle.count()) await toggle.first().click();
const mapEl = results.locator('svg').filter({ hasText: /Vault of Secrets|Escape Tunnel/ }).first();
await mapEl.waitFor({ timeout: 10000 });
await mapEl.scrollIntoViewIfNeeded();
await shot('haunted-house-map', results);

await page.goto(`${BASE}/?demo=rug-pull`, { waitUntil: 'networkidle' });
const lab = page.getByRole('dialog', { name: /Possession Lab/ });
await lab.getByText('EXORCISED').first().waitFor({ timeout: 30000 });
await shot('possession-lab', lab);

const tab = lab.getByRole('tab', { name: 'Bring your own attack' });
await tab.click();
await lab.getByRole('button', { name: /^Booby-trapped web page/ }).click();
await lab.locator('.byoa-verdict').waitFor({ timeout: 15000 });
await lab.locator('.byoa-verdict').scrollIntoViewIfNeeded();
await shot('bring-your-own-attack', lab);

await page.goto(`${BASE}/?open=field`, { waitUntil: 'networkidle' });
const field = page.getByRole('dialog', { name: /Field Report/ });
await field.waitFor();
await shot('field-report', field);

await page.goto(`${BASE}/how-kiro`, { waitUntil: 'networkidle' });
await shot('how-kiro');

await page.setViewportSize({ width: 390, height: 844 });
await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
await page.waitForTimeout(1800);
await shot('mobile');
await browser.close();
