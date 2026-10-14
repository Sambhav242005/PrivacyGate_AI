// demo-record.cjs — Phase 3: polished demo recording (1280x720, headless, video).
// Usage: node e2e/demo-record.cjs
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const MOCK_WALLET = '0x1111111111111111111111111111111111111111';
const BASE = 'http://127.0.0.1:3000';
const VID_DIR = path.join(__dirname, '.vid');
const OUT = path.join(__dirname, '..', '..', '..', 'docs', 'results', 'demo-privacygate.webm');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const OVERLAY_JS = () => {
  if (document.getElementById('demo-cursor')) return;
  const c = document.createElement('div');
  c.id = 'demo-cursor';
  c.innerHTML = `<svg width="26" height="26" viewBox="0 0 24 24"><path d="M5 3l14 7-6.5 1.5L9 18z" fill="#ffd60a" stroke="#111" stroke-width="1.5"/></svg>`;
  c.style.cssText = 'position:fixed;left:0;top:0;z-index:99999;pointer-events:none;transition:left .12s linear,top .12s linear;';
  document.body.appendChild(c);
  document.addEventListener('mousemove', (e) => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; });
  const bar = document.createElement('div');
  bar.id = 'demo-sub';
  bar.style.cssText = 'position:fixed;left:50%;transform:translateX(-50%);bottom:18px;z-index:99999;background:rgba(10,10,10,.82);color:#fff;font:600 20px/1.3 system-ui,sans-serif;padding:10px 22px;border-radius:10px;pointer-events:none;max-width:90vw;text-align:center;';
  document.body.appendChild(bar);
};
async function subtitle(page, t) {
  if (t.length >= 60) throw new Error(`subtitle too long (${t.length}): ${t}`);
  await page.evaluate((x) => { const b = document.getElementById('demo-sub'); if (b) b.textContent = x; }, t);
  console.log('SUB:', t);
}
async function inject(page) { await page.evaluate(OVERLAY_JS).catch(() => {}); }
async function goto(page, route, sub) {
  await page.goto(BASE + route, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1200); // hydration
  await inject(page);
  await subtitle(page, sub);
  await page.waitForTimeout(3000); // pacing: 3s post-nav
}
async function moveAndClick(page, locator) {
  const box = await locator.boundingBox();
  if (!box) throw new Error('moveAndClick: no bounding box');
  const x = box.x + box.width / 2, y = box.y + box.height / 2;
  const steps = 12;
  for (let i = 1; i <= steps; i++) {
    const px = (x * i) / steps, py = (y * i) / steps;
    await page.mouse.move(px, py);
    await sleep(25);
  }
  await locator.scrollIntoViewIfNeeded().catch(() => {});
  await page.mouse.click(x, y);
  await page.waitForTimeout(2000); // pacing: 2s post-click
}
async function typeSlowly(page, locator, text) {
  await locator.click().catch(() => {});
  await locator.fill('');
  for (const ch of text) { await locator.pressSequentially(ch, { delay: 35 }); }
  await page.waitForTimeout(800);
}

(async () => {
  fs.mkdirSync(VID_DIR, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 720 }, recordVideo: { dir: VID_DIR, size: { width: 1280, height: 720 } } });
  const page = await ctx.newPage();
  await page.addInitScript((addr) => {
    window.ethereum = { request: async ({ method }) => {
      if (method === 'eth_requestAccounts') return [addr];
      if (method === 'personal_sign') return '0x' + 'ab'.repeat(32);
      if (method === 'eth_sendTransaction') return '0x' + 'cd'.repeat(32);
      throw new Error(`unsupported method ${method}`);
    } };
  }, MOCK_WALLET);
  await page.route('**/v1/auth/challenge', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ challenge_id: 'stub', message_to_sign: 'stub', expires_at: new Date().toISOString() }) }));
  await page.route('**/v1/auth/verify', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ wallet_address: MOCK_WALLET, expires_at: new Date().toISOString(), csrf_token: 'stub' }) }));

  // 1) home entry
  await goto(page, '/', 'Step 1 - Home: owner vs subscriber entry');
  await moveAndClick(page, page.getByRole('link', { name: /subscriber insights/i }));
  await page.goBack({ waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1200); await inject(page);
  await subtitle(page, 'Step 1 - Home: owner vs subscriber entry');
  await page.waitForTimeout(2000);

  // 2) login (mock wallet, no real extension)
  await goto(page, '/login', 'Step 2 - Login: mock wallet, no extension');
  const btn = page.getByRole('button', { name: /connect wallet and sign in/i });
  for (let i = 0; i < 3; i++) {
    await moveAndClick(page, btn).catch(() => {});
    const ok = await page.getByText(/0x11111111/i).first().waitFor({ state: 'visible', timeout: 4000 }).then(() => true).catch(() => false);
    if (ok) break;
  }
  await subtitle(page, 'Step 2 - Login: signed in as mock owner');
  await page.waitForTimeout(4000); // pacing: 4s post-login

  // 3) owner dashboard pan
  await goto(page, '/dashboard', 'Step 3 - Owner dashboard: full telemetry');
  for (const sel of ['text=Device enrollment', 'text=Detailed telemetry', 'text=Policy draft']) {
    await page.locator(sel).first().scrollIntoViewIfNeeded().catch(() => {});
    await page.mouse.wheel(0, 300).catch(() => {});
    await page.waitForTimeout(1500);
  }
  await page.locator('text=Wallet login').first().scrollIntoViewIfNeeded().catch(() => {});
  await page.waitForTimeout(1500);

  // 4) subscriber insights (ciphertext only, no raw telemetry)
  await goto(page, '/insights', 'Step 4 - Insights: ciphertext only, no raw data');
  const html = await page.content();
  for (const bad of ['temp_c', 'vibration_mm_s']) {
    if (html.includes(bad)) throw new Error(`RECORD-FAIL: insights leaks "${bad}"`);
  }
  await moveAndClick(page, page.getByRole('button', { name: 'Refresh' }));
  console.log('ok: no raw telemetry on insights');

  // 5) api-docs explorer
  await goto(page, '/api-docs', 'Step 5 - API explorer: live gateway schema');
  await typeSlowly(page, page.getByLabel('Filter endpoints'), 'insights');
  await moveAndClick(page, page.getByRole('button', { name: /GET.*v1\/insights/i }).first());
  await subtitle(page, 'Step 5 - API explorer: typed endpoint detail');
  await page.waitForTimeout(2000);
  await page.getByLabel('Filter endpoints').fill('');
  await page.waitForTimeout(1000);

  // 6) result state
  await goto(page, '/', 'Step 6 - Done: owner detail vs encrypted insight');
  await page.waitForTimeout(3000); // pacing: 3s final

  const vidPath = await page.video().path();
  await ctx.close();
  await browser.close();
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.copyFileSync(vidPath, OUT);
  const size = fs.statSync(OUT).size;
  console.log(`VIDEO: ${vidPath} -> ${OUT} (${size} bytes)`);
  if (size < 50000) throw new Error(`RECORD-FAIL: video suspiciously small (${size} bytes)`);
  console.log('RECORD PASS');
})().catch((e) => { console.error(e.message); process.exit(1); });
