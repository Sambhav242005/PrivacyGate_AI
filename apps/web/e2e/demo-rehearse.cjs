// demo-rehearse.cjs — Phase 2: selector rehearsal. Usage: node e2e/demo-rehearse.cjs --rehearse
const { chromium } = require('playwright');
const MOCK_WALLET = '0x1111111111111111111111111111111111111111';
const BASE = 'http://127.0.0.1:3000';

async function dumpVisible(page) {
  return page.evaluate(() => {
    const out = [];
    document.querySelectorAll('a,button,input,select,textarea,[role="button"],summary,h1,h2').forEach(el => {
      const cs = getComputedStyle(el);
      const r = el.getBoundingClientRect();
      if (cs.display === 'none' || cs.visibility === 'hidden' || r.width === 0 || r.height === 0) return;
      out.push(`${el.tagName.toLowerCase()}[aria=${el.getAttribute('aria-label') || ''}][ph=${el.getAttribute('placeholder') || ''}] "${(el.innerText || el.textContent || '').trim().slice(0, 60)}"`);
    });
    return out.join('\n');
  });
}

async function ensureVisible(page, locator, name) {
  try {
    await locator.waitFor({ state: 'visible', timeout: 10000 });
  } catch (e) {
    const dump = await dumpVisible(page);
    throw new Error(`REHEARSE-FAIL: "${name}" not visible on ${page.url()}\n--- visible elements ---\n${dump}\n--- end ---`);
  }
  console.log(`ok: ${name}`);
}

(async () => {
  const rehearse = process.argv.includes('--rehearse');
  console.log(`demo-rehearse ${rehearse ? '(rehearse mode)' : ''}`);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  let cur = 'home';
  const errors = [];
  page.on('console', m => { if (m.type() === 'error') errors.push(`[${cur}] ${m.text()}`); });
  page.on('pageerror', e => errors.push(`[${cur}] ${String(e)}`));
  page.on('requestfailed', r => errors.push(`[${cur}] REQFAIL ${r.url()} ${r.failure()?.errorText || ''}`));
  let step = 0;
  const stepOk = (s) => console.log(`STEP ${++step} PASS: ${s}`);

  // 1) home entry
  cur = 'home';
  await page.goto(BASE + '/', { waitUntil: 'domcontentloaded' });
  await ensureVisible(page, page.getByRole('heading', { name: /privacygate/i }), 'home heading');
  await ensureVisible(page, page.getByRole('link', { name: /owner dashboard/i }), 'home owner link');
  await ensureVisible(page, page.getByRole('link', { name: /subscriber insights/i }), 'home subscriber link');
  stepOk('home entry');

  // 2) login (mock-wallet stub like live.spec.ts — no real wallet)
  cur = 'login';
  await page.addInitScript((addr) => {
    window.ethereum = {
      request: async ({ method }) => {
        if (method === 'eth_requestAccounts') return [addr];
        if (method === 'personal_sign') return '0x' + 'ab'.repeat(32);
        if (method === 'eth_sendTransaction') return '0x' + 'cd'.repeat(32);
        throw new Error(`unsupported method ${method}`);
      },
    };
  }, MOCK_WALLET);
  await page.route('**/v1/auth/challenge', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ challenge_id: 'stub-challenge', message_to_sign: 'stub message', expires_at: new Date().toISOString() }) });
  });
  await page.route('**/v1/auth/verify', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ wallet_address: MOCK_WALLET, expires_at: new Date().toISOString(), csrf_token: 'stub' }) });
  });
  await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(2500); // hydration: React onClick attaches after load
  await ensureVisible(page, page.getByRole('heading', { name: /owner.*login/i }), 'login heading');
  await ensureVisible(page, page.getByRole('button', { name: /connect wallet and sign in/i }), 'login button');
  const addrRe = new RegExp(MOCK_WALLET.slice(0, 10), 'i');
  let logged = false;
  for (let i = 0; i < 3 && !logged; i++) {
    await page.getByRole('button', { name: /connect wallet and sign in/i }).click().catch(() => {});
    logged = await page.getByText(addrRe).first().waitFor({ state: 'visible', timeout: 6000 }).then(() => true).catch(() => false);
  }
  if (!logged) {
    const dump = await dumpVisible(page);
    throw new Error(`REHEARSE-FAIL: "login wallet addr" not visible after 3 clicks\n${dump}`);
  }
  console.log('ok: login wallet addr');
  stepOk('login mock-wallet');

  // 3) owner dashboard pan
  cur = 'dashboard';
  await page.goto(BASE + '/dashboard', { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1500);
  await ensureVisible(page, page.getByRole('heading', { name: /owner.*dashboard/i }), 'dashboard heading');
  await ensureVisible(page, page.getByRole('button', { name: /connect wallet/i }).first(), 'dashboard connect btn');
  await ensureVisible(page, page.getByLabel('Resource ID'), 'dashboard resource input');
  await ensureVisible(page, page.getByRole('button', { name: /load telemetry/i }), 'dashboard telemetry btn');
  await ensureVisible(page, page.getByRole('button', { name: /create policy draft/i }), 'dashboard draft btn');
  await ensureVisible(page, page.getByRole('button', { name: /revoke grant/i }), 'dashboard revoke btn');
  // pan: scroll through sections
  for (const sel of ['text=Device enrollment', 'text=Detailed telemetry', 'text=Policy draft']) {
    const el = page.locator(sel).first();
    await el.scrollIntoViewIfNeeded().catch(() => {});
    await page.waitForTimeout(300);
  }
  stepOk('owner dashboard pan');

  // 4) subscriber insights (assert no raw telemetry)
  cur = 'insights';
  await page.goto(BASE + '/insights', { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1500);
  await ensureVisible(page, page.getByRole('heading', { name: /subscriber.*insights/i }), 'insights heading');
  await ensureVisible(page, page.getByRole('button', { name: /connect wallet/i }).first(), 'insights connect btn');
  await ensureVisible(page, page.getByLabel('Resource ID'), 'insights resource input');
  await ensureVisible(page, page.getByRole('button', { name: /decrypt all/i }), 'insights decrypt-all btn');
  const html = await page.content();
  for (const bad of ['temp_c', 'vibration_mm_s']) {
    if (html.includes(bad)) throw new Error(`REHEARSE-FAIL: insights leaks raw field "${bad}"`);
  }
  console.log('ok: insights no raw telemetry');
  stepOk('subscriber insights no-leak');

  // 5) api-docs explorer
  cur = 'api-docs';
  await page.goto(BASE + '/api-docs', { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(2000);
  await ensureVisible(page, page.getByLabel('Filter endpoints'), 'api-docs filter');
  await ensureVisible(page, page.getByRole('button', { name: /GET.*v1\/insights/i }).first(), 'api-docs insights endpoint');
  // exercise filter + endpoint select (discovered selectors only)
  await page.getByLabel('Filter endpoints').fill('insights');
  await page.waitForTimeout(500);
  await ensureVisible(page, page.getByRole('button', { name: /GET.*v1\/insights/i }).first(), 'api-docs filtered insights btn');
  await page.getByRole('button', { name: /GET.*v1\/insights/i }).first().click();
  await page.waitForTimeout(500);
  await page.getByLabel('Filter endpoints').fill('');
  await page.waitForTimeout(500);
  stepOk('api-docs explorer');

  // 6) result state (api-docs falls back to snapshot when gateway omits
  // CORS on /openapi.json — allowlist only that known environmental failure)
  cur = 'result';
  const real = errors.filter((e) => !(
    e.startsWith('[api-docs]') && (e.includes('openapi.json') || e.includes('ERR_FAILED') || e.includes('Failed to load resource'))
  ));
  if (real.length) throw new Error(`REHEARSE-FAIL: console errors:\n${real.join('\n')}`);
  if (errors.length) console.log(`note: ignored ${errors.length} known api-docs/openapi.json CORS fallback error(s) (snapshot used)`);
  console.log('ok: zero unexpected console errors');
  stepOk('result state clean');

  console.log(`REHEARSAL PASS: all ${step} steps`);
  await browser.close();
})().catch(e => { console.error(e.message); process.exit(1); });
