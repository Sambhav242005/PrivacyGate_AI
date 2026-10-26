'use strict';
const { chromium } = require('@playwright/test');
const fs = require('node:fs/promises');
const path = require('node:path');
const BASE = process.env.PG_WEB_URL || 'http://127.0.0.1:3001';
const OUTPUT = path.resolve(__dirname, '../../../docs/results/v2-fieldmap.json');
async function fields(page) {
  return page.evaluate(() => Array.from(document.querySelectorAll('input, select, textarea, button, a, [contenteditable]'))
    .filter(el => el.getClientRects().length)
    .map(el => ({tag: el.tagName, id: el.id, type: el.type || '', name: el.name || '',
      text: el.tagName === 'INPUT' ? '' : (el.textContent || '').trim().slice(0, 90),
      placeholder: el.getAttribute('placeholder') || '', required: !!el.required,
      options: el.tagName === 'SELECT' ? Array.from(el.options).map(o => ({value: o.value, text: o.text})) : undefined})));
}
(async () => {
  const browser = await chromium.launch({headless:true});
  const map = {};
  try {
    const credentials = JSON.parse(await fs.readFile(path.resolve(__dirname, '../../../var/v2/credentials.json'), 'utf8'));
    for (const role of ['owner', 'reader']) {
      const context = await browser.newContext({viewport:{width:1280,height:720}});
      const page = await context.newPage();
      await page.goto(BASE + '/login');
      await page.getByLabel('Username').waitFor();
      map['/login'] = await fields(page);
      const account = credentials.find(c => c.role === role);
      await page.getByLabel('Username').fill(account.username);
      await page.getByLabel('Password').fill(account.password);
      await page.getByRole('button', {name:'Sign in securely'}).click();
      await page.waitForURL(role === 'owner' ? '**/dashboard' : '**/insights');
      await page.getByText(`Signed in as ${account.username}`, {exact:true}).waitFor();
      if (role === 'owner') {
        await page.getByLabel('Equipment name').fill('Discovery synthetic compressor');
        await page.getByRole('button', {name:'Add device', exact:true}).click();
        await page.locator('#page-content [role="status"]').filter({hasText:'Registration receipt confirmed'}).waitFor();
      }
      map[role === 'owner' ? '/dashboard' : '/insights'] = await fields(page);
      await context.close();
    }
    const page = await browser.newPage();
    await page.goto(BASE);
    map['/'] = await fields(page);
    await fs.writeFile(OUTPUT, JSON.stringify({base_url:BASE,recorded_at:new Date().toISOString(),pages:map}, null, 2) + '\n');
    console.log('Discovery field map saved:', OUTPUT);
  } finally { await browser.close(); }
})().catch(error => {console.error('Discovery failed:', error.message);process.exitCode=1});
