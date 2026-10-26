'use strict';
// Native v2 discovery -> rehearsal -> recording. Credentials and backups stay ignored.
const { chromium, expect } = require('@playwright/test');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const ROOT = path.resolve(__dirname, '../../..');
const BASE = process.env.PG_WEB_URL || 'http://127.0.0.1:3000';
const RUNTIME = path.join(ROOT, 'var/v2');
const RESULT = path.join(ROOT, 'docs/results');
const REHEARSE = process.argv.includes('--rehearse');
const DISCOVER = process.argv.includes('--discover');
const BACKUP = path.join(RUNTIME, 'demo-reader2-backup.json');
const MANIFEST = path.join(RUNTIME, 'demo-rehearsal.json');
const VIDEO = path.join(RESULT, 'demo-privacygate-v2.webm');
let sensitiveValues = [];

async function pause(page, milliseconds) { await page.waitForTimeout(REHEARSE ? 100 : milliseconds); }
async function overlays(page) {
  await page.evaluate(() => {
    if (!document.getElementById('demo-cursor')) {
      const cursor = document.createElement('div'); cursor.id = 'demo-cursor';
      cursor.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24"><path d="M5 3L19 12L12 13L9 20L5 3Z" fill="white" stroke="black" stroke-width="1.5" stroke-linejoin="round"/></svg>';
      cursor.style.cssText = 'position:fixed;z-index:999999;pointer-events:none;width:24px;height:24px;left:0;top:0;filter:drop-shadow(1px 1px 2px #0006)';
      document.body.appendChild(cursor);
      document.addEventListener('mousemove', e => {cursor.style.left=e.clientX+'px';cursor.style.top=e.clientY+'px'});
    }
    if (!document.getElementById('demo-subtitle')) {
      const bar = document.createElement('div'); bar.id='demo-subtitle';
      bar.style.cssText='position:fixed;bottom:0;left:0;right:0;z-index:999998;text-align:center;padding:14px 24px;background:#111e;color:white;font:500 17px system-ui;pointer-events:none';
      document.body.appendChild(bar);
    }
  });
}
async function subtitle(page, text) {
  await overlays(page);
  await page.evaluate(t=>{document.getElementById('demo-subtitle').textContent=t},text);
  await pause(page,1500);
}
async function visible(locator, label) {
  try { await locator.waitFor({state:'visible',timeout:15000}); }
  catch (error) { throw new Error(`REHEARSAL FAIL: ${label}: ${error.message}`); }
  console.log('Selector verified:', label);
  return locator;
}
async function click(page, locator, label) {
  await visible(locator,label); await locator.scrollIntoViewIfNeeded();
  await pause(page,350); const box=await locator.boundingBox();
  if (!box) throw new Error(`No clickable box: ${label}`);
  await page.mouse.move(box.x+box.width/2,box.y+box.height/2,{steps:12});
  await pause(page,350); await locator.click(); await pause(page,1800);
}
async function type(page, locator, text, label) {
  await click(page,locator,label);await locator.fill('');
  await locator.pressSequentially(text,{delay:REHEARSE?0:30});await pause(page,500);
}
async function select(page, locator, value, label) {
  await visible(locator,label);await locator.scrollIntoViewIfNeeded();const box=await locator.boundingBox();
  await page.mouse.move(box.x+box.width/2,box.y+box.height/2,{steps:10});
  await locator.selectOption(value);await pause(page,1800);
}
async function goto(page,route) {await page.goto(BASE+route);await overlays(page);await pause(page,3000);}
async function signIn(page,account,step) {
  await goto(page,'/login');await subtitle(page,`Step ${step} - Sign in as ${account.username}`);
  await type(page,page.getByLabel('Username'),account.username,'username');
  await type(page,page.getByLabel('Password'),account.password,'masked password');
  await click(page,page.getByRole('button',{name:'Sign in securely',exact:true}),'sign in');
  await page.waitForURL(account.role==='owner'?'**/dashboard':'**/insights');await overlays(page);
  await expect(page.getByText(`Signed in as ${account.username}`,{exact:true})).toBeVisible();await pause(page,4000);
}
async function signOut(page) {
  await click(page,page.getByRole('button',{name:'Sign out',exact:true}),'sign out');
  await expect(page.getByText(/Signed in as /)).toHaveCount(0);
}
async function restoreKey(page) {
  await visible(page.getByLabel('Restore JSON backup'),'local backup import');
  await page.getByLabel('Restore JSON backup').setInputFiles(BACKUP);
  await expect(page.getByText('Ready in this tab',{exact:true})).toBeVisible();await pause(page,2000);
}
async function setupKey(page) {
  await expect(page.getByText('Checking account key…',{exact:true})).toHaveCount(0);
  const create = page.getByRole('button',{name:'Create viewing key',exact:true});
  if (await create.isVisible()) {
    const downloaded=page.waitForEvent('download');
    await click(page,create,'create a reader key and request backup download');
    await (await downloaded).saveAs(BACKUP);
    await click(page,page.getByLabel('I saved the downloaded JSON somewhere secure.'),'acknowledge locally saved backup');
    await click(page,page.getByRole('button',{name:'Register viewing key',exact:true}),'register public key only');
    await expect(page.getByText('Ready in this tab',{exact:true})).toBeVisible();
  } else {
    await fs.access(BACKUP).catch(()=>{throw new Error('Reader2 has an enrolled key but no demo backup. Restore the existing backup or use an explicit v2 reset; no silent key replacement.')});
    await restoreKey(page);
  }
}
async function screenshot(page,name) {
  const scrollY = await page.evaluate(()=>window.scrollY);
  await page.evaluate(()=>window.scrollTo({top:0,behavior:'smooth'}));
  await pause(page,1500);
  await page.evaluate(()=>{
    for (const id of ['demo-cursor','demo-subtitle']) document.getElementById(id).style.visibility='hidden';
  });
  await page.screenshot({path:path.join(RESULT,'playwright',`v2-${name}.png`),fullPage:true});
  await page.evaluate(y=>{
    for (const id of ['demo-cursor','demo-subtitle']) document.getElementById(id).style.visibility='visible';
    window.scrollTo({top:y,behavior:'smooth'});
  },scrollY);
  await pause(page,1500);
}
async function story(page,accounts) {
  const owner=accounts.find(a=>a.username==='owner');const reader=accounts.find(a=>a.username==='reader2');
  if(!owner||!reader)throw new Error('Provision owner and reader2 before running the demo');
  await goto(page,'/');await subtitle(page,'Step 1 - Private insights, owner-controlled access');
  await page.mouse.move(620,260,{steps:20});await pause(page,3000);
  await signIn(page,owner,2);
  await subtitle(page,'Step 2 - Register a signed sensor simulator');
  await type(page,page.getByLabel('Equipment name'),`Demo compressor ${REHEARSE?'rehearsal':'recording'} ${Date.now()}`,'synthetic equipment name');
  await click(page,page.getByRole('button',{name:'Add device',exact:true}),'register device');
  await expect(page.locator('#page-content [role="status"]')).toContainText('Registration receipt confirmed');
  const resource=(await page.locator('.device-list .mono').last().textContent()).trim();
  if(!/^0x[0-9a-f]{64}$/.test(resource))throw new Error('No registered resource reference');
  await subtitle(page,'Step 3 - Verify readings and reject tampered packets');
  await select(page,page.getByLabel('Simulation case'),'normal','normal signed simulator case');
  await click(page,page.getByRole('button',{name:'Run simulation',exact:true}),'publish normal signed reading');
  await expect(page.locator('#page-content [role="status"]')).toContainText('accepted');
  await select(page,page.getByLabel('Simulation case'),'tampered','tampered simulator case');
  await click(page,page.getByRole('button',{name:'Run simulation',exact:true}),'reject tampered packet');
  await expect(page.locator('#page-content [role="status"]')).toContainText('rejected');
  await screenshot(page,'demo-owner');
  await subtitle(page,'Step 4 - Commit reader permission to our blockchain');
  await select(page,page.getByLabel('Reader account'),reader.account_id,'reader2 permission recipient');
  await click(page,page.getByRole('button',{name:'Grant access',exact:true}),'commit signed grant');
  await expect(page.locator('#page-content [role="status"]')).toContainText('Grant confirmed at block');await pause(page,3000);
  await signOut(page);await signIn(page,reader,5);
  await subtitle(page,'Step 5 - Back up the private reader key locally');await setupKey(page);
  await signOut(page);await signIn(page,owner,6);
  await click(page,page.locator('.device-list li').filter({hasText:resource}).getByRole('button'),'select demo equipment');
  await subtitle(page,'Step 6 - Produce an encrypted anomaly insight');
  await select(page,page.getByLabel('Simulation case'),'anomaly','anomaly simulator case');
  await click(page,page.getByRole('button',{name:'Run simulation',exact:true}),'process signed anomaly');
  await expect(page.locator('#page-content [role="status"]')).toContainText('insight deliver');
  await signOut(page);await signIn(page,reader,7);await restoreKey(page);
  await subtitle(page,'Step 7 - Decrypt only the approved insight');
  await type(page,page.getByLabel('Equipment reference'),resource,'equipment reference');
  await click(page,page.getByRole('button',{name:'Refresh',exact:true}),'request current authorized envelopes');
  await click(page,page.getByRole('button',{name:'Open insight',exact:true}).first(),'decrypt insight in browser');
  await expect(page.getByText('MACHINE_ANOMALY',{exact:true})).toBeVisible();
  await page.locator('.insight-update').first().evaluate(el=>el.scrollIntoView({block:'center',behavior:'smooth'}));
  await pause(page,2000);
  await screenshot(page,'demo-reader');await pause(page,3500);
  await signOut(page);await signIn(page,owner,8);
  await click(page,page.locator('.device-list li').filter({hasText:resource}).getByRole('button'),'select equipment for revoke');
  await subtitle(page,'Step 8 - Revoke future delivery and unread access');
  await click(page,page.getByRole('button',{name:'Refresh access list',exact:true}),'load current grants');
  await click(page,page.getByRole('button',{name:'Revoke future access',exact:true}),'commit signed revoke');
  await expect(page.locator('#page-content [role="status"]')).toContainText('Revocation confirmed at block');
  await signOut(page);await signIn(page,reader,9);await restoreKey(page);
  await type(page,page.getByLabel('Equipment reference'),resource,'revoked equipment reference');
  await click(page,page.getByRole('button',{name:'Refresh',exact:true}),'verify new retrieval is denied');
  await expect(page.locator('#page-content [role="alert"]')).toContainText(/access|permission|denied/i);
  await subtitle(page,'Step 9 - Access denied; earlier copies cannot be recalled');
  await screenshot(page,'demo-revoked');await pause(page,4000);
}
(async()=>{
  if(DISCOVER){execFileSync(process.execPath,[path.join(__dirname,'v2-discover.cjs')],{env:{...process.env,PG_WEB_URL:BASE},stdio:'inherit'});return;}
  await fs.access(path.join(RESULT,'v2-fieldmap.json'));
  const fingerprint=crypto.createHash('sha256').update(await fs.readFile(__filename)).digest('hex');
  if(!REHEARSE){const proof=JSON.parse(await fs.readFile(MANIFEST,'utf8'));if(proof.base_url!==BASE||proof.script_sha256!==fingerprint||!proof.passed)throw new Error('Run --rehearse successfully for this script and URL before recording');}
  const accounts=JSON.parse(await fs.readFile(path.join(RUNTIME,'credentials.json'),'utf8'));
  sensitiveValues = accounts.map(account=>account.password).filter(Boolean);
  await fs.mkdir(path.join(RESULT,'playwright'),{recursive:true});
  const browser=await chromium.launch({headless:true});
  const context=await browser.newContext({viewport:{width:1280,height:720},acceptDownloads:true,
    ...(!REHEARSE?{recordVideo:{dir:path.join(RUNTIME,'recordings'),size:{width:1280,height:720}}}:{})});
  const page=await context.newPage();const video=page.video();let passed=false;
  try {await story(page,accounts);passed=true;}
  finally {await context.close();if(video&&passed)await video.saveAs(VIDEO);await browser.close();}
  if(REHEARSE)await fs.writeFile(MANIFEST,JSON.stringify({passed:true,base_url:BASE,script_sha256:fingerprint,completed_at:new Date().toISOString()},null,2));
  console.log(REHEARSE?'REHEARSAL PASSED':`Recording saved: ${VIDEO}`);
})().catch(error=>{
  let message = error.message;
  for (const value of sensitiveValues) message = message.replaceAll(value, '[redacted]');
  console.error('Demo failed:',message);process.exitCode=1;
});
