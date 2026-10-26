import { test, expect, type Page } from "@playwright/test";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

type Credential={account_id:string;username:string;password:string;role:"owner"|"reader"};
async function runtimeCredentials():Promise<Credential[]|null>{try{return JSON.parse(await readFile(join(process.cwd(),"../../var/v2/credentials.json"),"utf8")) as Credential[]}catch{return null}}
async function signIn(page:Page, credential:Credential){await page.goto("/login");const username=page.getByLabel("Username"),signOut=page.getByRole("button",{name:"Sign out"});const state=await Promise.race([username.waitFor({state:"visible"}).then(()=>"form" as const),signOut.waitFor({state:"visible"}).then(()=>"session" as const)]);if(state==="session"){await signOut.click();await username.waitFor({state:"visible"})}await username.fill(credential.username);await page.getByLabel("Password").fill(credential.password);await page.getByRole("button",{name:"Sign in securely"}).click()}

test("v2 live end-to-end: signed simulation, reader key restore, grant, decrypt, revoke",async({browser})=>{
 test.setTimeout(120_000);
 const credentials=await runtimeCredentials();expect(credentials,"Run infra/scripts/v2/Setup.ps1 before browser acceptance; credentials are read locally and never logged.").not.toBeNull();
 const owner=credentials!.find(x=>x.role==="owner"),reader=credentials!.find(x=>x.role==="reader");expect(owner,"credentials.json must include an owner account").toBeTruthy();expect(reader,"credentials.json must include a reader account").toBeTruthy();
 const dir=await mkdtemp(join(tmpdir(),"pg-v2-browser-"));const backupPath=join(dir,"reader-key.json");let ownerContext,readerContext;
 try{
  ownerContext=await browser.newContext();const ownerPage=await ownerContext.newPage();await signIn(ownerPage,owner!);await expect(ownerPage).toHaveURL(/dashboard/);
  const equipmentName=`Browser demo ${Date.now()}`;await ownerPage.getByLabel("Equipment name").fill(equipmentName);await ownerPage.getByRole("button",{name:"Add device"}).click();await expect(ownerPage.getByRole("status")).toContainText("Registration receipt confirmed");
  const resource=(await ownerPage.locator(".device-list li").filter({hasText:equipmentName}).locator(".mono").textContent())?.trim();expect(resource).toMatch(/^0x[0-9a-f]{64}$/);
  readerContext=await browser.newContext();const readerPage=await readerContext.newPage();readerPage.on("dialog",dialog=>dialog.accept());await signIn(readerPage,reader!);await expect(readerPage).toHaveURL(/insights/);const createKey=readerPage.getByRole("button",{name:/Create viewing key|Replace viewing key/});const [download]=await Promise.all([readerPage.waitForEvent("download"),createKey.click()]);await download.saveAs(backupPath);await readerPage.getByLabel("I saved the downloaded JSON somewhere secure.").check();await readerPage.getByRole("button",{name:"Register viewing key"}).click();await expect(readerPage.getByText("Ready in this tab")).toBeVisible();
  await readerPage.getByLabel("Restore JSON backup").setInputFiles(backupPath);await expect(readerPage.getByText("Ready in this tab")).toBeVisible();
  await ownerPage.getByLabel("Reader account").selectOption(reader!.account_id);await ownerPage.getByRole("button",{name:"Grant access"}).click();await expect(ownerPage.getByRole("status")).toContainText("Grant confirmed at block");
  await ownerPage.getByLabel("Simulation case").selectOption("anomaly");await ownerPage.getByRole("button",{name:"Run simulation"}).click();await expect(ownerPage.getByRole("status")).toContainText("insight deliveries",{timeout:30000});
  await readerPage.getByLabel("Equipment reference").fill(resource!);const open=readerPage.getByRole("button",{name:"Open insight"}).first();await expect(open).toBeVisible({timeout:30000});for(const field of ["nonce_b64","aad_b64","ciphertext_b64","key_epoch"]){
   await readerPage.route("**/v2/insights?*",async route=>{const response=await route.fetch();const body=await response.json();const envelope={...body.items[0]};if(field==="key_epoch"){envelope.key_epoch+=1}else{const raw=Buffer.from(envelope[field],"base64");raw[0]^=1;envelope[field]=raw.toString("base64")}await route.fulfill({response,json:{...body,items:[envelope]}})});
   await readerPage.getByRole("button",{name:"Refresh",exact:true}).click();await open.click();await expect(readerPage.locator(".err[role=alert]")).toBeVisible();await expect(readerPage.getByText("MACHINE_ANOMALY",{exact:true})).toHaveCount(0);await readerPage.unroute("**/v2/insights?*");
  }
  await readerPage.getByRole("button",{name:"Refresh",exact:true}).click();await open.click();await expect(readerPage.getByText("MACHINE_ANOMALY")).toBeVisible();const readerHtml=await readerPage.locator("#page-content").textContent();expect(readerHtml).not.toContain("temp_c");expect(readerHtml).not.toContain("vibration_mm_s");expect(readerHtml).not.toContain("rpm");
  await ownerPage.getByRole("button",{name:"Revoke future access"}).click();await expect(ownerPage.getByRole("status")).toContainText("Revocation confirmed at block");await readerPage.getByRole("button",{name:"Refresh"}).click();await expect(readerPage.locator(".err[role=alert]")).toContainText(/denied|permission|access|not allowed/i,{timeout:30000});
 }finally{await Promise.allSettled([ownerContext?.close(),readerContext?.close()]);await rm(dir,{recursive:true,force:true})}
});
