import { test, expect } from "@playwright/test";

const MOCK_OWNER = "11111111-1111-4111-8111-111111111111";
const RESOURCE = `0x${"a".repeat(64)}`;
const receipt = { transaction_id:"22222222-2222-4222-8222-222222222222", block_height:2, block_hash:"b".repeat(64), operation:"REGISTER_RESOURCE", resource_id:RESOURCE, version:1 };

test.describe("mocked v2 browser integration (mock state; not a backend security claim)", () => {
  test("password session restores role and routes owner to device workspace", async ({page}) => {
    let authenticated=false;
    await page.route("**/v2/auth/login", async route => { authenticated=true; await route.fulfill({json:{account_id:MOCK_OWNER,username:"owner",role:"owner",expires_at:2000000000,csrf_token:"csrf-test"}}) });
    await page.route("**/v2/me", async route => authenticated ? route.fulfill({json:{account_id:MOCK_OWNER,username:"owner",role:"owner",expires_at:2000000000,csrf_token:"csrf-test"}}) : route.fulfill({status:401,json:{error:{code:"NOT_AUTHENTICATED",message:"Sign in"}}}));
    await page.route("**/v2/devices", async route => route.fulfill({json:{items:[]}}));
    await page.route("**/v2/accounts", async route => route.fulfill({json:{items:[{account_id:MOCK_OWNER,username:"reader",role:"reader"}]}}));
    await page.goto("/login"); await page.getByLabel("Username").fill("owner"); await page.getByLabel("Password").fill("runtime-secret"); await page.getByRole("button",{name:"Sign in securely"}).click();
    await expect(page).toHaveURL(/dashboard/); await expect(page.getByRole("heading",{name:"My devices"})).toBeVisible(); await expect(page.getByText("No equipment registered yet")).toBeVisible();
  });

  test("logout refreshes the current CSRF token before its single mutation",async({page})=>{
    let authenticated=false,csrfToken="old-token",logoutToken="";
    await page.route("**/v2/auth/login",async route=>{authenticated=true;await route.fulfill({json:{account_id:MOCK_OWNER,username:"owner",role:"owner",expires_at:2000000000,csrf_token:csrfToken}})});
    await page.route("**/v2/me",route=>authenticated?route.fulfill({json:{account_id:MOCK_OWNER,username:"owner",role:"owner",expires_at:2000000000,csrf_token:csrfToken}}):route.fulfill({status:401,json:{error:{code:"NOT_AUTHENTICATED",message:"Sign in"}}}));
    await page.route("**/v2/devices",route=>route.fulfill({json:{items:[]}}));await page.route("**/v2/accounts",route=>route.fulfill({json:{items:[]}}));
    await page.route("**/v2/auth/logout",async route=>{logoutToken=route.request().headers()["x-csrf-token"]??"";await route.fulfill({json:{ok:true}})});
    await page.goto("/login");await page.getByLabel("Username").fill("owner");await page.getByLabel("Password").fill("runtime-secret");await page.getByRole("button",{name:"Sign in securely"}).click();await expect(page).toHaveURL(/dashboard/);
    csrfToken="refreshed-token";await page.getByRole("button",{name:"Sign out"}).click();await expect(page.locator(".account-banner")).toContainText("Owner account required");expect(logoutToken).toBe("refreshed-token");
  });

  test("owner creates simulated device and grant, displaying confirmed receipt details", async ({page}) => {
    await page.route("**/v2/me", route => route.fulfill({json:{account_id:MOCK_OWNER,username:"owner",role:"owner",expires_at:2000000000,csrf_token:"csrf-test"}}));
    await page.route("**/v2/devices", route => route.request().method()==="POST" ? route.fulfill({json:{resource_id:RESOURCE,device_id:MOCK_OWNER,name:"Compressor A",ed25519_public_key_b64:"dGVzdA==",last_sequence:0,receipt}}) : route.fulfill({json:{items:[]}}));
    await page.route("**/v2/accounts", route => route.fulfill({json:{items:[{account_id:"33333333-3333-4333-8333-333333333333",username:"reader",role:"reader"}]}}));
    await page.goto("/dashboard"); await page.getByLabel("Equipment name").fill("Compressor A"); await page.getByRole("button",{name:"Add device"}).click();
    await expect(page.getByRole("status")).toContainText("Registration receipt confirmed at block 2");await page.getByText("Registration receipt",{exact:true}).click();await expect(page.getByText(receipt.transaction_id,{exact:true})).toBeVisible();await expect(page.getByText(receipt.block_hash,{exact:true})).toBeVisible();await page.getByLabel("Reader account").selectOption("33333333-3333-4333-8333-333333333333");
    const grantReceipt={...receipt,transaction_id:"55555555-5555-4555-8555-555555555555",block_hash:"d".repeat(64),operation:"GRANT",version:1};
    await page.route("**/v2/policies",route=>route.request().method()==="POST"?route.fulfill({json:{policy_id:"44444444-4444-4444-8444-444444444444",policy_digest:"c".repeat(64),resource_id:RESOURCE,recipient_id:"33333333-3333-4333-8333-333333333333",expires_at:2000000000,status:"ACTIVE",version:1,receipt:grantReceipt}}):route.fulfill({json:{items:[]}}));
    await page.getByRole("button",{name:"Grant access"}).click(); await expect(page.getByRole("status")).toContainText("Grant confirmed at block 2");await page.getByText("GRANT receipt details",{exact:true}).click();await expect(page.getByText(grantReceipt.transaction_id,{exact:true})).toBeVisible();await expect(page.getByText(grantReceipt.block_hash,{exact:true})).toBeVisible();
  });

  test("uncertain device creation checks operation status and retries with the same id and payload",async({page})=>{
    let posts=0,firstId="",secondId="",firstBody="",secondBody="";
    await page.route("**/v2/me",route=>route.fulfill({json:{account_id:MOCK_OWNER,username:"owner",role:"owner",expires_at:2000000000,csrf_token:"csrf-test"}}));
    await page.route("**/v2/accounts",route=>route.fulfill({json:{items:[]}}));
    await page.route("**/v2/devices",async route=>{if(route.request().method()!=="POST"){await route.fulfill({json:{items:[]}});return}posts++;const id=route.request().headers()["x-operation-id"]??"";const body=route.request().postData()??"";if(posts===1){firstId=id;firstBody=body;await route.fulfill({status:503,json:{error:{code:"GATEWAY_UNAVAILABLE",message:"Response was interrupted"}}});return}secondId=id;secondBody=body;await route.fulfill({json:{resource_id:RESOURCE,device_id:MOCK_OWNER,name:"Compressor A",ed25519_public_key_b64:"dGVzdA==",last_sequence:0,receipt}})});
    await page.route("**/v2/operations/*",route=>route.fulfill({status:404,json:{error:{code:"NOT_FOUND",message:"No operation recorded"}}}));
    await page.goto("/dashboard");await page.getByLabel("Equipment name").fill("Compressor A");await page.getByRole("button",{name:"Add device"}).click();await expect(page.getByText("Operation result is uncertain.")).toBeVisible();await page.getByRole("button",{name:"Check and retry pending operation"}).click();await expect(page.getByRole("status")).toContainText("Equipment registration confirmed at block 2");expect(posts).toBe(2);expect(firstId).toMatch(/^[0-9a-f-]{36}$/);expect(secondId).toBe(firstId);expect(secondBody).toBe(firstBody);
  });

  test("reader denial is visible and private telemetry fields never render", async ({page}) => {
    await page.route("**/v2/me",route=>route.fulfill({json:{account_id:"33333333-3333-4333-8333-333333333333",username:"reader",role:"reader",expires_at:2000000000,csrf_token:"csrf-test"}}));
    await page.route("**/v2/keys",route=>route.fulfill({json:null}));
    await page.route("**/v2/insights?**",route=>route.fulfill({status:403,json:{error:{code:"POLICY_DENIED",message:"No active READ_INSIGHT permission"}}}));
    await page.goto("/insights"); await page.getByLabel("Equipment reference").fill(RESOURCE); await page.waitForTimeout(150);
    await expect(page.locator(".err[role=alert]")).toContainText("No active READ_INSIGHT permission"); const html=await page.content(); expect(html).not.toContain("temp_c"); expect(html).not.toContain("vibration_mm_s"); expect(html).not.toContain("rpm");
  });

  test("logout before registering a viewing key clears the pending private key state", async ({page}) => {
    let authenticated=false,registered=false,failLogout=true;const readerId="33333333-3333-4333-8333-333333333333";
    await page.route("**/v2/auth/login",async route=>{authenticated=true;await route.fulfill({json:{account_id:readerId,username:"reader",role:"reader",expires_at:2000000000,csrf_token:"csrf-test"}})});
    await page.route("**/v2/me",route=>authenticated?route.fulfill({json:{account_id:readerId,username:"reader",role:"reader",expires_at:2000000000,csrf_token:"csrf-test"}}):route.fulfill({status:401,json:{error:{code:"NOT_AUTHENTICATED",message:"Sign in"}}}));
    await page.route("**/v2/keys",route=>route.request().method()==="POST"?(registered=true,route.fulfill({json:{key_id:"key",key_version:1,x25519_public_key_b64:"AA=="}})):route.fulfill({json:null}));
    await page.route("**/v2/auth/logout",route=>failLogout?route.fulfill({status:503,json:{error:{code:"GATEWAY_UNAVAILABLE",message:"Try again"}}}):route.fulfill({json:{ok:true}}));
    await page.goto("/login");await page.getByLabel("Username").fill("reader");await page.getByLabel("Password").fill("runtime-secret");await page.getByRole("button",{name:"Sign in securely"}).click();await expect(page).toHaveURL(/insights/);
    const [download]=await Promise.all([page.waitForEvent("download"),page.getByRole("button",{name:"Create viewing key"}).click()]);expect(download.suggestedFilename()).toContain("v2.json");await page.getByRole("button",{name:"Sign out"}).click();
    await expect(page.locator(".err[role=alert]")).toContainText("could not confirm sign-out");await expect(page.locator(".account-banner")).toContainText("Signed in as reader");await expect(page.getByText("Setup required")).toBeVisible();expect(registered).toBe(false);expect(await page.evaluate(()=>[localStorage.length,sessionStorage.length])).toEqual([0,0]);
    failLogout=false;await page.getByRole("button",{name:"Sign out"}).click();await expect(page.locator(".account-banner")).toContainText("Reader account required");
  });
});

test("live v2 backend login and role landing (requires PG_V2_OWNER_USERNAME and PG_V2_OWNER_PASSWORD)", async ({page}) => {
  test.skip(!process.env.PG_V2_OWNER_USERNAME || !process.env.PG_V2_OWNER_PASSWORD, "Set runtime credentials to enable the local backend integration check.");
  await page.goto("/login"); await page.getByLabel("Username").fill(process.env.PG_V2_OWNER_USERNAME!); await page.getByLabel("Password").fill(process.env.PG_V2_OWNER_PASSWORD!); await page.getByRole("button",{name:"Sign in securely"}).click();
  await expect(page).toHaveURL(/dashboard/); await expect(page.getByRole("heading",{name:"My devices"})).toBeVisible();
});
