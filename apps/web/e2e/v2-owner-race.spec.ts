import { test, expect } from "@playwright/test";

test("owner selection stays fixed during a delayed telemetry page and clears old pagination", async ({page}) => {
  const first = `0x${"a".repeat(64)}`, second = `0x${"b".repeat(64)}`;
  const account = "11111111-1111-4111-8111-111111111111";
  await page.route("**/v2/me", route => route.fulfill({json:{account_id:account,username:"owner",role:"owner",expires_at:2000000000,csrf_token:"test"}}));
  await page.route("**/v2/accounts", route => route.fulfill({json:{items:[]}}));
  await page.route("**/v2/devices", route => route.fulfill({json:{items:[
    {resource_id:first,device_id:account,name:"First compressor",ed25519_public_key_b64:"",last_sequence:1},
    {resource_id:second,device_id:account,name:"Second compressor",ed25519_public_key_b64:"",last_sequence:0},
  ]}}));
  let release!: () => void;
  const held = new Promise<void>(resolve => {release=resolve});
  await page.route(`**/v2/resources/${first}/telemetry?*`, async route => {
    await held;
    await route.fulfill({json:{items:[{device_id:account,sequence:1,issued_at:"2026-10-26T12:00:00.000Z",temp_c:77,vibration_mm_s:3,rpm:1500}],next_cursor:"old-resource-cursor"}});
  });
  await page.goto("/dashboard");
  await expect(page.getByRole("button",{name:"Refresh readings",exact:true})).toBeVisible();
  await page.getByRole("button",{name:"Refresh readings",exact:true}).click();
  const select = page.locator(".device-list li").filter({hasText:"Second compressor"}).getByRole("button");
  await expect(select).toBeDisabled();
  release();
  await expect(page.getByRole("button",{name:"Load next page of readings"})).toBeVisible();
  await select.click();
  await expect(page.getByRole("button",{name:"Load next page of readings"})).toHaveCount(0);
  await expect(page.locator("tbody tr")).toHaveCount(0);
});
