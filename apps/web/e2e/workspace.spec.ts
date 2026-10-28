import { test, expect } from "@playwright/test";

test("late initial device refresh preserves newly registered equipment", async ({ page }) => {
  const oldResource = `0x${"1".repeat(64)}`;
  const newResource = `0x${"2".repeat(64)}`;
  const device = (resource_id: string, name: string) => ({resource_id, name, device_id: resource_id, last_sequence: 0, ed25519_public_key_b64: ""});
  const oldDevice = device(oldResource, "Existing equipment");
  const newDevice = device(newResource, "New equipment");
  let releaseInitial!: () => void;
  const initial = new Promise<void>(resolve => { releaseInitial = resolve; });
  let deviceReads = 0;
  await page.route("**/v2/**", async route => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown;
    if (path === "/v2/me") json = {account_id: "owner", username: "owner", role: "owner", csrf_token: "test", expires_at: 9999999999};
    else if (path === "/v2/accounts") json = {items: []};
    else if (path === "/v2/devices" && route.request().method() === "POST") json = {...newDevice, receipt: {resource_id: newResource, block_height: 1, transaction_id: "test", block_hash: "test", operation: "REGISTER", version: 1}};
    else if (path === "/v2/devices") {
      deviceReads++;
      if (deviceReads === 1) await initial;
      json = {items: [oldDevice, newDevice]};
    } else json = {items: []};
    await route.fulfill({json});
  });
  await page.goto("/dashboard");
  await expect.poll(() => deviceReads).toBe(1);
  await page.getByLabel("Equipment name").fill("New equipment");
  await page.getByRole("button", {name: "Add device"}).click();
  await expect(page.getByRole("status")).toContainText("Registration receipt confirmed");
  releaseInitial();
  await expect(page.locator(".device-list li").filter({hasText: "New equipment"}).getByRole("button")).toHaveText("Selected");
});
