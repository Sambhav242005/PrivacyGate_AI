import { test, expect } from "@playwright/test";

for (const scenario of ["Access allowed", "After revocation", "Chain offline"]) {
  test(`illustrative network: ${scenario}, manual steps and replay`, async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText("Illustrative demo", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: scenario, exact: true }).click();
    for (let step = 0; step < 4; step++) {
      await page.getByRole("button", { name: "Next step", exact: true }).click();
    }
    await expect(page.getByRole("button", { name: "Next step", exact: true })).toBeDisabled();
    if (scenario === "Access allowed") {
      await expect(page.getByText("Encrypted insight delivered", { exact: true }).first()).toBeVisible();
    } else {
      await expect(page.getByText("Third-party delivery blocked", { exact: true }).first()).toBeVisible();
    }
    await page.getByRole("button", { name: "Replay demo", exact: true }).click();
    await expect(page.getByRole("button", { name: "Pause", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Pause", exact: true }).click();
    await page.getByRole("button", { name: "Reset walkthrough", exact: true }).click();
    await expect(page.getByText("Ready to follow a packet", { exact: true }).first()).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  });
}
