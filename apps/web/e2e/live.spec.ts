import { test, expect } from "@playwright/test";

const SHOT = "../../docs/results/playwright";
const MOCK_WALLET = "0x1111111111111111111111111111111111111111";

async function trackConsoleErrors(page: import("@playwright/test").Page) {
  const errors: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(String(e)));
  return errors;
}

test("home renders", async ({ page }) => {
  const errors = await trackConsoleErrors(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /privacygate/i })).toBeVisible();
  await expect(page.getByRole("link", { name: /owner dashboard/i })).toBeVisible();
  await expect(page.getByRole("link", { name: /subscriber insights/i })).toBeVisible();
  await page.screenshot({ path: `${SHOT}/home.png` });
  expect(errors, `console errors: ${errors.join("\n")}`).toEqual([]);
});

test("login page renders", async ({ page }) => {
  const errors = await trackConsoleErrors(page);
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: /owner.*login/i })).toBeVisible();
  await expect(
    page.getByRole("button", { name: /connect wallet and sign in/i }),
  ).toBeVisible();
  await page.screenshot({ path: `${SHOT}/login.png` });
  expect(errors, `console errors: ${errors.join("\n")}`).toEqual([]);
});

test("owner dashboard renders", async ({ page }) => {
  const errors = await trackConsoleErrors(page);
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: /owner.*dashboard/i })).toBeVisible();
  await expect(page.getByText(/owner only/i).first()).toBeVisible();
  await page.screenshot({ path: `${SHOT}/dashboard.png` });
  expect(errors, `console errors: ${errors.join("\n")}`).toEqual([]);
});

test("subscriber insights renders with no raw telemetry names", async ({
  page,
}) => {
  const errors = await trackConsoleErrors(page);
  await page.goto("/insights");
  await expect(
    page.getByRole("heading", { name: /subscriber.*insights/i }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /connect wallet/i }).first(),
  ).toBeVisible();
  const html = await page.content();
  expect(html).not.toContain("temp_c");
  expect(html).not.toContain("vibration_mm_s");
  await page.screenshot({ path: `${SHOT}/insights.png` });
  expect(errors, `console errors: ${errors.join("\n")}`).toEqual([]);
});

test("mock-wallet login flow (stubbed wallet + stubbed gateway auth)", async ({
  page,
}) => {
  const errors = await trackConsoleErrors(page);
  // Fake EIP-1193 provider: no real extension needed.
  await page.addInitScript((addr) => {
    (window as any).ethereum = {
      request: async ({ method }: { method: string }) => {
        if (method === "eth_requestAccounts") return [addr];
        if (method === "personal_sign") return "0x" + "ab".repeat(32);
        if (method === "eth_sendTransaction") return "0x" + "cd".repeat(32);
        throw new Error(`unsupported method ${method}`);
      },
    };
  }, MOCK_WALLET);
  // Stub gateway auth so no real signature verification is needed.
  await page.route("**/v1/auth/challenge", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        challenge_id: "stub-challenge",
        message_to_sign: "stub message",
        expires_at: new Date().toISOString(),
      }),
    });
  });
  await page.route("**/v1/auth/verify", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        wallet_address: MOCK_WALLET,
        expires_at: new Date().toISOString(),
        csrf_token: "stub",
      }),
    });
  });
  await page.goto("/login");
  await page.getByRole("button", { name: /connect wallet and sign in/i }).click();
  await expect(page.getByText(new RegExp(MOCK_WALLET.slice(0, 10), "i")).first()).toBeVisible({
    timeout: 15_000,
  });
  await page.screenshot({ path: `${SHOT}/login-mocked.png` });
  expect(errors, `console errors: ${errors.join("\n")}`).toEqual([]);
});
