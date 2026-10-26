import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  use: {
    baseURL: process.env.PG_WEB_URL ?? "http://127.0.0.1:3000",
    screenshot: "only-on-failure",
  },
  webServer: undefined, // v2 Smoke starts the complete loopback stack first
});
