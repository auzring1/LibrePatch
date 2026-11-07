import { defineConfig } from "@playwright/test";

// GUI end-to-end test. Run via scripts/gui-e2e.sh, which starts a fresh
// server + database and a real (Linux test build) agent.
export default defineConfig({
  testDir: "e2e",
  timeout: 300_000, // one long test that walks the whole console
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.LIBREPATCH_GUI_URL ?? "http://localhost:18080",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
});
