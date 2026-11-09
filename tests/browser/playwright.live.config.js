// @ts-check
// The live People Analytics run (#545): tests/e2e
// TestE2E_PeopleAnalytics_CrossProcess starts a real HR MCP backend, the
// production `talon serve --proxy-config` and `talon ui serve`, drives the
// traffic, writes TALON_BROWSER_STATE and runs this config while the data
// plane is up. No global setup: the installation is the e2e test's.
const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./live",
  testMatch: /.*\.spec\.js/,
  timeout: 60_000,
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? [["github"], ["list"]] : "list",
  use: { baseURL: process.env.TALON_CONSOLE_URL, trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
