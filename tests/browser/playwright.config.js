// @ts-check
// Browser tests against the PACKAGED console: global-setup starts the built
// talon binary (`talon serve` for the store, `talon ui serve` for the
// console) on loopback ports and writes the pairing code it printed; the
// spec drives a real Chromium through the shell. Run via `make
// test-browser-console` or the CI "browser" job; TALON_BINARY must point at a
// built talon.
const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.js/,
  globalSetup: require.resolve("./global-setup.js"),
  globalTeardown: require.resolve("./global-teardown.js"),
  timeout: 60_000,
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? [["github"], ["list"]] : "list",
  use: {
    baseURL: process.env.TALON_CONSOLE_URL || "http://127.0.0.1:8797",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
