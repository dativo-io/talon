// @ts-check
// Opt-in page screenshots for review and documentation (CONSOLE_SCREENSHOTS=<dir>).
// Not an assertion suite; skipped unless the variable is set.
const { test } = require("@playwright/test");
const path = require("node:path");
const { state, pair } = require("./helpers.js");

const dir = process.env.CONSOLE_SCREENSHOTS;
test.skip(!dir, "set CONSOLE_SCREENSHOTS=<dir> to capture page screenshots");

for (const theme of ["light", "dark"]) {
  test(`screenshots (${theme})`, async ({ page }) => {
    const f = state().fixture;
    await page.setViewportSize({ width: 1360, height: 900 });
    await page.emulateMedia({ colorScheme: theme });
    await page.goto("/overview");
    await page.screenshot({ path: path.join(dir, `${theme}-00-pair.png`) });
    await pair(page, "/overview");
    const pages = [
      ["01-overview", "/overview"],
      ["02-use-cases", "/use-cases"],
      ["03-use-case", `/use-cases/${f.use_case}`],
      ["04-sessions", "/sessions"],
      ["05-session", `/sessions/${f.session}`],
      ["06-evidence", `/evidence/${f.export_denied_evidence}`],
      ["07-evidence-tampered", `/evidence/${f.tampered_evidence}`],
      ["08-costs", "/costs"],
      ["09-configuration", "/configuration"],
      ["10-system", "/system"],
    ];
    for (const [name, url] of pages) {
      await page.goto(url);
      await page.waitForLoadState("networkidle");
      await page.screenshot({ path: path.join(dir, `${theme}-${name}.png`), fullPage: true });
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`/sessions/${f.session}`);
    await page.waitForLoadState("networkidle");
    await page.screenshot({ path: path.join(dir, `${theme}-11-session-mobile.png`), fullPage: true });
  });
}
