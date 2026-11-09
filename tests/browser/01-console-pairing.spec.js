// @ts-check
// Real-browser acceptance for #537 on the packaged console: pairing through
// the app's own form, the HttpOnly session cookie, session expiry returning
// to the same page, logout. Each test gets a fresh context.
const { test, expect } = require("@playwright/test");
const fs = require("node:fs");
const { state, pair } = require("./helpers.js");
const { CODE_RE, SIGNING_KEY } = require("./global-setup.js");

test.describe.configure({ mode: "serial" });

test("wrong code: the page shows the server's reason and no cookie is set", async ({ page, context }) => {
  await page.goto("/overview");
  await expect(page.locator("#pair")).toBeVisible();
  await page.fill("#code", "AAAAA-AAAAA-AAAAA-AAAAA");
  await page.click("#pair-form button[type=submit]");
  await expect(page.locator("#pair-error")).toContainText("pairing_code_invalid");
  expect(await context.cookies()).toEqual([]);
  expect(page.url()).not.toContain("AAAAA");
});

test("pairing with the startup code: HttpOnly cookie, no code in URL, document or storage; replay refused", async ({ page, context }) => {
  const st = state();
  await page.waitForTimeout(600);
  await page.goto("/overview");
  await page.fill("#code", st.code);
  await page.click("#pair-form button[type=submit]");
  await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();

  const cookies = await context.cookies();
  expect(cookies).toHaveLength(1);
  expect(cookies[0].name).toBe("talon_console_session");
  expect(cookies[0].httpOnly).toBe(true);
  expect(cookies[0].sameSite).toBe("Strict");
  expect(await page.evaluate(() => document.cookie)).toBe("");
  expect(page.url()).not.toContain(st.code);
  expect(await page.content()).not.toContain(st.code);
  expect(await page.content()).not.toContain(SIGNING_KEY);
  const storage = await page.evaluate(() => JSON.stringify(window.localStorage) + JSON.stringify(window.sessionStorage));
  expect(storage).not.toContain(st.code);
  expect(storage).not.toContain("talon_console_session");

  await page.waitForTimeout(600);
  const replay = await page.request.post("/console/auth/pair", { data: { code: st.code }, headers: { "Content-Type": "application/json" } });
  expect(replay.status()).toBe(401);
});

test("session ended mid-investigation: pairing appears in place and returns to the same page", async ({ page, context }) => {
  await pair(page, "/configuration");
  await expect(page.getByRole("heading", { name: "Configuration", level: 1 })).toBeVisible();
  await context.clearCookies(); // the server-side session is gone for this browser
  await page.getByRole("link", { name: "Costs" }).click();
  await expect(page.locator("#pair")).toBeVisible();
  await expect(page.getByText("Your console session ended")).toBeVisible();
  expect(new URL(page.url()).pathname).toBe("/costs");
  await pair(page, "/costs");
  await expect(page.getByRole("heading", { name: "Costs", level: 1 })).toBeVisible();
  expect(new URL(page.url()).pathname).toBe("/costs");
});

test("logout clears the cookie and the server session", async ({ page, context }) => {
  await pair(page, "/system");
  await page.getByRole("button", { name: "Log out", exact: true }).click();
  await expect(page.locator("#pair")).toBeVisible();
  expect(await context.cookies()).toEqual([]);
  expect((await page.request.get("/console/v1/system")).status()).toBe(401);
});

test("cross-origin pages get no read; the log printed each code once", async ({ page, context }) => {
  const st = state();
  await pair(page, "/overview");
  const evil = await context.newPage();
  await evil.goto("about:blank");
  const r = await evil.evaluate((url) => fetch(url, { credentials: "include" }).then((x) => x.status).catch(() => "blocked"), `http://127.0.0.1:${st.uiPort}/console/v1/system`);
  expect(r).toBe("blocked");
  const all = [...fs.readFileSync(st.uiLogPath, "utf8").matchAll(CODE_RE)].map((m) => m[1]);
  expect(new Set(all).size).toBe(all.length);
});
