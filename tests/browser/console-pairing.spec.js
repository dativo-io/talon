// @ts-check
// Real-browser acceptance for #537: a Chromium drives the packaged shell.
// Proves what HTTP-client tests cannot: the browser stores and sends the
// HttpOnly cookie, the pairing page's own script posts the code, the
// connected panel renders the read API's facts, logout ends the session in
// the browser as well as on the server, and no code or key reaches the URL
// or the document. Playwright gives every test a fresh browser context, so
// pairing and logout are ONE journey; nothing is assumed to carry over.
const { test, expect } = require("@playwright/test");
const fs = require("node:fs");
const { STATE, CODE_RE } = require("./global-setup.js");

function state() { return JSON.parse(fs.readFileSync(STATE, "utf8")); }

test.describe.configure({ mode: "serial" });

test("wrong code: the page shows the server's reason and no cookie is set", async ({ page, context }) => {
  await page.goto("/");
  await expect(page.locator("#pair")).toBeVisible();
  await expect(page.locator("#connected")).toBeHidden();
  await page.fill("#code", "AAAAA-AAAAA-AAAAA-AAAAA");
  await page.click("#pair-form button[type=submit]");
  await expect(page.locator("#pair-error")).toContainText("pairing_code_invalid");
  expect(await context.cookies()).toEqual([]);
  expect(page.url()).not.toContain("AAAAA");
});

test("one journey: pair with the logged code, read as the browser, refuse replay and cross-origin, log out", async ({ page, context }) => {
  const st = state();
  const base = `http://127.0.0.1:${st.uiPort}`;
  await page.waitForTimeout(600); // the pairer throttles attempts closer than 500 ms

  // Pair through the shell's own form.
  await page.goto("/");
  await expect(page.locator("#pair")).toBeVisible();
  await page.fill("#code", st.code);
  await page.click("#pair-form button[type=submit]");
  await expect(page.locator("#connected")).toBeVisible();
  await expect(page.locator("#pair")).toBeHidden();
  await expect(page.locator("#f-console")).toContainText("amounts in");
  await expect(page.locator("#f-store")).toContainText("evidence.db");
  await expect(page.locator("#f-runtime")).toContainText("unknown");

  // The session is an HttpOnly, SameSite=Strict cookie the page cannot read.
  const cookies = await context.cookies();
  expect(cookies).toHaveLength(1);
  expect(cookies[0].name).toBe("talon_console_session");
  expect(cookies[0].httpOnly).toBe(true);
  expect(cookies[0].sameSite).toBe("Strict");
  expect(cookies[0].value).not.toBe(st.code);
  expect(await page.evaluate(() => document.cookie)).toBe("");
  expect(page.url()).not.toContain(st.code);
  expect(await page.content()).not.toContain(st.code);
  expect(await page.evaluate(() => JSON.stringify(window.localStorage))).toBe("{}");

  // The browser's own fetch, from the console page, reads the API with the cookie.
  expect(await page.evaluate(() => fetch("/console/v1/system", { credentials: "same-origin" }).then((r) => r.status))).toBe(200);
  // The code was spent on pairing.
  expect(await page.evaluate(() => fetch("/console/auth/pair", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: "" }),
  }).then((r) => r.status))).toBe(400);
  await page.waitForTimeout(600); // past the attempt gap, so the answer is "spent", not "throttled"
  const replay = await page.request.post("/console/auth/pair", { data: { code: st.code }, headers: { "Content-Type": "application/json" } });
  expect(replay.status()).toBe(401);

  // A page from another origin in the SAME browser gets no read: SameSite=Strict
  // keeps the cookie home and the API sends no CORS headers, so fetch rejects.
  const evil = await context.newPage();
  await evil.goto("about:blank");
  const crossRead = await evil.evaluate((url) => fetch(url, { credentials: "include" }).then((r) => r.status).catch(() => "blocked"), `${base}/console/v1/system`);
  expect(crossRead).toBe("blocked");
  await evil.close();

  // A reload keeps the session (cookie, not page state).
  await page.reload();
  await expect(page.locator("#connected")).toBeVisible();

  // Logout: cookie gone in the browser, session gone on the server, pairing page back.
  await page.click("#logout");
  await expect(page.locator("#pair")).toBeVisible();
  await expect(page.locator("#connected")).toBeHidden();
  expect(await context.cookies()).toEqual([]);
  expect(await page.evaluate(() => fetch("/console/v1/system", { credentials: "same-origin" }).then((r) => r.status))).toBe(401);
  await page.reload();
  await expect(page.locator("#pair")).toBeVisible();
});

test("a fresh context after logout is unpaired, and the log printed the code exactly once", async ({ page, context }) => {
  const st = state();
  await page.goto("/");
  await expect(page.locator("#pair")).toBeVisible();
  expect(await context.cookies()).toEqual([]);
  const log = fs.readFileSync(st.uiLogPath, "utf8");
  const codes = [...log.matchAll(CODE_RE)].map((m) => m[1]);
  expect(codes.filter((c) => c === st.code)).toHaveLength(1);
  expect(log).not.toContain("browser-test-secrets-key");
});
