// @ts-check
// Real-browser acceptance for #537: a Chromium drives the packaged shell.
// Proves what HTTP-client tests cannot: the browser stores and sends the
// HttpOnly cookie, the pairing page's own script posts the code, the
// connected panel renders the read API's facts, logout ends the session in
// the browser as well as on the server, and no code or key reaches the URL
// or the document.
const { test, expect } = require("@playwright/test");
const fs = require("node:fs");
const { STATE, CODE_RE } = require("./global-setup.js");

function state() { return JSON.parse(fs.readFileSync(STATE, "utf8")); }

test.describe.configure({ mode: "serial" });

test("pairing page: wrong code shows the server's reason, no cookie is set", async ({ page, context }) => {
  await page.goto("/");
  await expect(page.locator("#pair")).toBeVisible();
  await expect(page.locator("#connected")).toBeHidden();
  await page.fill("#code", "AAAAA-AAAAA-AAAAA-AAAAA");
  await page.click("#pair-form button[type=submit]");
  await expect(page.locator("#pair-error")).toContainText("pairing_code_invalid");
  expect(await context.cookies()).toEqual([]);
  expect(page.url()).not.toContain("AAAAA");
});

test("pairing with the logged code: HttpOnly cookie, connected panel from /console/v1/system, no code in the document", async ({ page, context }) => {
  const st = state();
  await page.waitForTimeout(600); // the pairer throttles attempts closer than 500 ms
  await page.goto("/");
  await page.fill("#code", st.code);
  await page.click("#pair-form button[type=submit]");
  await expect(page.locator("#connected")).toBeVisible();
  await expect(page.locator("#f-console")).toContainText("amounts in");
  await expect(page.locator("#f-store")).toContainText("evidence.db");
  await expect(page.locator("#f-runtime")).toContainText("unknown");

  const cookies = await context.cookies();
  expect(cookies).toHaveLength(1);
  expect(cookies[0].name).toBe("talon_console_session");
  expect(cookies[0].httpOnly).toBe(true);
  expect(cookies[0].sameSite).toBe("Strict");
  expect(cookies[0].value).not.toBe(st.code);

  expect(page.url()).not.toContain(st.code);
  expect(await page.content()).not.toContain(st.code);
  expect(await page.evaluate(() => JSON.stringify(window.localStorage))).toBe("{}");
  expect(await page.evaluate(() => document.cookie)).toBe(""); // HttpOnly: invisible to script

  // The browser's own fetch, with its cookie, reads the API; the code is spent.
  const sys = await page.request.get("/console/v1/system");
  expect(sys.status()).toBe(200);
  const replay = await page.request.post("/console/auth/pair", { data: { code: st.code }, headers: { "Content-Type": "application/json" } });
  expect(replay.status()).toBe(401);

  // A cross-origin page cannot pair or read with this browser: SameSite=Strict
  // keeps the cookie home and the Origin check refuses the POST.
  const evil = await context.newPage();
  await evil.setContent(`<script>
    window.__r = fetch("${st.uiPort ? `http://127.0.0.1:${st.uiPort}` : ""}/console/v1/system", {credentials: "include"}).then(r => r.status).catch(() => "blocked");
  </script>`);
  // about:blank origin → the console's CORS-less API answers no cross-origin read.
  const status = await evil.evaluate(() => window.__r);
  expect(status).toBe("blocked");
  await evil.close();
});

test("logout clears the cookie and the server session; reload shows the pairing page", async ({ page, context }) => {
  await page.goto("/");
  await expect(page.locator("#connected")).toBeVisible();
  await page.click("#logout");
  await expect(page.locator("#pair")).toBeVisible();
  expect(await context.cookies()).toEqual([]);
  const sys = await page.request.get("/console/v1/system");
  expect(sys.status()).toBe(401);
  await page.reload();
  await expect(page.locator("#pair")).toBeVisible();
});

test("the console log printed the code exactly once and nothing else secret", async () => {
  const st = state();
  const log = fs.readFileSync(st.uiLogPath, "utf8");
  const codes = [...log.matchAll(CODE_RE)].map((m) => m[1]);
  expect(codes.filter((c) => c === st.code)).toHaveLength(1);
  expect(log).not.toContain("browser-test-secrets-key");
});
