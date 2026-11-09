// @ts-check
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const { expect } = require("@playwright/test");
const { STATE, CODE_RE } = require("./global-setup.js");

function state() { return JSON.parse(fs.readFileSync(STATE, "utf8")); }

function codes(st) {
  return [...fs.readFileSync(st.uiLogPath, "utf8").matchAll(CODE_RE)].map((m) => m[1]);
}

// freshCode asks the running console for a new code with `talon ui pair`
// (the documented reissue path) and returns it from the console's log.
async function freshCode() {
  const st = state();
  const before = codes(st).length;
  const r = spawnSync(st.bin, ["ui", "pair"], { env: { ...process.env, ...st.env }, cwd: st.dir, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`talon ui pair failed: ${r.stdout}${r.stderr}`);
  for (let i = 0; i < 50; i++) {
    const all = codes(st);
    if (all.length > before) return all[all.length - 1];
    await new Promise((res) => setTimeout(res, 100));
  }
  throw new Error("no new pairing code after talon ui pair");
}

// pair pairs this browser context through the shell's own form.
async function pair(page, path = "/overview") {
  const code = await freshCode();
  await page.waitForTimeout(600); // the pairer throttles attempts closer than 500 ms
  await page.goto(path);
  await expect(page.locator("#pair")).toBeVisible();
  await page.fill("#code", code);
  await page.click("#pair-form button[type=submit]");
  await expect(page.locator("#pair")).toBeHidden();
}

// cli runs the talon CLI against the same installation for parity checks.
function cli(args) {
  const st = state();
  const r = spawnSync(st.bin, args, { env: { ...process.env, ...st.env, TALON_GATEWAY_CONFIG: `${st.dir}/talon.config.yaml` }, cwd: st.dir, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`talon ${args.join(" ")} failed (${r.status}): ${r.stderr}`);
  return JSON.parse(r.stdout);
}

module.exports = { state, freshCode, pair, cli };
