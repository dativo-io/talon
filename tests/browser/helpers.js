// @ts-check
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
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

// Runtime records written exactly as `talon serve` writes them (same schema,
// same installation fingerprint), for readiness states no seeded process
// produces (#533).
function fingerprint(signingKey) {
  return crypto.createHmac("sha256", signingKey).update("talon-installation-fingerprint-v1").digest("hex").slice(0, 32);
}

// writeRecords writes runtime records and returns a cleanup function.
function writeRecords(records) {
  const st = state();
  const dir = path.join(st.dir, "runtime");
  fs.mkdirSync(dir, { recursive: true });
  const files = records.map((r) => {
    const p = path.join(dir, `${r.instance_id}.json`);
    fs.writeFileSync(p, JSON.stringify(r));
    return p;
  });
  return () => files.forEach((p) => fs.rmSync(p, { force: true }));
}

function runtimeRecord(extra) {
  const st = state();
  const now = new Date().toISOString();
  return {
    schema: 1, installation: { key_fingerprint: fingerprint(st.env.TALON_SIGNING_KEY), store_path: path.join(st.dir, "evidence.db") },
    version: "browser-test", pid: 4242, started_at: now, written_at: now, sequence: Date.now(), interval_seconds: 5, state: "running", ...extra,
  };
}

// caseGRecords: the People Analytics failure. The gateway failed to start on
// an undecryptable agent key; the MCP proxy heartbeats without the key.
function caseGRecords(useCase) {
  return [
    runtimeRecord({ instance_id: "startup-failure-gateway", roles: ["gateway"], state: "failed", stopped_at: new Date().toISOString(),
      startup_failure: { code: "agent_key_unavailable", reason: "a declared agent key cannot be decrypted with the configured secrets key (TALON_SECRETS_KEY changed since the key was stored?); agent authentication cannot work" } }),
    runtimeRecord({ instance_id: "browser-mcp-1", roles: ["mcp_proxy"], agent_keys: { declared: 1, loaded: 0, unloaded: [useCase] } }),
  ];
}

module.exports = { state, freshCode, pair, cli, writeRecords, runtimeRecord, caseGRecords };
