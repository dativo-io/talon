// @ts-check
// Starts the console process from the built binary over a seeded
// installation. The seed (tests/browser/seed) writes signed evidence through
// the production store; nothing the browser sees is mocked. The pairing code
// is read from the console's stdout, as an operator reads
// `docker compose logs talon-ui`; later codes come from `talon ui pair`.
const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

// TALON_BROWSER_STATE lets a live run (tests/e2e TestE2E_PeopleAnalytics_CrossProcess
// with TALON_PA_BROWSER=1) hand its own installation to the same helpers.
const STATE = process.env.TALON_BROWSER_STATE || path.join(os.tmpdir(), "talon-console-browser-state.json");
const CODE_RE = /Talon console pairing code: ([A-Z2-9]{5}(?:-[A-Z2-9]{5}){3})/g;
const SIGNING_KEY = "browser-test-signing-key-0123456789ab";
const REPO = path.resolve(__dirname, "..", "..");

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function readLog(p) {
  try { return fs.readFileSync(p, "utf8"); } catch (_) { return "(no log)"; }
}

async function waitHttp(url, ms, proc, logPath) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (proc && proc.exitCode !== null) {
      throw new Error(`${proc.spawnargs.join(" ")} exited with ${proc.exitCode} before ${url} answered:\n${readLog(logPath)}`);
    }
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch (_) { /* not up yet */ }
    await sleep(200);
  }
  throw new Error(`timeout waiting for ${url}; log:\n${readLog(logPath)}`);
}

function seed(dir) {
  const args = ["-dir", dir, "-signing-key", SIGNING_KEY];
  const r = process.env.TALON_SEED_BINARY
    ? spawnSync(process.env.TALON_SEED_BINARY, args, { encoding: "utf8" })
    : spawnSync("go", ["run", "./tests/browser/seed", ...args], { cwd: REPO, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`seed failed (${r.status}):\n${r.stdout}\n${r.stderr}`);
  const line = r.stdout.trim().split("\n").filter((l) => l.startsWith("{\"dir\"")).pop();
  if (!line) throw new Error(`seed printed no expectations:\n${r.stdout}`);
  return JSON.parse(line);
}

module.exports = async () => {
  const bin = process.env.TALON_BINARY;
  if (!bin || !fs.existsSync(bin)) throw new Error("TALON_BINARY must point at a built talon binary");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "talon-console-browser-"));
  const fixture = seed(dir);
  const env = {
    ...process.env,
    TALON_DATA_DIR: dir,
    TALON_AGENTS_DIR: path.join(dir, "agents"),
    TALON_SECRETS_KEY: "browser-test-secrets-key-0123456",
    TALON_SIGNING_KEY: SIGNING_KEY,
    TALON_LOG_FORMAT: "json",
  };
  const uiPort = Number(process.env.TALON_UI_PORT || 8797);
  const uiLogPath = path.join(dir, "ui.log");
  const uiLog = fs.openSync(uiLogPath, "a");
  const ui = spawn(bin, ["ui", "serve", "--listen", `127.0.0.1:${uiPort}`, "--store-wait", "10s",
    "--gateway-config", path.join(dir, "talon.config.yaml"), "--proxy-config", path.join(dir, "proxy.talon.yaml")],
  { env, cwd: dir, stdio: ["ignore", uiLog, uiLog] });
  await waitHttp(`http://127.0.0.1:${uiPort}/healthz`, 30_000, ui, uiLogPath);

  let code = null;
  for (let i = 0; i < 50 && !code; i++) {
    const codes = [...readLog(uiLogPath).matchAll(CODE_RE)].map((m) => m[1]);
    code = codes[codes.length - 1] || null;
    if (!code) await sleep(100);
  }
  if (!code) throw new Error(`no pairing code in ${uiLogPath}:\n${readLog(uiLogPath)}`);
  fs.writeFileSync(STATE, JSON.stringify({ dir, uiPid: ui.pid, uiLogPath, code, uiPort, bin, env: { TALON_DATA_DIR: dir, TALON_AGENTS_DIR: env.TALON_AGENTS_DIR, TALON_SIGNING_KEY: SIGNING_KEY }, fixture }));
  process.env.TALON_CONSOLE_URL = `http://127.0.0.1:${uiPort}`;
};

module.exports.STATE = STATE;
module.exports.CODE_RE = CODE_RE;
module.exports.SIGNING_KEY = SIGNING_KEY;
