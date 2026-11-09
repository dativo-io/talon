// @ts-check
// Starts a throwaway Talon installation and the console process from the
// built binary. Nothing here is mocked: the shell the browser loads is the
// embedded one, the code is read from the console's stdout exactly as an
// operator reads `docker compose logs talon-ui`.
const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const STATE = path.join(os.tmpdir(), "talon-console-browser-state.json");
const CODE_RE = /Talon console pairing code: ([A-Z2-9]{5}(?:-[A-Z2-9]{5}){3})/g;

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// waitHttp polls url until it answers 2xx. If the process exits first, or
// the deadline passes, the error carries the process log: a setup failure
// must say WHY the server never answered.
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

function readLog(p) {
  try { return fs.readFileSync(p, "utf8"); } catch (_) { return "(no log)"; }
}

function run(bin, args, env, cwd) {
  const r = spawnSync(bin, args, { env, cwd, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`${args.join(" ")} failed (${r.status}):\n${r.stdout}\n${r.stderr}`);
  return r.stdout;
}

module.exports = async () => {
  const bin = process.env.TALON_BINARY;
  if (!bin || !fs.existsSync(bin)) throw new Error("TALON_BINARY must point at a built talon binary");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "talon-console-browser-"));
  const env = {
    ...process.env,
    TALON_DATA_DIR: dir,
    // secrets_key must be exactly 32 bytes (talon refuses to start otherwise).
    TALON_SECRETS_KEY: "browser-test-secrets-key-0123456",
    TALON_SIGNING_KEY: "browser-test-signing-key-0123456789ab",
    TALON_LOG_FORMAT: "json",
  };
  run(bin, ["init", "--scaffold", "--name", "hr-analytics-assistant"], env, dir);

  const dpPort = Number(process.env.TALON_DP_PORT || 8796);
  const uiPort = Number(process.env.TALON_UI_PORT || 8797);
  const dpLogPath = path.join(dir, "serve.log");
  const dpLog = fs.openSync(dpLogPath, "a");
  const dp = spawn(bin, ["serve", "--port", String(dpPort)], { env, cwd: dir, stdio: ["ignore", dpLog, dpLog] });
  await waitHttp(`http://127.0.0.1:${dpPort}/health`, 30_000, dp, dpLogPath);

  const uiLogPath = path.join(dir, "ui.log");
  const uiLog = fs.openSync(uiLogPath, "a");
  const ui = spawn(bin, ["ui", "serve", "--listen", `127.0.0.1:${uiPort}`, "--store-wait", "10s"], { env, cwd: dir, stdio: ["ignore", uiLog, uiLog] });
  await waitHttp(`http://127.0.0.1:${uiPort}/healthz`, 30_000, ui, uiLogPath);

  let code = null;
  for (let i = 0; i < 50 && !code; i++) {
    const codes = [...fs.readFileSync(uiLogPath, "utf8").matchAll(CODE_RE)].map((m) => m[1]);
    code = codes[codes.length - 1] || null;
    if (!code) await sleep(100);
  }
  if (!code) throw new Error(`no pairing code in ${uiLogPath}:\n${fs.readFileSync(uiLogPath, "utf8")}`);

  fs.writeFileSync(STATE, JSON.stringify({ dir, dpPid: dp.pid, uiPid: ui.pid, uiLogPath, code, uiPort, dpPort }));
  process.env.TALON_CONSOLE_URL = `http://127.0.0.1:${uiPort}`;
};

module.exports.STATE = STATE;
module.exports.CODE_RE = CODE_RE;
