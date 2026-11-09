// @ts-check
const fs = require("node:fs");
const { STATE } = require("./global-setup.js");

module.exports = async () => {
  if (!fs.existsSync(STATE)) return;
  const st = JSON.parse(fs.readFileSync(STATE, "utf8"));
  try { process.kill(st.uiPid, "SIGTERM"); } catch (_) { /* already gone */ }
  fs.rmSync(STATE, { force: true });
  if (!process.env.KEEP_TALON_BROWSER_DIR) fs.rmSync(st.dir, { recursive: true, force: true });
};
