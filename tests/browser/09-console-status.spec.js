// @ts-check
// The use-case status (#575), in a real browser over the seeded
// installation: the AI Use Cases list and each use case's page show the
// Status and Next step `talon agents show <name>` prints, through the states
// an operator meets after registering an application: not active (nothing
// serves it), waiting for its first request (a running Talon process loaded
// it), working (an authenticated request evaluated under the current policy,
// served now). Fleet health "healthy" is never shown as a green verdict.
const { test, expect } = require("@playwright/test");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { state, pair, cli, writeRecords, runtimeRecord } = require("./helpers.js");

test.describe.configure({ mode: "serial" });

const NEW = "first-app";

function cliText(args) {
  const st = state();
  const r = spawnSync(st.bin, args, { env: { ...process.env, ...st.env, TALON_GATEWAY_CONFIG: `${st.dir}/talon.config.yaml` }, cwd: st.dir, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`talon ${args.join(" ")} failed (${r.status}): ${r.stderr}`);
  return r.stdout;
}

// cliStatus is the Status line and the Next block `talon agents show <name>` prints.
function cliStatus(name) {
  const lines = cliText(["agents", "show", name]).split("\n");
  const prefix = "  Status      ";
  const status = (lines.find((l) => l.startsWith(prefix)) ?? "").slice(prefix.length);
  const i = lines.indexOf("Next");
  const next = i >= 0 ? lines[i + 1].slice(2) : "";
  const commands = [];
  for (let j = i + 2; i >= 0 && j < lines.length && lines[j].startsWith("    "); j++) commands.push(lines[j].slice(4));
  return { status, next, commands };
}

// expectStatus checks one use case on the list and on its page against the
// CLI, and against the code the test expects (when given).
async function expectStatus(page, name, tenant, code, beforeEachRead = () => {}) {
  beforeEachRead();
  const want = cliStatus(name);
  expect(want.status, `talon agents show ${name} prints a Status`).not.toBe("");
  await page.goto(`/use-cases?tenant=${encodeURIComponent(tenant)}`);
  const row = page.getByRole("row", { name: new RegExp(`^${name}`) });
  const badge = row.getByTestId("use-case-status");
  await expect(badge).toHaveText(want.status);
  if (code) await expect(badge).toHaveAttribute("data-code", code);
  await expect(row.getByText("Healthy", { exact: true })).toHaveCount(0);

  beforeEachRead();
  await page.goto(`/use-cases/${encodeURIComponent(name)}?tenant=${encodeURIComponent(tenant)}`);
  const card = page.getByRole("region", { name: "Status", exact: true });
  await expect(card.getByTestId("use-case-status")).toHaveText(want.status);
  if (code) await expect(card.getByTestId("use-case-status")).toHaveAttribute("data-code", code);
  const next = card.getByTestId("use-case-next");
  await expect(next).toContainText(want.next);
  for (const c of want.commands) await expect(next.getByText(c, { exact: true })).toBeVisible();
  return want;
}

test("not active, waiting for its first request, working: the list and the page say what talon agents show says", async ({ page }) => {
  const st = state();
  const refund = st.fixture.action.use_case; // its genuine Action Gateway lifecycle verifies under the current policy
  const dir = path.join(st.dir, "agents", NEW);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "agent.talon.yaml"), `agent:\n  name: ${NEW}\n  version: "1.0.0"\npolicies:\n  cost_limits:\n    monthly: 20\n`);
  let removeRecords = () => {};
  try {
    await pair(page, "/use-cases");

    // 1. No Talon process runs in this suite. The registered use case is
    // not active; so is refund-bot, whose earlier requests verified: a
    // request recorded earlier is not a connection now. Every other use case
    // reads what the CLI prints too (disabled, needs attention).
    expect(cli(["agents", "--json"]).agents.find((a) => a.name === NEW)?.health).toBe("healthy");
    const first = await expectStatus(page, NEW, "default", "not_active");
    expect(first.next).toContain("No Talon process of this installation is running");
    const before = await expectStatus(page, refund, "default", "not_active");
    expect(before.next).toContain("The newest request verified, but that was earlier.");
    for (const a of cli(["agents", "--json"]).agents) {
      if (a.name !== NEW && a.name !== refund) await expectStatus(page, a.name, a.tenant_id);
    }

    // 2. A running `talon serve --gateway` reports both use cases loaded,
    // as talon serve writes it. Records are re-written before each read so
    // the heartbeat stays fresh.
    const reportOf = (n) => cli(["agents", "show", n, "--effective", "--json"]);
    const mine = reportOf(NEW);
    const agents = [NEW, refund].map((n) => ({ name: n, tenant_id: "default", enabled: true, policy_digest: reportOf(n).current_files.policy_digest }));
    const heartbeat = () => {
      const now = new Date().toISOString();
      removeRecords = writeRecords([runtimeRecord({
        instance_id: "browser-gw-status", roles: ["gateway"], started_at: new Date(Date.now() - 3600_000).toISOString(),
        gateway_config: { path: mine.current_files.gateway_config.path, digest: mine.current_files.gateway_config.digest, loaded_at: now },
        catalog: { active_generation: "g-status", scan_digest: "s-status", activated_at: now, reload_enabled: true, reload_rejected: false, agents },
        agent_keys: { declared: 0, loaded: 0 },
      })]);
    };
    const waiting = await expectStatus(page, NEW, "default", "waiting_for_first_request", heartbeat);
    expect(waiting.status).toBe("Waiting for its first request");
    expect(waiting.next).toContain("no request has arrived yet");

    // 3. refund-bot's newest request was authenticated and evaluated under
    // the current policy, and a running process serves it now: working.
    const working = await expectStatus(page, refund, "default", "working", heartbeat);
    expect(working.status).toBe("Working");
    expect(working.next).toContain("Nothing to do");
    // Only "Working" is green, and the page's reading is the CLI's.
    heartbeat();
    await page.goto(`/use-cases/${refund}?tenant=default`);
    const card = page.getByRole("region", { name: "Status", exact: true });
    await expect(card.locator(".badge.tone-ok")).toHaveText("Working");
    const v = reportOf(refund).verification;
    await expect(card.getByTestId("connection-reading").locator("[data-code]")).toHaveAttribute("data-code", v.reading.code);
    heartbeat();
    await page.goto("/use-cases?tenant=default");
    const firstRow = page.getByRole("row", { name: new RegExp(`^${NEW}`) });
    await expect(firstRow.locator(".badge.tone-ok")).toHaveCount(0);
    await expect(firstRow.getByTestId("fleet-attention")).toHaveText("—");
  } finally {
    removeRecords();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
