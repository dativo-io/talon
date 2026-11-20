// @ts-check
// People Analytics over real processes (#545): every value below was produced
// by the HR MCP backend, the production MCP proxy and the production store;
// the e2e test that started them already proved the backend's own counters.
// Here the browser must show the same facts the API and the CLI returned.
const { test, expect } = require("@playwright/test");
const { state, pair, cli } = require("../helpers.js");

test("Session: a valid aggregate, the forbidden export and an aggregate the HR backend rejects as invalid SQL stay distinct, as talon audit list says", async ({ page }) => {
  const f = state().fixture;
  const timelineCli = cli(["audit", "list", "--json", "--session", f.session]);
  await pair(page, `/sessions/${f.session}?agent=${f.use_case}`);
  await expect(page.getByRole("heading", { name: `Session ${f.session}` })).toBeVisible();
  const timeline = page.locator("ol.timeline");
  const item = (id) => timeline.locator("li", { has: page.getByRole("link", { name: id }) });
  await expect(timeline.locator("li")).toHaveCount(timelineCli.records.length);

  const allowed = item(f.evidence.allowed);
  await expect(allowed.getByText("Talon allowed", { exact: true })).toBeVisible();
  await expect(allowed.getByText("Destination answered", { exact: true })).toBeVisible();

  const denied = item(f.evidence.forbidden);
  await expect(denied.getByText("Talon denied", { exact: true })).toBeVisible();
  await expect(denied.getByText("Not dispatched", { exact: true })).toBeVisible();

  // The same allowed tool, invalid SQL: Talon dispatched it, the HR backend refused it.
  const rejected = item(f.evidence.invalid_sql);
  await expect(rejected.getByText("Talon allowed", { exact: true })).toBeVisible();
  await expect(rejected.getByText("Destination rejected", { exact: true })).toBeVisible();
  await expect(rejected.getByText("Talon denied", { exact: true })).toHaveCount(0);
});

test("Evidence: the denied call's record verifies, with the outcome talon audit show prints", async ({ page }) => {
  const f = state().fixture;
  const id = f.evidence.forbidden;
  const detail = cli(["audit", "show", id, "--json"]);
  expect(detail.verification.state).toBe("valid");
  expect(detail.outcome.dispatch).toBe("not_dispatched");
  await pair(page, `/evidence/${id}`);
  await expect(page.getByText("Signature valid")).toBeVisible();
  await expect(page.getByText("Talon denied").first()).toBeVisible();
  await expect(page.getByText("Not dispatched").first()).toBeVisible();
});

test("Effective policy: MCP decisions proven by the running proxy, gateway policy not proven (no gateway); hr_employee_export denied before dispatch, as talon agents show --effective says", async ({ page }) => {
  const f = state().fixture;
  const report = cli(["agents", "show", f.use_case, "--effective", "--json", "--proxy-config", f.proxy_config]);
  expect(report.loaded.state).toBe("loaded_matches_file");
  expect(report.mcp_boundary.proven_active).toBe(true);
  expect(report.effective.proven_active).toBe(false);
  expect(report.effective.proof.state).toBe("no_running_process");
  expect(report.last_decision.verification).toBe("valid");
  await pair(page, `/use-cases/${f.use_case}`);
  const eff = page.getByRole("region", { name: "Effective policy" });
  // Exactly one boundary is proven: the MCP proxy's.
  await expect(eff.getByText("Proven active", { exact: true })).toHaveCount(1);
  await expect(eff.getByText("Compiled from current files, not proven active")).toBeVisible();
  await expect(eff.locator("p", { hasText: "LLM gateway:" }).getByText(report.effective.proof.reason)).toBeVisible();
  await expect(eff.locator("p", { hasText: "MCP proxy:" }).getByText("Proven active", { exact: true })).toBeVisible();
  // The last decision and the per-boundary observations are separate
  // sections; each assertion names the one it is about.
  const last = eff.getByRole("region", { name: "4. Last recorded decision" });
  await expect(last.getByText("Signature valid")).toBeVisible();
  await expect(last.getByRole("link", { name: report.last_decision.evidence_id })).toBeVisible();
  await expect(eff.getByText("Yes: this file is loaded")).toBeVisible();
  const tool = eff.getByRole("row").filter({ has: page.getByText("hr_employee_export", { exact: true }) });
  await expect(tool.getByText("denied at forbidden tools (hr_employee_export)")).toBeVisible();

  // Connection and verification, as the CLI states it: this use case's
  // traffic is at the MCP proxy only, whose records do not say how the
  // caller was identified, so nothing here reads as an authenticated
  // connection; the LLM gateway has no traffic.
  const mcp = report.verification.traffic.find((o) => o.boundary === "mcp_proxy");
  expect(mcp.state).toBe("observed");
  expect(mcp.identity_proven).toBe(false);
  expect(report.verification.traffic.find((o) => o.boundary === "llm_gateway").state).toBe("none");
  const ver = eff.getByTestId("verification");
  await expect(ver.getByTestId("verification-reading")).toHaveText(report.verification.reading.text);
  const row = ver.locator('tr[data-boundary="mcp_proxy"]');
  await expect(row.getByText("Observed, caller's identity not established")).toBeVisible();
  await expect(row.getByRole("link", { name: mcp.evidence_id })).toBeVisible();
  await expect(ver.locator('tr[data-boundary="llm_gateway"][data-state="none"]')).toBeVisible();
  await expect(ver.getByText("Observed, authenticated")).toHaveCount(0);
});

test("System: the MCP proxy is running, the gateway is not configured", async ({ page }) => {
  await pair(page, "/system");
  await expect(page.locator(".stat", { hasText: "MCP proxy" }).getByText("Running", { exact: true })).toBeVisible();
  await expect(page.locator(".stat", { hasText: "LLM gateway" }).getByText("Not configured", { exact: true })).toBeVisible();
});
