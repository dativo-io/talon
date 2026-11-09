// @ts-check
// People Analytics over real processes (#545): every value below was produced
// by the HR MCP backend, the production MCP proxy and the production store;
// the e2e test that started them already proved the backend's own counters.
// Here the browser must show the same facts the API and the CLI returned.
const { test, expect } = require("@playwright/test");
const { state, pair, cli } = require("../helpers.js");

test("Session: allowed, denied before dispatch and rejected by the HR backend stay distinct, as talon audit list says", async ({ page }) => {
  const f = state().fixture;
  const timelineCli = cli(["audit", "list", "--json", "--session", f.session]);
  await pair(page, `/sessions/${f.session}?agent=${f.use_case}`);
  await expect(page.getByRole("heading", { name: `Session ${f.session}` })).toBeVisible();
  const timeline = page.locator("ol.timeline");
  const item = (id) => timeline.locator("li", { has: page.getByRole("link", { name: id }) });
  await expect(timeline.locator("li")).toHaveCount(timelineCli.records.length);

  const allowed = item(f.evidence.hr_aggregate_sql);
  await expect(allowed.getByText("Talon allowed")).toBeVisible();
  await expect(allowed.getByText("Destination answered")).toBeVisible();

  const denied = item(f.evidence.hr_employee_export);
  await expect(denied.getByText("Talon denied")).toBeVisible();
  await expect(denied.getByText("Not dispatched")).toBeVisible();

  const rejected = item(f.evidence.hr_headcount_detail);
  await expect(rejected.getByText("Talon allowed")).toBeVisible();
  await expect(rejected.getByText("Destination rejected")).toBeVisible();
  await expect(rejected.getByText("Talon denied")).toHaveCount(0);
});

test("Evidence: the denied call's record verifies, with the outcome talon audit show prints", async ({ page }) => {
  const f = state().fixture;
  const id = f.evidence.hr_employee_export;
  const detail = cli(["audit", "show", id, "--json"]);
  expect(detail.verification.state).toBe("valid");
  expect(detail.outcome.dispatch).toBe("not_dispatched");
  await pair(page, `/evidence/${id}`);
  await expect(page.getByText("Signature valid")).toBeVisible();
  await expect(page.getByText("Talon denied").first()).toBeVisible();
  await expect(page.getByText("Not dispatched").first()).toBeVisible();
});

test("Effective policy: proven loaded by the running proxy; hr_employee_export denied before dispatch, as talon agents show --effective says", async ({ page }) => {
  const f = state().fixture;
  const report = cli(["agents", "show", f.use_case, "--effective", "--json", "--proxy-config", f.proxy_config]);
  expect(report.loaded.state).toBe("loaded_matches_file");
  await pair(page, `/use-cases/${f.use_case}`);
  const eff = page.getByRole("region", { name: "Effective policy" });
  await expect(eff.getByText("Proven active", { exact: true })).toBeVisible();
  await expect(eff.getByText("Yes: this file is loaded")).toBeVisible();
  const tool = eff.getByRole("row").filter({ has: page.getByText("hr_employee_export", { exact: true }) });
  await expect(tool.getByText("denied at forbidden tools (hr_employee_export)")).toBeVisible();
  await expect(eff.getByRole("link", { name: report.last_decision.evidence_id })).toBeVisible();
});

test("System: the MCP proxy is running, the gateway is not configured", async ({ page }) => {
  await pair(page, "/system");
  await expect(page.locator(".stat", { hasText: "MCP proxy" }).getByText("Running", { exact: true })).toBeVisible();
  await expect(page.locator(".stat", { hasText: "LLM gateway" }).getByText("Not configured", { exact: true })).toBeVisible();
});
