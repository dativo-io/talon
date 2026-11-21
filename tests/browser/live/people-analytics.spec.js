// @ts-check
// People Analytics over real processes (#545, #431): every value below was
// produced by the HR MCP backend (the use case's trusted MCP action source),
// the production governed MCP endpoint and the production store;
// the e2e test that started them already proved the backend's own counters.
// Here the browser must show the same facts the API and the CLI returned.
const { test, expect } = require("@playwright/test");
const { state, pair, cli } = require("../helpers.js");

test("Session: a valid aggregate, the forbidden export and an aggregate the HR backend rejects after dispatch (unknown) stay distinct, as talon audit list says", async ({ page }) => {
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

  // The same allowed tool, invalid SQL: Talon authorized and dispatched it;
  // the HR backend's error after dispatch makes the outcome unknown — never
  // a Talon denial.
  const unknown = item(f.evidence.invalid_sql);
  await expect(unknown.getByText("Talon allowed", { exact: true })).toBeVisible();
  await expect(unknown.getByText("Dispatch unknown", { exact: true })).toBeVisible();
  await expect(unknown.locator("strong", { hasText: /^Outcome unknown$/ })).toBeVisible();
  await expect(unknown.getByText("Talon denied", { exact: true })).toHaveCount(0);
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

test("Effective policy: the running serve loaded the file, gateway policy not proven (no gateway); the use case's traffic is at the Action Gateway, as talon agents show --effective says", async ({ page }) => {
  const f = state().fixture;
  const report = cli(["agents", "show", f.use_case, "--effective", "--json"]);
  expect(report.loaded.state).toBe("loaded_matches_file");
  expect(report.effective.proven_active).toBe(false);
  expect(report.effective.proof.state).toBe("no_running_process");
  expect(report.last_decision.verification).toBe("valid");
  await pair(page, `/use-cases/${f.use_case}`);
  const eff = page.getByRole("region", { name: "Effective policy" });
  await expect(eff.locator("p", { hasText: "LLM gateway:" }).getByText("Compiled from current files, not proven active")).toBeVisible();
  await expect(eff.locator("p", { hasText: "LLM gateway:" }).getByText(report.effective.proof.reason)).toBeVisible();
  // The Action Gateway's own proof, as the CLI states it (it needs the gateway
  // config the company action policy was read from; this serve has none).
  expect(report.action_boundary.proven_active).toBe(false);
  const boundary = eff.getByTestId("action-boundary");
  await expect(boundary.getByText("Compiled from current files, not proven active")).toBeVisible();
  await expect(boundary.getByText(report.action_boundary.proof.reason, { exact: true })).toBeVisible();
  const last = eff.getByRole("region", { name: "4. Last recorded decision" });
  await expect(last.getByText("Signature valid")).toBeVisible();
  await expect(last.getByRole("link", { name: report.last_decision.evidence_id })).toBeVisible();
  await expect(eff.getByText("Yes: this file is loaded")).toBeVisible();

  // Connection and verification, as the CLI states it: governed MCP calls
  // are Action Gateway operations of this use case; the LLM gateway has no
  // traffic.
  const action = report.verification.traffic.find((o) => o.boundary === "action_gateway");
  expect(action.state).toBe("observed");
  expect(report.verification.traffic.find((o) => o.boundary === "llm_gateway").state).toBe("none");
  const ver = eff.getByTestId("verification");
  await expect(ver.getByTestId("verification-reading")).toHaveText(report.verification.reading.text);
  const row = ver.locator('tr[data-boundary="action_gateway"]');
  await expect(row.getByRole("link", { name: action.evidence_id })).toBeVisible();
  await expect(ver.locator('tr[data-boundary="llm_gateway"][data-state="none"]')).toBeVisible();
});

test("System: the MCP endpoint is running, the gateway is not configured", async ({ page }) => {
  await pair(page, "/system");
  await expect(page.locator(".stat", { hasText: "MCP endpoint" }).getByText("Running", { exact: true })).toBeVisible();
  await expect(page.locator(".stat", { hasText: "LLM gateway" }).getByText("Not configured", { exact: true })).toBeVisible();
});
