// @ts-check
// The operator journeys of #539–#544 on the seeded People Analytics
// installation, in a real browser against the packaged console. Values the
// browser shows are compared with the talon CLI over the same files.
const { test, expect } = require("@playwright/test");
const { state, pair, cli } = require("./helpers.js");

test.describe.configure({ mode: "serial" });

test("Overview: readiness first, canonical health kept, disabled is not a failure, values match talon agents", async ({ page }) => {
  const f = state().fixture;
  await pair(page, "/overview");
  // No data-plane process runs in this suite while both are configured:
  // readiness is degraded, never inferred healthy from the readable store.
  await expect(page.getByTestId("readiness").getByText("Degraded", { exact: true }).first()).toBeVisible();
  const queue = page.getByRole("region", { name: "Fleet health" });
  await expect(queue).toBeVisible();
  // support-bot is disabled in its file: Talon reports it stopped; the UI labels it Disabled, not failed.
  const bot = queue.getByRole("row", { name: new RegExp(f.disabled_use_case) });
  await expect(bot.getByText("Disabled", { exact: true })).toBeVisible();
  await expect(bot.getByText("Stopped", { exact: true })).toBeVisible();

  const agents = cli(["agents", "--json"]).agents;
  const hr = agents.find((a) => a.name === f.use_case);
  await page.getByRole("link", { name: "AI Use Cases" }).click();
  const row = page.getByRole("row", { name: new RegExp(`^${f.use_case}`) });
  await expect(row).toBeVisible();
  const cells = row.getByRole("cell");
  await expect(cells.nth(6)).toHaveText(String(hr.requests)); // Requests (1h) column
  await expect(cells.nth(7)).toHaveText(String(hr.denied)); // Denied column
});

test("Use case detail: identity, costs with caps, effective policy in four layers matching talon agents show --effective, deep link survives refresh", async ({ page }) => {
  const f = state().fixture;
  const st = state();
  const report = cli(["agents", "show", f.use_case, "--effective", "--json", "--proxy-config", `${st.dir}/proxy.talon.yaml`]);
  await pair(page, `/use-cases/${f.use_case}`);
  await expect(page.getByRole("heading", { name: f.use_case, level: 1 })).toBeVisible();
  const eff = page.getByRole("region", { name: "Effective policy" });
  for (const layer of ["1. Current files", "2. Loaded by a running process", "3. Effective policy", "4. Last recorded decision"]) {
    await expect(eff.getByRole("heading", { name: layer })).toBeVisible();
  }
  // No talon serve runs in this suite: compiled, never claimed active.
  expect(report.effective.proven_active).toBe(false);
  await expect(eff.getByText("Compiled from current files, not proven active")).toBeVisible();
  await expect(eff.getByText("Not proven", { exact: true })).toBeVisible();
  // The forbidden-tools rule: the union of the organization and use-case lists, as the CLI prints it.
  const ft = report.effective.rules.find((r) => r.rule === "forbidden_tools");
  const ftRow = eff.getByRole("row").filter({ has: page.getByText("forbidden_tools", { exact: true }) });
  await expect(ftRow.getByRole("cell").nth(1)).toHaveText(ft.effective);
  expect(ft.effective).toContain("hr_employee_export");
  expect(ft.effective).toContain("admin_*");
  // The MCP proxy denies hr_employee_export before dispatch.
  const tool = eff.getByRole("row").filter({ has: page.getByText("hr_employee_export", { exact: true }) });
  await expect(tool.getByText("denied at forbidden tools (hr_employee_export)")).toBeVisible();
  // The last decision is the same evidence record the CLI names.
  await expect(eff.getByRole("link", { name: report.last_decision.evidence_id })).toBeVisible();
  await expect(page.getByRole("region", { name: "Costs" }).getByText("Cap source")).toHaveCount(2);
  await page.reload();
  await expect(page.getByRole("heading", { name: f.use_case, level: 1 })).toBeVisible();
});

test("Session investigation: allowed, denied-not-dispatched and HR-rejected stay distinct; evidence verifies", async ({ page }) => {
  const f = state().fixture;
  await pair(page, "/sessions");
  const observed = page.getByRole("region", { name: "Observed in evidence" });
  await observed.getByRole("link", { name: f.session }).click();
  await expect(page.getByRole("heading", { name: `Session ${f.session}` })).toBeVisible();
  await expect(page.getByText("Observed in evidence only (no lifecycle tracked)")).toBeVisible();

  const timeline = page.locator("ol.timeline");
  const item = (id) => timeline.locator("li", { has: page.getByRole("link", { name: id }) });
  await expect(item(f.allowed_evidence).getByText("Talon allowed", { exact: true })).toBeVisible();
  await expect(item(f.allowed_evidence).getByText("Destination answered", { exact: true })).toBeVisible();
  await expect(item(f.export_denied_evidence).getByText("Talon denied", { exact: true })).toBeVisible();
  await expect(item(f.export_denied_evidence).getByText("Not dispatched", { exact: true })).toBeVisible();
  await expect(item(f.export_denied_evidence).getByText("hr_employee_export", { exact: true })).toBeVisible();
  // Talon allowed the SQL; the HR backend rejected it. Not a Talon denial.
  await expect(item(f.hr_rejected_evidence).getByText("Talon allowed", { exact: true })).toBeVisible();
  await expect(item(f.hr_rejected_evidence).getByText("Destination rejected", { exact: true })).toBeVisible();
  await expect(item(f.hr_rejected_evidence).getByText("Talon denied", { exact: true })).toHaveCount(0);
  // A cache hit is not a provider dispatch.
  await expect(item(f.cache_hit_evidence).getByText("Not dispatched", { exact: true })).toBeVisible();
  await expect(item(f.cache_hit_evidence).getByText("Answered from Talon's cache", { exact: true })).toBeVisible();
  await expect(item(f.cache_hit_evidence).getByText("Destination answered", { exact: true })).toHaveCount(0);

  await item(f.export_denied_evidence).getByRole("link", { name: f.export_denied_evidence }).click();
  await expect(page.getByText("Signature valid")).toBeVisible();
  await expect(page.getByRole("cell", { name: "POLICY_DENIED_TOOL" })).toBeVisible();
  await page.reload(); // deep link to evidence survives refresh
  await expect(page.getByText("Signature valid")).toBeVisible();
});

test("Tampered and standalone evidence: invalid signature is shown as such; no session is fabricated", async ({ page }) => {
  const f = state().fixture;
  await pair(page, `/evidence/${f.tampered_evidence}`);
  await expect(page.getByText("Signature invalid: record changed after signing")).toBeVisible();
  await page.goto(`/evidence/${f.standalone_evidence}`);
  await expect(page.getByText("Signature valid")).toBeVisible();
  await expect(page.getByText("none: a standalone record, not part of a session")).toBeVisible();
});

test("Shared external session id: each AI use case's records stay separate", async ({ page }) => {
  const f = state().fixture;
  await pair(page, `/sessions/${f.shared_external}`);
  // Unscoped: the page says the id spans two use cases and offers each one.
  await expect(page.getByText("2 AI use cases recorded this session id.")).toBeVisible();
  await page.getByRole("status").getByRole("link", { name: "support-bot" }).click();
  await expect(page).toHaveURL(/agent=support-bot/);
  const timeline = page.locator("ol.timeline");
  await expect(timeline.getByRole("link", { name: "shared-b" })).toBeVisible();
  await expect(timeline.getByRole("link", { name: "shared-a" })).toHaveCount(0);
  await expect(page.getByText("AI use cases recorded this session id.")).toHaveCount(0);
});

test("Costs: figures, unavailability and currency match talon costs --json", async ({ page }) => {
  const f = state().fixture;
  const fmt = (v, cur) => new Intl.NumberFormat("en-US", { style: "currency", currency: cur, minimumFractionDigits: 2, maximumFractionDigits: v !== 0 && Math.abs(v) < 1 ? 4 : 2 }).format(v);
  // Tenant-wide: the EUR record makes the month total not a USD sum. The CLI
  // marks it unavailable; the console must show unavailable, not $x.xx.
  const tenantReport = cli(["costs", "--json", "--tenant", "default"]);
  expect(tenantReport.unavailable_fields).toContain("month_eur");
  await pair(page, "/costs");
  await expect(page.getByText(`Currency: ${tenantReport.currency}`)).toBeVisible();
  const month = page.locator(".stat", { hasText: "This calendar month" });
  await expect(month.locator(".value")).toContainText("unavailable");
  await expect(month).toContainText("EUR");
  // One use case with comparable records: the exact CLI figure.
  const ucReport = cli(["costs", "--json", "--tenant", "default", "--agent", f.use_case]);
  expect(ucReport.unavailable_fields ?? []).not.toContain("month_eur");
  await page.goto(`/costs?agent=${f.use_case}`);
  const ucMonth = page.locator(".stat", { hasText: "This calendar month" });
  await expect(ucMonth.locator(".value")).toHaveText(fmt(ucReport.month_eur, ucReport.currency));
  await page.goto("/costs");
  const byUseCase = page.getByRole("region", { name: "By AI use case" });
  await expect(byUseCase.getByRole("link", { name: f.use_case })).toBeVisible();
});

test("Configuration: MCP proxy forbids hr_employee_export; file contents are not claimed active; links to effective policy", async ({ page }) => {
  await pair(page, "/configuration");
  const proxy = page.getByRole("region", { name: "MCP proxy" });
  await expect(proxy.getByText("hr_employee_export")).toBeVisible();
  await expect(proxy.getByText("http://hr-upstream:9000")).toBeVisible();
  await expect(page.getByText("The effective policy with rule provenance is on each AI use case's page.")).toBeVisible();
  await expect(page.getByRole("link", { name: "Effective policy and provenance" }).first()).toBeVisible();
  await expect(page.getByText("Active configuration not proven.")).toBeVisible();
  await expect(page.getByText("Not proven").first()).toBeVisible();
});

test("System: console responding, store readable with the fixture's record count, runtimes offline with the reason", async ({ page }) => {
  await pair(page, "/system");
  await expect(page.locator(".stat", { hasText: "Console" }).getByText("Responding", { exact: true })).toBeVisible();
  await expect(page.locator(".stat", { hasText: "Evidence store" }).getByText("Readable", { exact: true })).toBeVisible();
  // The fixture runs no data-plane process: both configured runtimes are
  // offline with the reason, never running and never inferred from the store.
  for (const label of ["MCP proxy", "LLM gateway"]) {
    await expect(page.locator(".stat", { hasText: label }).getByText("Offline", { exact: true })).toBeVisible();
  }
  await expect(page.getByText("configured for this installation, but no process has reported this role").first()).toBeVisible();
  const f = state().fixture;
  await expect(page.getByRole("region", { name: "Evidence store" }).getByText(String(f.records), { exact: true })).toBeVisible();
});

test("Global search finds evidence by id and navigates to it", async ({ page }) => {
  const f = state().fixture;
  await pair(page, "/overview");
  await page.getByRole("searchbox").fill(f.hr_rejected_evidence);
  await page.getByRole("listbox", { name: "Search results" }).getByText(f.hr_rejected_evidence).click();
  await expect(page).toHaveURL(new RegExp(`/evidence/${f.hr_rejected_evidence}`));
  await expect(page.getByText("Destination rejected", { exact: true })).toBeVisible();
});

test("Unknown routes are a truthful 404", async ({ page }) => {
  const res = await page.goto("/decisions");
  expect(res?.status()).toBe(404);
});

test("Fleet spend in another currency: unavailable, budget not evaluated, same as talon agents", async ({ page }) => {
  const f = state().fixture;
  const row = cli(["agents", "--json"]).agents.find((a) => a.name === f.foreign_currency_use_case);
  expect(row.unavailable_fields).toEqual(["spend_day", "spend_month"]);
  expect(row.health).toBe("needs-attention");
  await pair(page, "/use-cases");
  const ui = page.getByRole("row", { name: new RegExp(`^${f.foreign_currency_use_case}`) });
  await expect(ui.getByText("unavailable")).toBeVisible();
  await expect(ui.getByText("€")).toHaveCount(0);
  await expect(ui.getByText(/budget not evaluated/)).toBeVisible();
  await expect(ui.getByText("Needs attention")).toBeVisible();
});

test("Overview: one scope for the whole page — the chart totals today's requests, for all tenants and for one", async ({ page }) => {
  const statValue = async () => Number((await page.locator(".stat", { hasText: "Requests today" }).locator(".value").innerText()).replace(/,/g, ""));
  const chartTotal = async () => Number(/Requests \((\d+)\)/.exec(await page.locator(".legend").innerText())?.[1]);
  await pair(page, "/overview");
  await expect(page.locator(".legend")).toBeVisible();
  const allStat = await statValue();
  expect(await chartTotal()).toBe(allStat);
  await page.goto("/overview?tenant=default");
  await expect(page.locator(".legend")).toBeVisible();
  const defStat = await statValue();
  expect(await chartTotal()).toBe(defStat);
  expect(allStat).toBeGreaterThan(defStat); // the fixture has traffic in tenant acme too
});
