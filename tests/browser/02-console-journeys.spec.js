// @ts-check
// The operator journeys of #539–#544 on the seeded People Analytics
// installation, in a real browser against the packaged console. Values the
// browser shows are compared with the talon CLI over the same files.
const { test, expect } = require("@playwright/test");
const { state, pair, cli } = require("./helpers.js");

test.describe.configure({ mode: "serial" });

test("Overview: canonical health, disabled is not a failure, runtime stated as unknown, values match talon agents", async ({ page }) => {
  const f = state().fixture;
  await pair(page, "/overview");
  await expect(page.getByText("Health projected from persisted data.")).toBeVisible();
  const queue = page.getByRole("region", { name: "Attention queue" });
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

test("Use case detail: identity, costs with caps, policy provenance stated unknown, deep link survives refresh", async ({ page }) => {
  const f = state().fixture;
  await pair(page, `/use-cases/${f.use_case}`);
  await expect(page.getByRole("heading", { name: f.use_case, level: 1 })).toBeVisible();
  await expect(page.getByText("Effective policy provenance not available.")).toBeVisible();
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
  await expect(item(f.allowed_evidence).getByText("Talon allowed")).toBeVisible();
  await expect(item(f.allowed_evidence).getByText("Destination answered")).toBeVisible();
  await expect(item(f.export_denied_evidence).getByText("Talon denied")).toBeVisible();
  await expect(item(f.export_denied_evidence).getByText("Not dispatched")).toBeVisible();
  await expect(item(f.export_denied_evidence).getByText("hr_employee_export")).toBeVisible();
  // Talon allowed the SQL; the HR backend rejected it. Not a Talon denial.
  await expect(item(f.hr_rejected_evidence).getByText("Talon allowed")).toBeVisible();
  await expect(item(f.hr_rejected_evidence).getByText("Destination rejected")).toBeVisible();
  await expect(item(f.hr_rejected_evidence).getByText("Talon denied")).toHaveCount(0);

  await item(f.export_denied_evidence).getByRole("link", { name: f.export_denied_evidence }).click();
  await expect(page.getByText("Signature valid")).toBeVisible();
  await expect(page.getByRole("cell", { name: "POLICY_DENIED_TOOL" })).toBeVisible();
  await page.reload(); // deep link to evidence survives refresh
  await expect(page.getByText("Signature valid")).toBeVisible();
});

test("Tampered and standalone evidence: invalid signature is shown as such; no session is fabricated", async ({ page }) => {
  const f = state().fixture;
  await pair(page, `/evidence/${f.tampered_evidence}`);
  await expect(page.getByText("Signature invalid")).toBeVisible();
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

test("Costs: month figure and currency match talon costs --json", async ({ page }) => {
  const f = state().fixture;
  const report = cli(["costs", "--json", "--tenant", "default"]);
  await pair(page, "/costs");
  await expect(page.getByText(`Currency: ${report.currency}`)).toBeVisible();
  const month = page.locator(".stat", { hasText: "This calendar month" });
  const expected = new Intl.NumberFormat("en-US", { style: "currency", currency: report.currency, minimumFractionDigits: 2, maximumFractionDigits: report.month_eur !== 0 && Math.abs(report.month_eur) < 1 ? 4 : 2 }).format(report.month_eur);
  await expect(month.locator(".value")).toHaveText(expected);
  const byUseCase = page.getByRole("region", { name: "By ai use case" });
  await expect(byUseCase.getByRole("link", { name: f.use_case })).toBeVisible();
});

test("Configuration: MCP proxy forbids hr_employee_export; file contents are not claimed active", async ({ page }) => {
  await pair(page, "/configuration");
  const proxy = page.getByRole("region", { name: "MCP proxy" });
  await expect(proxy.getByText("hr_employee_export")).toBeVisible();
  await expect(proxy.getByText("http://hr-upstream:9000")).toBeVisible();
  await expect(page.getByText("Effective policy provenance not available.")).toBeVisible();
  await expect(page.getByText(/Active runtime generation: unknown/)).toBeVisible();
});

test("System: console responding, store readable with the fixture's record count, runtime unknown", async ({ page }) => {
  await pair(page, "/system");
  await expect(page.locator(".stat", { hasText: "Console" }).getByText("Responding", { exact: true })).toBeVisible();
  await expect(page.locator(".stat", { hasText: "Evidence store" }).getByText("Readable", { exact: true })).toBeVisible();
  await expect(page.locator(".stat", { hasText: "Gateway / MCP runtime" }).getByText("Unknown")).toBeVisible();
  await expect(page.getByRole("region", { name: "Evidence store" }).getByText("9", { exact: true })).toBeVisible();
});

test("Global search finds evidence by id and navigates to it", async ({ page }) => {
  const f = state().fixture;
  await pair(page, "/overview");
  await page.getByRole("searchbox").fill(f.hr_rejected_evidence);
  await page.getByRole("listbox", { name: "Search results" }).getByText(f.hr_rejected_evidence).click();
  await expect(page).toHaveURL(new RegExp(`/evidence/${f.hr_rejected_evidence}`));
  await expect(page.getByText("Destination rejected")).toBeVisible();
});

test("Unknown routes are a truthful 404", async ({ page }) => {
  const res = await page.goto("/decisions");
  expect(res?.status()).toBe(404);
});
