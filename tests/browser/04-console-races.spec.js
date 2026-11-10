// @ts-check
// Late and delayed responses (#553 review): a response is shown only under
// the request it answers. Each test holds one response back with page.route
// and changes the scope, record or session while it is in flight.
const { test, expect } = require("@playwright/test");
const { state, pair } = require("./helpers.js");

test.describe.configure({ mode: "serial" });

function hold(page, pattern) {
  let release;
  const gate = new Promise((r) => { release = r; });
  page.route(pattern, async (route) => {
    await gate;
    await route.continue();
  });
  return () => release();
}

test("Evidence X → Y: while Y loads, X's details are not shown under Y", async ({ page }) => {
  const f = state().fixture;
  await pair(page, `/evidence/${f.export_denied_evidence}`);
  await expect(page.getByRole("region", { name: "Identity" }).getByText("corr-pa-export")).toBeVisible();
  const release = hold(page, `**/console/v1/evidence/${f.llm_evidence}*`);
  await page.getByRole("searchbox").fill(f.llm_evidence);
  await page.getByRole("listbox", { name: "Search results" }).getByText(f.llm_evidence).click();
  await expect(page).toHaveURL(new RegExp(`/evidence/${f.llm_evidence}`));
  await expect(page.getByText("Loading evidence")).toBeVisible();
  await expect(page.getByText("corr-pa-export")).toHaveCount(0);
  await expect(page.getByText("hr_employee_export")).toHaveCount(0);
  release();
  await expect(page.getByRole("region", { name: "Identity" }).getByText("corr-pa-llm")).toBeVisible();
  await expect(page.getByText("corr-pa-export")).toHaveCount(0);
});

test("Tenant change: tenant A's use cases are not shown while tenant B loads", async ({ page }) => {
  const f = state().fixture;
  await pair(page, "/use-cases");
  await expect(page.getByRole("link", { name: f.use_case })).toBeVisible();
  const release = hold(page, "**/console/v1/use-cases?tenant=acme*");
  await page.getByLabel("Tenant scope").selectOption("acme");
  await expect(page).toHaveURL(/tenant=acme/);
  await expect(page.getByText("Loading AI use cases")).toBeVisible();
  await expect(page.getByRole("link", { name: f.use_case })).toHaveCount(0);
  release();
  await expect(page.getByText("Loading AI use cases")).toHaveCount(0);
  await expect(page.getByRole("link", { name: f.use_case })).toHaveCount(0);
});

test("Timeline paging: a late page of session A never lands in session B", async ({ page }) => {
  const f = state().fixture;
  await pair(page, `/sessions/${f.long_session}`);
  await expect(page.getByText(/50 of 60 records/)).toBeVisible();
  const release = hold(page, `**/console/v1/sessions/${f.long_session}/timeline*`);
  await page.getByRole("button", { name: /Load 50 more/ }).click();
  // Navigate in-app to another session while A's page is held.
  await page.getByRole("searchbox").fill(f.session);
  await page.getByRole("listbox", { name: "Search results" }).getByText(f.session).click();
  await expect(page.getByRole("heading", { name: `Session ${f.session}` })).toBeVisible();
  await expect(page.locator("ol.timeline li")).toHaveCount(5);
  release();
  await page.waitForTimeout(500);
  await expect(page.locator("ol.timeline li")).toHaveCount(5);
  await expect(page.locator("ol.timeline").getByText(/long-\d\d/)).toHaveCount(0);
});

test("Session cursors: changing tenant on an older page starts the new tenant from its first page", async ({ page }) => {
  await pair(page, "/sessions?limit=1");
  const observed = page.getByRole("region", { name: "Observed in evidence" });
  await observed.getByRole("button", { name: "Older" }).click();
  await expect(observed.getByRole("button", { name: "Newer" })).toBeEnabled();
  const requests = [];
  page.on("request", (r) => { if (r.url().includes("/console/v1/sessions?")) requests.push(r.url()); });
  await page.getByLabel("Tenant scope").selectOption("acme");
  await expect(page).toHaveURL(/tenant=acme/);
  await page.waitForLoadState("networkidle");
  const last = new URL(requests[requests.length - 1]);
  expect(last.searchParams.get("tenant")).toBe("acme");
  expect(last.searchParams.get("before")).toBeNull();
  expect(last.searchParams.get("observed_before")).toBeNull();
});

test("Search: results of the previous query are not shown while the next one is pending", async ({ page }) => {
  const f = state().fixture;
  await pair(page, "/overview");
  const box = page.getByRole("searchbox");
  const list = page.getByRole("listbox", { name: "Search results" });
  await box.fill(f.export_denied_evidence);
  await expect(list.getByText(f.export_denied_evidence)).toBeVisible();
  await expect(list.getByText("Tenant default")).toBeVisible();
  const release = hold(page, `**/console/v1/search?*${f.hr_rejected_evidence}*`);
  await box.fill(f.hr_rejected_evidence);
  await expect(list.getByText("Searching…")).toBeVisible();
  await expect(list.getByText(f.export_denied_evidence)).toHaveCount(0);
  release();
  await expect(list.getByText(f.hr_rejected_evidence)).toBeVisible();
  await expect(list.getByText(f.export_denied_evidence)).toHaveCount(0);
});
