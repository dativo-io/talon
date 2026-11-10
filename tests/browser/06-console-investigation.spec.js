// @ts-check
// The use-case-centric investigation (#533 PR 2), in a real browser over the
// seeded People Analytics installation: AI use case → session → decision →
// signed evidence with the context kept in the URL, outcomes in plain
// language before details, and explicit proof boundaries. Case H starts at
// Costs with all tenants.
const { test, expect } = require("@playwright/test");
const { state, pair, cli } = require("./helpers.js");

test.describe.configure({ mode: "serial" });

test("AI use case page: four sections, each answering its question", async ({ page }) => {
  const f = state().fixture;
  await pair(page, `/use-cases/${f.use_case}`);
  const nav = page.getByRole("navigation", { name: "Sections of this AI use case" });
  for (const s of ["Summary", "Sessions & Activity", "Policy & Runtime", "Costs"]) {
    await expect(nav.getByRole("link", { name: s, exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: s, exact: true, level: 2 })).toBeVisible();
  }
  for (const q of ["Is this AI use case operating as expected?", "What happened when this AI use case ran?", "What is permitted, and which policy is currently active?", "What does this AI use case cost?"]) {
    await expect(page.getByText(q)).toBeVisible();
  }
  // Summary: identity, owner metadata only as declared, readiness and the most urgent finding.
  await expect(page.getByRole("region", { name: "Identity" }).getByText("default", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "State now" }).getByText("Installation readiness")).toBeVisible();
  await expect(page.getByTestId("findings")).toBeVisible();
  // Breadcrumb: scope → AI Use Cases → this use case.
  const crumbs = page.getByRole("navigation", { name: "Breadcrumb" });
  await expect(crumbs.getByRole("link", { name: "All tenants" })).toBeVisible();
  await expect(crumbs.getByText(f.use_case)).toBeVisible();
  // Policy & Runtime: the effective policy with separate boundary proofs.
  await expect(page.getByRole("region", { name: "Effective policy", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Runtime processes" })).toBeVisible();
  // Costs: attribution by model and by provider from the shared projection.
  await expect(page.getByRole("region", { name: "By model" })).toBeVisible();
  await expect(page.getByRole("region", { name: "By provider" })).toBeVisible();
  const model = cli(["costs", "--json", "--tenant", "default", "--agent", f.use_case, "--by-model"]);
  for (const m of Object.keys(model.by_model_month_eur ?? {})) {
    await expect(page.getByRole("region", { name: "By model" }).getByText(m, { exact: true })).toBeVisible();
  }
});

test("Navigation is grouped: Operate (use-case work) and Installation (setup and runtime)", async ({ page }) => {
  await pair(page, "/overview");
  const nav = page.getByRole("navigation", { name: "Console sections" });
  const operate = nav.getByRole("group", { name: "Operate" });
  const install = nav.getByRole("group", { name: "Installation" });
  for (const l of ["Overview", "AI Use Cases", "Sessions", "Costs"]) await expect(operate.getByRole("link", { name: l, exact: true })).toBeVisible();
  for (const l of ["Configuration", "System"]) await expect(install.getByRole("link", { name: l, exact: true })).toBeVisible();
});

test("Activity time range lives in the URL: deep link, reload and back keep it", async ({ page }) => {
  const f = state().fixture;
  await pair(page, `/use-cases/${f.use_case}`);
  const group = page.getByRole("group", { name: "Activity time range (UTC)" });
  await group.getByRole("button", { name: "7 days" }).click();
  await expect(page).toHaveURL(/range=7d/);
  await page.reload();
  await expect(page.getByRole("group", { name: "Activity time range (UTC)" }).getByRole("button", { name: "7 days" })).toHaveAttribute("aria-pressed", "true");
  await page.goto(`/use-cases/${f.use_case}?range=30d`);
  await expect(page.getByRole("group", { name: "Activity time range (UTC)" }).getByRole("button", { name: "30 days" })).toHaveAttribute("aria-pressed", "true");
});

test("Case D: use case → session → decision → signed evidence, with plain-language outcomes and proof boundaries; back returns along the path", async ({ page }) => {
  const f = state().fixture;
  await pair(page, `/use-cases/${f.use_case}`);
  // Recent decisions use the same rows as talon audit list, worded.
  const decisions = page.getByRole("region", { name: "Recent decisions" });
  await expect(decisions).toBeVisible();
  // Into the session: the context (tenant, use case) travels in the URL.
  await page.goto(`/sessions/${f.session}?agent=${f.use_case}`);
  const crumbs = page.getByRole("navigation", { name: "Breadcrumb" });
  await expect(crumbs.getByRole("link", { name: f.use_case })).toBeVisible();
  await expect(crumbs.getByText(`Session ${f.session}`)).toBeVisible();
  const tl = page.locator("ol.timeline");
  await expect(tl.getByText("Talon denied it — not dispatched")).toBeVisible();
  await expect(tl.getByText("Talon allowed it — dispatched — destination rejected it")).toBeVisible();
  await expect(tl.getByText("This is not a Talon denial.", { exact: false })).toBeVisible();
  // The session's proof boundaries: decisions Talon-recorded (a summary checks
  // no signature, so never "signature verified"), the client's session id
  // application-reported.
  const proof = page.getByTestId("proof-boundary");
  await expect(proof.getByRole("heading", { name: "Talon-recorded", exact: true })).toBeVisible();
  await expect(proof.getByText("signature verified", { exact: false })).toHaveCount(0);
  await expect(proof.getByText("in tenant default,", { exact: false })).toBeVisible();
  await expect(proof.getByRole("heading", { name: "Application-reported" })).toBeVisible();
  await expect(proof.getByRole("heading", { name: "Not independently verified" })).toBeVisible();
  await expect(proof.getByText("refund executed", { exact: false })).toBeVisible();
  // The forbidden export's evidence: not dispatched, zero cost, signature valid.
  await tl.getByRole("link", { name: f.export_denied_evidence }).click();
  await expect(page).toHaveURL(new RegExp(`/evidence/${f.export_denied_evidence}`));
  const story = page.getByTestId("outcome-story");
  await expect(story.getByRole("heading", { name: "Talon denied it — not dispatched" })).toBeVisible();
  await expect(story.getByText("never received it", { exact: false })).toBeVisible();
  const ev = page.getByTestId("proof-boundary");
  await expect(ev.getByRole("heading", { name: "Talon-recorded, signature verified" })).toBeVisible();
  await expect(ev.getByText("Recorded cost: none", { exact: false })).toBeVisible();
  await expect(ev.getByText("Signature: valid", { exact: false })).toBeVisible();
  await expect(ev.getByText("A valid Talon signature proves the integrity of the signed record", { exact: false })).toBeVisible();
  const evCrumbs = page.getByRole("navigation", { name: "Breadcrumb" });
  await expect(evCrumbs.getByRole("link", { name: `Session ${f.session}` })).toBeVisible();
  await expect(evCrumbs.getByRole("link", { name: f.use_case })).toBeVisible();
  // The CLI says the same about this record.
  const shown = cli(["audit", "show", f.export_denied_evidence, "--json"]);
  expect(shown.verification.state).toBe("valid");
  // Back returns to the session.
  await page.goBack();
  await expect(page).toHaveURL(new RegExp(`/sessions/${f.session}`));
  // The rejected SQL: allowed and dispatched, refused by the destination.
  await page.goto(`/evidence/${f.hr_rejected_evidence}`);
  await expect(page.getByTestId("outcome-story").getByRole("heading", { name: "Talon allowed it — dispatched — destination rejected it" })).toBeVisible();
  // Breadcrumb navigation back to the use case keeps the tenant.
  await page.getByRole("navigation", { name: "Breadcrumb" }).getByRole("link", { name: f.use_case }).click();
  await expect(page).toHaveURL(new RegExp(`/use-cases/${f.use_case}\\?tenant=default`));
});

test("A tampered record: an invalid signature invalidates the narrative, not just a warning beside it", async ({ page }) => {
  const f = state().fixture;
  await pair(page, `/evidence/${f.tampered_evidence}`);
  // The story card tells no outcome story.
  const story = page.getByTestId("outcome-story");
  await expect(story.getByRole("heading", { name: "Signature invalid — this record's outcome cannot be relied on" })).toBeVisible();
  await expect(story.getByText(/^Talon (allowed|denied) it/)).toHaveCount(0);
  // Nothing is presented as Talon's facts.
  const proof = page.getByTestId("proof-boundary");
  await expect(proof.getByText("The signature does not verify.")).toBeVisible();
  await expect(proof.getByRole("heading", { name: "Recorded claims — not reliable" })).toBeVisible();
  await expect(proof.getByRole("heading", { name: /^Talon-(verified|recorded)/ })).toHaveCount(0);
  await expect(proof.getByText(/^Talon (allowed|denied) it/)).toHaveCount(0);
  await expect(proof.getByText("Signature: INVALID", { exact: false })).toBeVisible();
  // The detailed decision card is qualified too, not shown as Talon's facts.
  await expect(page.getByRole("heading", { name: "Decision and outcome — claimed, not verified" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Decision and outcome", exact: true })).toHaveCount(0);
});

test("Case H: Costs with all tenants lists spend per (tenant, use case) and drills into sessions without choosing a use case first", async ({ page }) => {
  const f = state().fixture;
  await pair(page, "/costs");
  const fleet = page.getByTestId("fleet-spend");
  await expect(fleet).toBeVisible();
  // The table is built from configured fleet rows; it says so (#558 review).
  await expect(fleet.getByRole("heading", { name: "All tenants: month-to-date spend per configured AI use case" })).toBeVisible();
  await expect(fleet.getByText("no longer configured is not in this table", { exact: false })).toBeVisible();
  const agents = cli(["agents", "--json"]).agents;
  // One row per (tenant, use case); a name in two tenants is two rows.
  await expect(fleet.getByRole("row", { name: new RegExp(f.use_case) }).first()).toBeVisible();
  const hr = fleet.getByRole("row").filter({ has: page.getByRole("link", { name: f.use_case, exact: true }) }).filter({ hasText: "default" });
  await expect(hr).toHaveCount(1);
  const row = agents.find((a) => a.name === f.use_case);
  expect(row.tenant_id).toBe("default");
  await expect(page.getByText("The cost report below needs one tenant", { exact: false })).toBeVisible();
  await hr.getByRole("link", { name: "Sessions" }).click();
  await expect(page).toHaveURL(new RegExp(`/sessions\\?tenant=default&agent=${f.use_case}`));
  await expect(page.getByRole("heading", { name: `Sessions of ${f.use_case}` })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Breadcrumb" }).getByRole("link", { name: f.use_case })).toBeVisible();
});
