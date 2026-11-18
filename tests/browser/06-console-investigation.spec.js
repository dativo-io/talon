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

test("Effective policy shows the Action Gateway's argument rules with their origin; a baseline ALLOW is not shown as unconditional", async ({ page }) => {
  const a = state().fixture.action;
  await pair(page, `/use-cases/${a.use_case}?tenant=default`);
  const block = page.getByTestId("action-boundary");
  await expect(block).toBeVisible();
  // Same projection as the CLI.
  const report = cli(["agents", "show", a.use_case, "--effective", "--json"]);
  const refund = report.action_boundary.actions.find((x) => x.action === "create_refund_request");
  expect(refund.verdict).toBe("ALLOW");
  expect(refund.decision_basis).toBe("arguments");
  const refundRow = block.getByRole("row").filter({ hasText: "create_refund_request" }).first();
  await expect(refundRow.getByText("Depends on arguments")).toBeVisible();
  await expect(refundRow.getByText("Allowed by policy")).toHaveCount(0);
  const notifyRow = block.getByRole("row").filter({ hasText: "notify_customer" }).first();
  await expect(notifyRow.getByText("Allowed by policy")).toBeVisible();
  // One rule from each layer, each shown with the layer that declared it.
  const sources = report.action_boundary.argument_rules.map((r) => r.source).sort();
  expect(sources).toEqual(["company", "use_case"]);
  for (const r of report.action_boundary.argument_rules) {
    const row = block.getByRole("row").filter({ hasText: r.id }).last();
    await expect(row.getByText(r.condition, { exact: true })).toBeVisible();
    await expect(row.getByText(r.source === "company" ? "company" : "use case", { exact: true })).toBeVisible();
    await expect(row.getByText(r.effect === "deny" ? "Deny" : `Require approval by ${r.approver_groups.join(", ")}`, { exact: true })).toBeVisible();
  }
  // Activation is the action policy's own proof: no talon serve runs in this
  // fixture, so nothing enforces it now, and the page says so with the CLI's reason.
  expect(report.action_boundary.proven_active).toBe(false);
  expect(report.action_boundary.proof.state).toBe("no_running_process");
  await expect(block.getByText("Compiled from current files, not proven active")).toBeVisible();
  await expect(block.getByText(report.action_boundary.proof.reason, { exact: true })).toBeVisible();
  await expect(block.getByText("Proven active", { exact: true })).toHaveCount(0);
});

// The lifecycle below was produced by the production action service in the
// seed (establish, reviewer decision, claim, dispatch to a counting refund
// service), and signed by the store. Each page must say what `talon audit
// show` says about the same record.
test("Evidence: the Action decision block shows the actual verdict, the matched rule and its origin, operation and approval status, with the signature check", async ({ page }) => {
  const a = state().fixture.action;
  expect(a.downstream_calls).toBe(2); // 30.00 and the approved 75.00; 900.00 never left Talon
  const block = page.getByRole("region", { name: "Action decision", exact: true });
  const fact = (label) => block.locator("dt", { hasText: new RegExp(`^${label}$`) }).locator("xpath=following-sibling::dd[1]");
  const open = async (id) => {
    const d = cli(["audit", "show", id, "--json"]);
    expect(d.verification.state).toBe("valid");
    await page.goto(`/evidence/${id}?tenant=default`);
    await expect(page.getByText("Signature valid").first()).toBeVisible();
    await expect(block).toBeVisible();
    const l = d.record.action_lifecycle;
    await expect(fact("Action")).toHaveText(l.action);
    await expect(fact("Operation")).toContainText(l.operation_id);
    await expect(fact("Verdict")).toHaveText(l.verdict);
    await expect(fact("Operation status")).toHaveText(l.operation_status.replace(/_/g, " "));
    return l;
  };

  await pair(page, `/evidence/${a.approval_evidence}?tenant=default`);
  // 75.00: approval required by the USE CASE's rule.
  let l = await open(a.approval_evidence);
  expect([l.verdict, l.matched_rule_id, l.matched_rule_source, l.operation_status]).toEqual(["REQUIRE_APPROVAL", "refund-needs-approval", "use_case", "awaiting_approval"]);
  await expect(fact("Matched rule")).toHaveText("refund-needs-approval (declared by use case)");
  // Waiting for a reviewer is not told as an allow: nothing is dispatched yet.
  expect(cli(["audit", "show", a.approval_evidence, "--json"]).outcome).toMatchObject({ decision: "approval_required", dispatch: "not_dispatched" });
  await expect(page.getByText("Approval required — not dispatched").first()).toBeVisible();
  await expect(page.getByText("Talon allowed it", { exact: false })).toHaveCount(0);
  // The reviewer's decision: approved, by the authenticated principal, nothing dispatched by it.
  l = await open(a.approval_decided_evidence);
  expect([l.approval_status, l.operation_status]).toEqual(["approved", "authorized"]);
  await expect(fact("Approval")).toContainText("approved");
  await expect(fact("Reviewer")).toContainText(l.reviewer_principal);
  // The dispatch after the approval.
  l = await open(a.approval_attempt_evidence);
  expect(l.operation_status).toBe("succeeded");
  await expect(fact("Matched rule")).toHaveText("refund-needs-approval (declared by use case)");
  // 900.00: denied by the COMPANY's rule, never dispatched.
  l = await open(a.denied_evidence);
  expect([l.verdict, l.matched_rule_id, l.matched_rule_source, l.operation_status]).toEqual(["DENY", "company:refund-too-large", "company", "denied"]);
  await expect(fact("Matched rule")).toHaveText("company:refund-too-large (declared by company)");
  // A denied operation is never dispatched; the refund service's own count
  // above (2 calls) agrees.
  await expect(page.getByText("Talon denied it — not dispatched").first()).toBeVisible();
  // 30.00: allowed, no rule matched.
  l = await open(a.allowed_evidence);
  expect(l.verdict).toBe("ALLOW");
  expect(l.matched_rule_id ?? "").toBe("");
  await expect(fact("Matched rule")).toHaveText("none recorded");
  // No page of the lifecycle carries the call's argument values.
  for (const id of [a.approval_evidence, a.approval_decided_evidence, a.approval_attempt_evidence, a.denied_evidence]) {
    await page.goto(`/evidence/${id}?tenant=default`);
    await expect(block).toBeVisible();
    const text = await page.locator("main").innerText();
    for (const value of ["75.00", "900.00", "T-refund-75", "T-refund-900"]) expect(text).not.toContain(value);
  }
  // The whole operation verifies offline, as the page's hint says.
  await page.goto(`/evidence/${a.approval_attempt_evidence}?tenant=default`);
  await expect(block.getByText(`talon audit verify --operation ${a.approved_operation}`)).toBeVisible();
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
