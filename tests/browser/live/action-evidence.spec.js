// @ts-check
// Action Gateway evidence over real processes (#205): every record below was
// written by `talon serve` when TestE2E_ActionGateway_ArgumentRules called
// the HTTP Action Gateway (establish, a reviewer's decision with a real
// approver credential, claim, dispatch to a counting refund service). That
// test already proved the downstream call counts. Here the browser must show,
// for each signed record, what `talon audit show` says about it.
const { test, expect } = require("@playwright/test");
const { state, pair, cli } = require("../helpers.js");

const humanize = (s) => s.replace(/[_-]+/g, " ");

test("Evidence: the Action decision block shows the actual verdict, the matched rule with the layer that declared it, operation and approval status, and the signature check", async ({ page }) => {
  const f = state().fixture;
  const block = page.getByRole("region", { name: "Action decision", exact: true });
  const fact = (label) => block.locator("dt", { hasText: new RegExp(`^${label}$`) }).locator("xpath=following-sibling::dd[1]");
  const open = async (id) => {
    const d = cli(["audit", "show", id, "--json"]);
    expect(d.verification.state).toBe("valid");
    await page.goto(`/evidence/${id}`);
    await expect(page.getByText("Signature valid").first()).toBeVisible();
    await expect(block).toBeVisible();
    const l = d.record.action_lifecycle;
    await expect(fact("Action")).toHaveText(l.action);
    await expect(fact("Operation")).toContainText(l.operation_id);
    await expect(fact("Verdict")).toHaveText(l.verdict);
    await expect(fact("Operation status")).toHaveText(humanize(l.operation_status));
    if (l.matched_rule_id) {
      await expect(fact("Matched rule")).toHaveText(`${l.matched_rule_id} (declared by ${humanize(l.matched_rule_source)})`);
    } else {
      await expect(fact("Matched rule")).toHaveText("none recorded");
    }
    return { l, outcome: d.outcome };
  };

  await pair(page, `/evidence/${f.records.company_approval}`);

  // A refund of 75.00: approval required by the COMPANY's rule; not an allow.
  let r = await open(f.records.company_approval);
  expect([r.l.verdict, r.l.matched_rule_id, r.l.matched_rule_source, r.l.operation_status]).toEqual(["REQUIRE_APPROVAL", "company:refund-needs-approval", "company", "awaiting_approval"]);
  expect(r.outcome).toMatchObject({ decision: "approval_required", dispatch: "not_dispatched" });
  await expect(page.getByText("Approval required — not dispatched").first()).toBeVisible();
  await expect(page.getByText("Talon allowed it", { exact: false })).toHaveCount(0);

  // The reviewer's decision, by the authenticated approver principal.
  r = await open(f.records.company_decided);
  expect([r.l.approval_status, r.l.operation_status]).toEqual(["approved", "authorized"]);
  expect(r.l.reviewer_principal).toMatch(/^apr_/);
  await expect(fact("Approval")).toContainText("approved");
  await expect(fact("Reviewer")).toContainText(r.l.reviewer_principal);

  // The dispatch after the approval: observed, succeeded.
  r = await open(f.records.company_attempt);
  expect(r.l.operation_status).toBe("succeeded");
  expect(r.outcome).toMatchObject({ decision: "allowed", dispatch: "dispatched", downstream: "completed" });
  await expect(block.getByText(`talon audit verify --operation ${f.approved_operation}`)).toBeVisible();

  // A refund of 900.00: denied by the COMPANY's rule, never dispatched.
  r = await open(f.records.company_denied);
  expect([r.l.verdict, r.l.matched_rule_id, r.l.matched_rule_source, r.l.operation_status]).toEqual(["DENY", "company:refund-too-large", "company", "denied"]);
  expect(r.outcome).toMatchObject({ decision: "denied", dispatch: "not_dispatched" });
  await expect(page.getByText("Talon denied it — not dispatched").first()).toBeVisible();

  // Rules the USE CASE declared: a real deletion needs approval, a mass deletion is denied.
  r = await open(f.records.usecase_approval);
  expect([r.l.verdict, r.l.matched_rule_id, r.l.matched_rule_source]).toEqual(["REQUIRE_APPROVAL", "real-delete-needs-approval", "use_case"]);
  r = await open(f.records.usecase_denied);
  expect([r.l.verdict, r.l.matched_rule_id, r.l.matched_rule_source]).toEqual(["DENY", "mass-delete-denied", "use_case"]);

  // Allowed: no rule's condition held.
  r = await open(f.records.allowed);
  expect(r.l.verdict).toBe("ALLOW");
  expect(r.l.matched_rule_id ?? "").toBe("");

  // No page of these records carries an argument value of the call.
  for (const id of [f.records.company_approval, f.records.company_decided, f.records.company_attempt, f.records.company_denied, f.records.usecase_denied]) {
    await page.goto(`/evidence/${id}`);
    await expect(block).toBeVisible();
    const text = await page.locator("main").innerText();
    for (const value of ["75.00", "900.00", "T-2", "T-3", "5000"]) expect(text).not.toContain(value);
  }
});

test("Effective policy: the Action Gateway block equals talon agents show --effective, with the action policy's own activation proof", async ({ page }) => {
  const f = state().fixture;
  const report = cli(["agents", "show", f.use_case, "--effective", "--json"]);
  const b = report.action_boundary;
  expect(b.error ?? "").toBe("");
  expect(b.argument_rules.map((x) => x.source).sort()).toEqual(["company", "company", "use_case", "use_case", "use_case", "use_case"]);
  await pair(page, `/use-cases/${f.use_case}`);
  const block = page.getByTestId("action-boundary");
  await expect(block).toBeVisible();
  for (const a of b.actions) {
    const row = block.getByRole("row").filter({ hasText: a.action }).first();
    await expect(row.getByText(a.decision_basis === "arguments" ? "Depends on arguments" : "Allowed by policy")).toBeVisible();
  }
  for (const rule of b.argument_rules) {
    const row = block.getByRole("row").filter({ hasText: rule.id }).last();
    await expect(row.getByText(rule.condition, { exact: true })).toBeVisible();
    await expect(row.getByText(humanize(rule.source), { exact: true })).toBeVisible();
  }
  // The running `talon serve` was started without --gateway: it enforces the
  // company action policy it read from the file but does not report that
  // file's digest, so the policy must NOT read as proven active.
  expect(b.proven_active).toBe(false);
  expect(b.proof.state).toBe("unknown");
  await expect(block.getByText("Compiled from current files, not proven active")).toBeVisible();
  await expect(block.getByText(b.proof.reason, { exact: true })).toBeVisible();
  await expect(block.getByText("Proven active", { exact: true })).toHaveCount(0);
});
