// @ts-check
// Approval visibility in the read-only console (#565), in a real browser
// over refund-bot's genuine Action Gateway lifecycle: the operator finds a
// request that waits for a decision, reads why approval is required, sees
// the argument NAMES and the CLI command for the exact values, and finds no
// argument value and no decision control anywhere. A request whose lifetime
// elapsed reads as not decidable; a rejected one shows who, when and why.
const crypto = require("node:crypto");
const fs = require("node:fs");
const { test, expect } = require("@playwright/test");
const { state, pair, writeRecords, runtimeRecord } = require("./helpers.js");

test.describe.configure({ mode: "serial" });

// Every console response seen by the browser is collected, so "no argument
// value" is asserted on the wire, not only on what is rendered.
function collectBodies(page) {
  const bodies = [];
  page.on("response", async (res) => {
    if (!res.url().includes("/console/v1/")) return;
    try { bodies.push({ url: res.url(), text: await res.text() }); } catch { /* navigation aborted the read */ }
  });
  return bodies;
}

test("overview → approvals → detail: discover the request and why it needs approval, without argument values", async ({ page }) => {
  const a = state().fixture.action;
  const ap = a.approvals;
  const bodies = collectBodies(page);
  await pair(page, "/overview");

  // Overview: the count, with the stored number and the inferred one apart.
  const card = page.getByTestId("approvals-card");
  await expect(card).toBeVisible();
  await expect(card.getByTestId("approvals-total")).toContainText("1 approval may await a decision");
  await expect(card.getByTestId("approvals-total")).toContainText(`${ap.unresolved} unresolved in the store`);
  await expect(card.getByTestId("approvals-total")).toContainText("1 eligible per current files");
  await expect(card.getByTestId("approvals-total")).toContainText("1 no longer decidable");
  // ... and a finding for the use case, linking to its approvals.
  const finding = page.getByTestId("findings").getByText(`${a.use_case}: 1 approval may await a decision`);
  await expect(finding).toBeVisible();

  // Approvals page from the navigation.
  await page.getByRole("navigation", { name: "Console sections" }).getByRole("link", { name: "Approvals", exact: true }).click();
  await expect(page).toHaveURL(/\/approvals/);
  const table = page.getByTestId("approvals-table");
  await expect(table.locator("tbody tr")).toHaveCount(1);
  const row = table.locator(`tr[data-approval="${ap.waiting}"]`);
  await expect(row.getByText("create_refund_request")).toBeVisible();
  await expect(row.getByText("Eligible per current files")).toBeVisible();
  await expect(row.getByText("support-leads")).toBeVisible();
  await expect(row.getByText("Can be decided now")).toHaveCount(0); // no running process proves the files are loaded

  // Detail.
  await row.getByRole("link", { name: ap.waiting }).click();
  await expect(page).toHaveURL(new RegExp(`/approvals/${ap.waiting}`));
  const detail = page.getByTestId("approval-detail");
  await expect(page.getByRole("heading", { level: 1, name: "Refund a customer payment" })).toBeVisible();
  await expect(page.getByText(`Requested by AI use case ${a.use_case} in tenant default`)).toBeVisible();
  await expect(detail.getByTestId("approval-eligibility")).toContainText("Eligible per current files");
  await expect(detail.getByTestId("approval-eligibility")).toContainText("no running Talon process is proven to enforce them");
  for (const name of ["amount", "currency", "ticket_id"]) {
    await expect(detail.getByRole("region", { name: "Arguments" }).getByText(name, { exact: true })).toBeVisible();
  }
  await expect(detail.getByTestId("approval-arguments-note")).toContainText("does not receive argument values");
  await expect(detail.getByText(`talon approvals show ${ap.waiting}`, { exact: true })).toBeVisible();
  const why = detail.getByRole("region", { name: "Why approval is required" });
  await expect(why.getByText("Rule refund-needs-approval of the use case's own policy required approval by support-leads.")).toBeVisible();
  await expect(why.getByText(/a call of create_refund_request where amount gt 50 \(decimal\) requires approval by support-leads/)).toBeVisible();
  await expect(why.getByText("unchanged since the request was established").first()).toBeVisible();
  await expect(detail.getByTestId("approval-decision")).toHaveText("None yet");
  await expect(detail.getByTestId("approval-outcome")).toHaveText("Operation awaiting approval; nothing was dispatched");
  await expect(detail.getByText(`talon approvals approve ${ap.waiting} --reason "..."`, { exact: true })).toBeVisible();
  await expect(detail.getByText(`talon approvals reject ${ap.waiting} --reason "..."`, { exact: true })).toBeVisible();

  // Progressive disclosure: identifiers and digests are collapsed.
  const tech = page.getByTestId("approval-technical");
  await expect(tech.getByText("Policy digest (bound)")).toBeHidden();
  await tech.locator("summary").click();
  await expect(tech.getByText("Policy digest (bound)")).toBeVisible();
  await expect(tech.getByText(ap.waiting_operation)).toBeVisible();

  // Navigation to the signed evidence and back to the approval.
  const lifecycle = page.getByTestId("approval-lifecycle");
  await expect(lifecycle.locator("tbody tr")).toHaveCount(2);
  // The second record is the approval request: it carries the approval id.
  await lifecycle.locator("tbody tr").nth(1).getByRole("link").click();
  await expect(page).toHaveURL(/\/evidence\//);
  await expect(page.getByRole("region", { name: "Action decision" })).toBeVisible();
  await page.getByRole("link", { name: "open the approval" }).click();
  await expect(page).toHaveURL(new RegExp(`/approvals/${ap.waiting}`));

  // No decision control anywhere on the approval pages.
  for (const name of [/^approve/i, /^reject/i, /^decide/i]) {
    await expect(page.getByRole("button", { name })).toHaveCount(0);
  }
  await expect(page.locator("form")).toHaveCount(0);

  // No argument value: not rendered, and not in any console response.
  await page.goto("/approvals?state=unresolved");
  await expect(page.getByTestId("approvals-table").locator("tbody tr")).toHaveCount(ap.unresolved);
  await page.goto(`/use-cases/${a.use_case}?tenant=default`);
  await expect(page.getByTestId("approvals-card")).toBeVisible();
  expect(bodies.length).toBeGreaterThan(5);
  for (const b of bodies) {
    for (const v of ap.argument_values) expect(b.text, `${b.url} carries the argument value ${v}`).not.toContain(v);
    if (b.url.includes("/approvals")) expect(b.text).not.toContain('"value"');
  }
});

test("a running process that loaded these files makes the same request 'can be decided now'", async ({ page }) => {
  const st = state();
  const a = st.fixture.action;
  await pair(page, `/approvals/${a.approvals.waiting}`);
  await expect(page.getByTestId("approval-eligibility")).toContainText("Eligible per current files");
  // The runtime record a `talon serve --gateway` writes after loading exactly
  // the files on disk (digests from the console's own configuration view).
  const cfg = await page.evaluate(async () => (await fetch("/console/v1/configuration", { credentials: "same-origin" })).json());
  const agents = cfg.use_cases.items.map((u) => ({ name: u.name, tenant_id: u.tenant_id, enabled: true, policy_digest: u.policy_digest }));
  expect(agents.every((x) => x.policy_digest)).toBe(true);
  const gatewayDigest = crypto.createHash("sha256").update(fs.readFileSync(`${st.dir}/talon.config.yaml`)).digest("hex");
  const now = new Date().toISOString();
  const cleanup = writeRecords([runtimeRecord({
    instance_id: "browser-serve-1", roles: ["gateway"],
    catalog: { active_generation: "gen-browser", scan_digest: "x", activated_at: now, reload_enabled: false, agents },
    gateway_config: { path: `${st.dir}/talon.config.yaml`, digest: gatewayDigest, loaded_at: now },
  })]);
  try {
    await page.reload();
    await expect(page.getByTestId("approval-eligibility")).toContainText("Can be decided now");
    await expect(page.getByTestId("approval-eligibility")).toContainText("every running Talon process loaded the configuration");
  } finally {
    cleanup();
  }
});

test("expired, rejected and approved requests: state, decision and outcome", async ({ page }) => {
  const a = state().fixture.action;
  const ap = a.approvals;
  await pair(page, `/approvals/${ap.expired}?tenant=default`);
  // Lifetime elapsed while pending: unresolved in the store, not decidable, no command.
  await expect(page.getByTestId("approval-eligibility")).toContainText("Expired, not decidable");
  await expect(page.getByTestId("approval-detail").getByText("unresolved in the store")).toBeVisible();
  await expect(page.getByText("No decision is possible for this approval any more.")).toBeVisible();
  await expect(page.getByText(/talon approvals approve/)).toHaveCount(0);

  // History.
  await page.goto("/approvals?state=decided");
  const table = page.getByTestId("approvals-table");
  await expect(table.locator("tbody tr")).toHaveCount(2);
  await expect(table.locator(`tr[data-approval="${ap.rejected}"]`).getByText("Rejected")).toBeVisible();
  await expect(table.locator(`tr[data-approval="${ap.approved}"]`).getByText("Approved")).toBeVisible();

  // The reviewer's reason quotes the exact arguments. A paired browser is
  // not a reviewer: the console says that a reason was recorded and where
  // an approver reads it, and neither shows nor receives its text.
  const bodies = [];
  page.on("response", async (resp) => {
    if (resp.url().includes("/console/v1/")) bodies.push({ url: resp.url(), text: await resp.text().catch(() => "") });
  });
  await table.locator(`tr[data-approval="${ap.rejected}"]`).getByRole("link", { name: ap.rejected }).click();
  const decision = page.getByTestId("approval-decision");
  await expect(decision).toContainText("rejected");
  await expect(decision).toContainText("by apr_support_lead (group support-leads)");
  await expect(page.getByTestId("approval-reason-recorded")).toContainText("A reason was recorded");
  await expect(page.getByTestId("approval-reason-recorded")).toContainText(`talon approvals show ${ap.rejected}`);
  await expect(page.getByTestId("approval-outcome")).toContainText("nothing was dispatched");
  await expect(page.getByTestId("approval-detail")).not.toContainText(ap.reject_reason);
  await expect(page.getByTestId("approval-detail")).not.toContainText("99.50");
  // The linked signed record of the decision: the evidence page shows who
  // decided and that a reason is recorded, names the withheld field, and
  // the stored-record JSON it prints does not contain the text.
  await page.getByTestId("approval-lifecycle").locator("tbody tr").last().getByRole("link").click();
  await expect(page.getByTestId("evidence-reason-withheld")).toContainText("Recorded, not shown in the console");
  await expect(page.getByTestId("evidence-reason-withheld")).toContainText(`talon approvals show ${ap.rejected}`);
  await expect(page.getByTestId("evidence-withheld")).toContainText("action_lifecycle.decision_reason");
  await expect(page.getByTestId("evidence-withheld")).toContainText("verified by Talon over the complete stored record");
  await expect(page.getByText("Reviewer", { exact: true })).toBeVisible();
  await expect(page.locator("main")).not.toContainText(ap.reject_reason);
  await expect(page.locator("main")).not.toContainText("99.50");
  await expect(page.locator("pre.json")).not.toContainText("decision_reason");

  expect(bodies.some((b) => b.url.includes(`/approvals/${ap.rejected}`))).toBe(true);
  expect(bodies.some((b) => b.url.includes("/console/v1/evidence/"))).toBe(true);
  for (const b of bodies) {
    expect(b.text, `${b.url} returns the reviewer's reason`).not.toContain(ap.reject_reason);
    expect(b.text, `${b.url} returns an argument value quoted in the reason`).not.toContain("99.50");
  }

  await page.goto(`/approvals/${ap.approved}`);
  await expect(page.getByTestId("approval-decision")).toContainText("approved");
  await expect(page.getByTestId("approval-outcome")).toHaveText(/Operation succeeded; 1 dispatch attempt, latest \w+, destination answered HTTP 201/);
  await expect(page.getByTestId("approval-lifecycle").locator("tbody tr")).not.toHaveCount(0);
});

test("the tenant scope filters approvals; an unknown approval is a not-found, not an empty page", async ({ page }) => {
  const ap = state().fixture.action.approvals;
  await pair(page, "/approvals?tenant=acme");
  await expect(page.getByText("No approval awaits a decision in this scope")).toBeVisible();
  await expect(page.getByText("a filter, not an access control")).toBeVisible();
  await page.goto(`/approvals/${ap.waiting}?tenant=acme`);
  await expect(page.getByRole("alert")).toContainText("not found");
  await page.goto("/approvals/apr_does_not_exist");
  await expect(page.getByRole("alert")).toContainText("not found");
});

// #590: "Denied requests" counts request-class records (LLM and tool
// requests). refund-bot's only traffic is governed Action Gateway
// operations, so its counter reads 0 while its Recent decisions list the
// governed action Talon denied: the label says what the number counts and
// where governed action decisions are, and nothing reads "Denied by Talon".
test("Denied requests: governed action denials are listed under Recent decisions, never counted as denied requests", async ({ page }) => {
  const a = state().fixture.action;
  await pair(page, `/use-cases/${a.use_case}?tenant=default`);
  const stat = page.locator(".card.stat", { hasText: "Denied requests" });
  await expect(stat.locator(".value")).toHaveText("0");
  await expect(stat).toContainText("governed action decisions are listed under Recent decisions");
  await expect(page.getByText("Denied by Talon")).toHaveCount(0);
  const decisions = page.locator("section", { has: page.locator("#uc-decisions") });
  const deniedAction = decisions.locator("tbody tr").filter({ hasText: "action_lifecycle" }).filter({ hasText: "Talon denied it" });
  await expect(deniedAction.first()).toBeVisible();
});
