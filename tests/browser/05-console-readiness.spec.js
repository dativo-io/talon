// @ts-check
// Operational readiness and tenant scope (#533 PR 1), in a real browser
// against the packaged console over the seeded installation. Runtime records
// are written into the installation's data directory exactly as `talon
// serve` writes them (same schema, same installation fingerprint), so the
// console reads them through its production path.
const { test, expect } = require("@playwright/test");
const { state, pair, writeRecords, runtimeRecord: record, caseGRecords } = require("./helpers.js");

test.describe.configure({ mode: "serial" });

test("Overview: configured runtimes that do not run read degraded, with findings that say what, why and where next", async ({ page }) => {
  await pair(page, "/overview");
  const r = page.getByTestId("readiness");
  await expect(r.getByText("Degraded", { exact: true }).first()).toBeVisible();
  await expect(r.getByText("Installation-wide", { exact: false })).toBeVisible();
  const findings = page.getByTestId("findings");
  for (const title of ["LLM gateway is offline", "MCP endpoint is offline"]) {
    const item = findings.locator("li", { hasText: title });
    await expect(item).toBeVisible();
    await expect(item.getByText("Critical", { exact: true })).toBeVisible();
    await expect(item.getByText("configured for this installation, but no process has reported this role")).toBeVisible();
  }
  // Fleet health is still canonical and listed after the installation findings.
  await expect(findings.locator("li[data-code^='fleet_']").first()).toBeVisible();
  const codes = await findings.locator("li").evaluateAll((els) => els.map((e) => e.getAttribute("data-code")));
  expect(codes.indexOf("runtime_offline")).toBeLessThan(codes.findIndex((c) => (c ?? "").startsWith("fleet_")));
  // Where next: the System facts behind the finding.
  await findings.locator("li", { hasText: "LLM gateway is offline" }).getByRole("link", { name: /Inspect System facts/ }).click();
  await expect(page).toHaveURL(/\/system/);
  await expect(page.getByRole("heading", { name: "System", level: 1 })).toBeVisible();
  await expect(page.getByTestId("readiness").getByText("Degraded", { exact: true }).first()).toBeVisible();
});

// #593: Talon's own installation events (reloads activated/rejected by
// talon serve, a recovery resumed by talon backup) are recorded under the
// reserved namespace "system". They are not a tenant: the selector lists the
// business tenants only — a historical tenant with traffic and no use case
// stays — and the events are under System › Installation activity, each
// with its outcome and a link to its signed, verifying record.
test("Installation events: not a tenant in the selector, not AI use case decisions, listed under System with outcome and verified evidence", async ({ page }) => {
  const f = state().fixture;
  const inst = f.installation;
  await pair(page, "/overview");
  const select = page.getByLabel("Tenant scope");
  await expect(select.locator("option[value='default']")).toHaveCount(1);
  const labels = (await select.locator("option").allTextContents()).map((l) => l.trim());
  expect(labels[0]).toBe("All tenants");
  expect(labels).toContain("acme · observed only");
  expect(labels.filter((l) => /^default · \d+ use cases?$/.test(l))).toHaveLength(1);
  expect(labels).toHaveLength(3);
  await expect(select.locator(`option[value='${inst.namespace}']`)).toHaveCount(0);

  // Not AI use case decisions: no installation event in Recent decisions.
  const decisions = page.locator("section", { has: page.locator("#events-title") });
  await expect(decisions.locator("tbody tr").first()).toBeVisible();
  const showAll = decisions.getByRole("button", { name: /Show all/ });
  if (await showAll.count()) await showAll.click();
  for (const id of [inst.reload_activated, inst.reload_rejected, inst.recovery_resumed]) {
    await expect(decisions.getByText(id)).toHaveCount(0);
  }
  await expect(decisions.getByRole("link", { name: "talon-serve" })).toHaveCount(0);

  // System › Installation activity.
  await page.getByRole("navigation", { name: "Console sections" }).getByRole("link", { name: "System" }).click();
  const act = page.locator("section", { has: page.locator("#sys-installation") });
  await expect(act.getByRole("heading", { name: "Installation activity" })).toBeVisible();
  const rejected = act.getByRole("row").filter({ hasText: inst.reload_rejected });
  await expect(rejected).toContainText("Configuration reload");
  await expect(rejected).toContainText("Rejected");
  await expect(rejected).toContainText("talon-serve");
  await expect(rejected).toContainText("policies.cost_limits.daily must be a number");
  await expect(act.getByRole("row").filter({ hasText: inst.reload_activated })).toContainText("Activated");
  const resumed = act.getByRole("row").filter({ hasText: inst.recovery_resumed });
  await expect(resumed).toContainText("Recovery resumed");
  await expect(resumed).toContainText("talon-backup");

  // The signed record opens with no tenant scope, verifies, and is shown as
  // an installation event — not as an AI use case.
  await rejected.getByRole("link", { name: inst.reload_rejected }).click();
  await expect(page).toHaveURL(new RegExp(`/evidence/${inst.reload_rejected}$`));
  await expect(page.getByTestId("outcome-story")).toContainText("Configuration reload — rejected");
  await expect(page.getByText("Signature valid").first()).toBeVisible();
  await expect(page.getByText("a Talon process, not an AI use case")).toBeVisible();
  await expect(page.getByRole("link", { name: "talon-serve" })).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Breadcrumb" }).getByRole("link", { name: "System" })).toBeVisible();

  // A URL that names the namespace says what it is.
  await page.goto(`/overview?tenant=${inst.namespace}`);
  await expect(page.getByLabel("Tenant scope")).toHaveValue(inst.namespace);
  await expect(page.getByLabel("Tenant scope").locator(`option[value='${inst.namespace}']`)).toHaveText(`${inst.namespace} · installation events, not a tenant`);
});

test("Tenant scope: a discoverable selector; it filters use cases and keeps the installation outage visible; the scope survives navigation, reload and back", async ({ page }) => {
  const f = state().fixture;
  await pair(page, "/overview");
  const select = page.getByLabel("Tenant scope");
  await expect(select.locator("option", { hasText: "All tenants" })).toHaveCount(1);
  await expect(select.locator("option[value='acme']")).toHaveCount(1);
  await expect(select.locator("option[value='default']")).toHaveCount(1);
  await select.selectOption("acme");
  await expect(page).toHaveURL(/tenant=acme/);
  // Installation readiness is not filtered by the tenant.
  await expect(page.getByTestId("readiness").getByText("Degraded", { exact: true }).first()).toBeVisible();
  await expect(page.getByTestId("findings").locator("li", { hasText: "LLM gateway is offline" })).toBeVisible();
  // Fleet findings follow the scope: none of tenant default's use cases.
  await expect(page.getByTestId("findings").getByText(f.use_case)).toHaveCount(0);
  // Navigation keeps the scope, and so does a reload.
  await page.getByRole("link", { name: "AI Use Cases" }).click();
  await expect(page).toHaveURL(/\/use-cases\?tenant=acme/);
  await expect(page.getByRole("link", { name: f.use_case })).toHaveCount(0);
  await page.getByRole("link", { name: "Sessions" }).click();
  await expect(page).toHaveURL(/\/sessions\?tenant=acme/);
  await page.reload();
  await expect(page.getByLabel("Tenant scope")).toHaveValue("acme");
  await page.goBack();
  await expect(page).toHaveURL(/\/use-cases\?tenant=acme/);
  // All tenants again.
  await page.getByLabel("Tenant scope").selectOption("");
  await expect(page).not.toHaveURL(/tenant=/);
  await expect(page.getByRole("link", { name: f.use_case })).toBeVisible();
});

test("Case G: gateway failed to start on an undecryptable agent key, a running MCP endpoint lacks a declared key — never an unqualified healthy installation", async ({ page }) => {
  const f = state().fixture;
  const cleanup = writeRecords(caseGRecords(f.use_case));
  try {
    await pair(page, "/overview");
    const r = page.getByTestId("readiness");
    await expect(r.getByText("Degraded", { exact: true }).first()).toBeVisible();
    await expect(r.locator("[data-dimension='runtime.mcp']").getByText("OK", { exact: true })).toBeVisible();
    await expect(r.locator("[data-dimension='authentication.agent_keys']").getByText("Degraded", { exact: true })).toBeVisible();
    await expect(r.locator("[data-dimension='data.evidence_store']").getByText("OK", { exact: true })).toBeVisible();
    const findings = page.getByTestId("findings");
    await expect(findings.locator("li[data-code='runtime_failed_to_start']")).toContainText("LLM gateway failed to start");
    await expect(findings.locator("li[data-code='runtime_failed_to_start']")).toContainText("cannot be decrypted");
    await expect(findings.locator("li[data-code='agent_keys_unavailable']").first()).toContainText(f.use_case);
    await expect(page.getByText(/every configured runtime runs/i)).toHaveCount(0);
    // System names the process facts behind it.
    await page.goto("/system");
    await expect(page.getByText("Failed to start", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("0 of 1 loaded")).toBeVisible();
    // Same verdict under a tenant with no traffic.
    await page.goto("/overview?tenant=acme");
    await expect(page.getByTestId("findings").locator("li[data-code='runtime_failed_to_start']")).toBeVisible();
  } finally {
    cleanup();
  }
});

test("Configuration: installation settings are labelled shared; the tenant section lists only that tenant's use cases with effective-policy links", async ({ page }) => {
  const f = state().fixture;
  await pair(page, "/configuration?tenant=default");
  await expect(page.getByRole("heading", { name: "Installation configuration" })).toBeVisible();
  await expect(page.getByText("Shared by every tenant")).toBeVisible();
  await expect(page.getByText("Organization baseline (shared)")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Tenant default: AI use cases" })).toBeVisible();
  await expect(page.getByText("Talon has no tenant-wide policy layer.", { exact: false })).toBeVisible();
  await expect(page.getByRole("article", { name: `Configuration of ${f.use_case}` })).toBeVisible();
  await expect(page.getByRole("article", { name: "Configuration of acme-bot" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Effective policy and provenance" }).first()).toBeVisible();
});
