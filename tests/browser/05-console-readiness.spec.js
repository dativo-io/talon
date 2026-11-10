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
  for (const title of ["LLM gateway is offline", "MCP proxy is offline"]) {
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

test("Case G: gateway failed to start on an undecryptable agent key, a running MCP proxy lacks a declared key — never an unqualified healthy installation", async ({ page }) => {
  const f = state().fixture;
  const cleanup = writeRecords(caseGRecords(f.use_case));
  try {
    await pair(page, "/overview");
    const r = page.getByTestId("readiness");
    await expect(r.getByText("Degraded", { exact: true }).first()).toBeVisible();
    await expect(r.locator("[data-dimension='runtime.mcp_proxy']").getByText("OK", { exact: true })).toBeVisible();
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
