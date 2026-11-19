// @ts-check
// Connection and verification on the AI use case page (#472), in a real
// browser over the seeded installation: for every use case the console
// states exactly what `talon agents show <name> --effective --json` states
// (one projection, computed in Go), a use case whose only traffic is at the
// Action Gateway is not presented as an LLM application, and an observed
// record links to its signed evidence.
const { test, expect } = require("@playwright/test");
const { state, pair, cli } = require("./helpers.js");

test.describe.configure({ mode: "serial" });

const LABEL = { llm_gateway: "LLM gateway", mcp_proxy: "MCP proxy", action_gateway: "Action Gateway" };

test("every use case: the console's reading and observations equal the CLI's", async ({ page }) => {
  const fleet = cli(["agents", "--json"]);
  expect(fleet.agents.length).toBeGreaterThan(2);
  await pair(page, "/use-cases");
  const seen = new Set();
  for (const a of fleet.agents) {
    const report = cli(["agents", "show", a.name, "--effective", "--json"]);
    const v = report.verification;
    expect(v, `${a.name}: the CLI report carries the verification section`).toBeTruthy();
    seen.add(v.reading.code);
    await page.goto(`/use-cases/${encodeURIComponent(a.name)}?tenant=${encodeURIComponent(a.tenant_id)}`);
    // Summary: the one-line reading.
    const summary = page.getByTestId("connection-reading").locator("[data-code]");
    await expect(summary).toHaveAttribute("data-code", v.reading.code);
    await expect(summary).toContainText(v.reading.text);
    // Policy & Runtime: one row per boundary with the CLI's state.
    const section = page.getByTestId("verification");
    await expect(section.getByTestId("verification-reading")).toHaveText(v.reading.text);
    for (const o of v.traffic) {
      const row = section.locator(`tr[data-boundary="${o.boundary}"]`);
      await expect(row).toHaveAttribute("data-state", o.state);
      await expect(row.locator("td").first()).toContainText(LABEL[o.boundary]);
      if (o.state === "observed") {
        // Authenticated only where the record establishes the use case's
        // own credential; an MCP proxy record does not.
        await expect(row.getByText(o.identity_proven ? "Observed, authenticated" : "Observed, caller's identity not established")).toBeVisible();
        if (o.boundary === "mcp_proxy") expect(o.identity_proven).toBe(false);
        await expect(row.getByRole("link", { name: o.evidence_id })).toBeVisible();
        await expect(row.getByText(o.verification === "valid" ? "Signature valid" : "Signature invalid")).toBeVisible();
      } else if (o.state === "none") {
        await expect(row.getByText("None recorded")).toBeVisible();
      }
    }
    // The last decision is the newest observation, never an operator event.
    if (report.last_decision) {
      const observed = v.traffic.filter((o) => o.state === "observed").map((o) => o.evidence_id);
      expect(observed).toContain(report.last_decision.evidence_id);
    }
  }
  // The fixture exercises more than one reading.
  expect(seen.size).toBeGreaterThan(1);
});

test("an action-only use case is not presented as an LLM application; the observed record opens as signed evidence", async ({ page }) => {
  const a = state().fixture.action;
  const report = cli(["agents", "show", a.use_case, "--effective", "--json"]);
  const by = Object.fromEntries(report.verification.traffic.map((o) => [o.boundary, o]));
  expect(by.action_gateway.state).toBe("observed");
  expect(by.llm_gateway.state).toBe("none");
  expect(report.verification.not_established.join("\n")).toContain("no authenticated LLM gateway request of this use case is recorded");

  await pair(page, `/use-cases/${a.use_case}?tenant=default`);
  const section = page.getByTestId("verification");
  await expect(section.locator('tr[data-boundary="llm_gateway"]')).toHaveAttribute("data-state", "none");
  const action = section.locator('tr[data-boundary="action_gateway"]');
  await expect(action).toHaveAttribute("data-state", "observed");
  await expect(action.getByText("Establishing or authorizing an operation is not dispatching it", { exact: false })).toBeVisible();
  await section.getByText("What these observations do not establish").click();
  await expect(section.getByText("that all of this application's requests go through Talon", { exact: false })).toBeVisible();
  await action.getByRole("link", { name: by.action_gateway.evidence_id }).click();
  await expect(page).toHaveURL(new RegExp(`/evidence/${by.action_gateway.evidence_id}`));
  await expect(page.getByText("Signature valid").first()).toBeVisible();
});
