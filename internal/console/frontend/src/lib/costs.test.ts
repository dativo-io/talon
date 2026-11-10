import { describe, expect, it } from "vitest";
import { budgetUsage } from "./costs";
import type { BudgetUsage, CostReport } from "../api/types";

const usage: BudgetUsage = { used_eur: 80, limit_eur: 100, percent: 80, status: "WARNING", source: "agent" } as BudgetUsage;
const report = (over: Partial<CostReport>): CostReport => ({ currency: "EUR", unpriced_records: 0, monthly_budget: usage, ...over }) as CostReport;

// #558 review P1: a budget listed in unavailable_fields (spend in a currency
// the cap cannot be compared with) must not yield a percentage.
describe("budgetUsage", () => {
  it("returns the backend utilization when the budget is comparable", () => {
    expect(budgetUsage(report({}), "monthly_budget")?.percent).toBe(80);
  });
  it("returns null when the report lists the budget as unavailable, even if a stale value is present", () => {
    expect(budgetUsage(report({ unavailable_fields: ["monthly_budget"] }), "monthly_budget")).toBeNull();
  });
  it("returns undefined when no effective cap is reported", () => {
    expect(budgetUsage(report({ monthly_budget: undefined }), "monthly_budget")).toBeUndefined();
  });
});
