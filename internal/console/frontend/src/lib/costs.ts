import type { AgentRow, BudgetUsage, CostReport } from "../api/types";

// Field names of the cost report. The `_eur` suffix is historical: the unit
// of every amount is CostReport.currency.

export type Breakdown = "agents" | "model" | "provider" | "team";

export const BREAKDOWN_FIELDS: Record<Breakdown, { day: keyof CostReport; month: keyof CostReport; label: string }> = {
  agents: { day: "by_agent_eur", month: "by_agent_month_eur", label: "AI use case" },
  model: { day: "by_model_eur", month: "by_model_month_eur", label: "Model" },
  provider: { day: "by_provider_eur", month: "by_provider_month_eur", label: "Provider" },
  team: { day: "by_team_eur", month: "by_team_month_eur", label: "Team" },
};

export interface BreakdownRow {
  key: string;
  day: number | null; // null: not a measurement (field unavailable)
  month: number | null;
}

// breakdownRows lists the keys of both windows, ordered by month amount
// descending then name. A window listed in unavailable_fields yields null,
// never its retained number.
export function breakdownRows(r: CostReport, b: Breakdown): BreakdownRow[] {
  const f = BREAKDOWN_FIELDS[b];
  const unavailable = new Set(r.unavailable_fields ?? []);
  const day = (r[f.day] as Record<string, number> | undefined) ?? {};
  const month = (r[f.month] as Record<string, number> | undefined) ?? {};
  const dayOk = !unavailable.has(String(f.day));
  const monthOk = !unavailable.has(String(f.month));
  const keys = Array.from(new Set([...Object.keys(day), ...Object.keys(month)]));
  const rows = keys.map((key) => ({
    key,
    day: dayOk ? (day[key] ?? 0) : null,
    month: monthOk ? (month[key] ?? 0) : null,
  }));
  rows.sort((a, b2) => (b2.month ?? -1) - (a.month ?? -1) || a.key.localeCompare(b2.key));
  return rows;
}

export function fieldValue(r: CostReport, field: "today_eur" | "seven_days_eur" | "month_eur"): number | null {
  return (r.unavailable_fields ?? []).includes(field) ? null : r[field];
}

// budgetUsage is a report's budget utilization, or null when the report lists
// that budget in unavailable_fields (spend in a currency the cap cannot be
// compared with): the percentage must then not be shown at all. undefined
// means no effective cap was reported.
export function budgetUsage(r: CostReport, field: "daily_budget" | "monthly_budget"): BudgetUsage | null | undefined {
  return (r.unavailable_fields ?? []).includes(field) ? null : r[field];
}

// warningsFor returns the report warnings that mention the given window
// name, so an unavailable figure can show its own reason.
export function warningsFor(r: CostReport, needles: string[]): string[] {
  return (r.warnings ?? []).filter((w) => needles.some((n) => w.includes(n)));
}

// rowSpend is a fleet row's spend for one period, or null when the row says
// that period's priced records are not comparable with its currency.
export function rowSpend(r: AgentRow, period: "spend_day" | "spend_month"): number | null {
  return (r.unavailable_fields ?? []).includes(period) ? null : r[period];
}
