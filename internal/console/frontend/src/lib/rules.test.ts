import { describe, expect, it } from "vitest";
import { isMeasurement, viewOf } from "./availability";
import { breakdownRows, fieldValue } from "./costs";
import { money, utc, isZeroTime, relative, goDuration } from "./format";
import type { CostReport } from "../api/types";

const report = (over: Partial<CostReport>): CostReport => ({
  tenant_id: "default",
  currency: "USD",
  window: { day_start: "", day_end: "", month_start: "", month_end: "", week_start: "", week_end: "" },
  today_eur: 1.5,
  month_eur: 12.25,
  seven_days_eur: 4,
  unpriced_records: 0,
  ...over,
});

describe("availability", () => {
  it("only ok, empty and partial sections hold measurements", () => {
    expect(viewOf({ state: "ok", source: "evidence_store" }).measured).toBe(true);
    expect(viewOf({ state: "empty", source: "evidence_store" }).measured).toBe(true);
    expect(viewOf({ state: "partial", source: "evidence_store" }).measured).toBe(true);
    expect(viewOf({ state: "unavailable", source: "evidence_store" }).measured).toBe(false);
    expect(viewOf({ state: "unknown", source: "none" }).measured).toBe(false);
    expect(viewOf(undefined).measured).toBe(false);
  });
  it("a field listed unavailable is not a measurement even in a partial section", () => {
    const a = { state: "partial" as const, source: "evidence_store", unavailable: ["cost"] };
    expect(isMeasurement(a, "cost")).toBe(false);
    expect(isMeasurement(a, "requests")).toBe(true);
    expect(isMeasurement({ state: "ok", source: "x" }, "month_eur", ["month_eur"])).toBe(false);
    expect(isMeasurement({ state: "unavailable", source: "x" }, "requests")).toBe(false);
  });
});

describe("costs", () => {
  it("never surfaces the retained number of an unavailable field", () => {
    const r = report({ unavailable_fields: ["month_eur", "monthly_budget"] });
    expect(fieldValue(r, "month_eur")).toBeNull();
    expect(fieldValue(r, "today_eur")).toBe(1.5);
  });
  it("breakdown rows null out an unavailable window and order by month spend", () => {
    const r = report({
      by_agent_eur: { a: 1, b: 2 },
      by_agent_month_eur: { a: 5, b: 3, c: 9 },
      unavailable_fields: ["by_agent_eur"],
    });
    const rows = breakdownRows(r, "agents");
    expect(rows.map((x) => x.key)).toEqual(["c", "a", "b"]);
    expect(rows.every((x) => x.day === null)).toBe(true);
    expect(rows[0]?.month).toBe(9);
  });
});

describe("format", () => {
  it("formats in the given currency and never converts", () => {
    expect(money(12.5, "USD")).toBe("$12.50");
    expect(money(12.5, "EUR")).toBe("€12.50");
    expect(money(0.0042, "USD")).toBe("$0.0042");
    expect(money(0.0123, "USD")).toBe("$0.0123");
    expect(money(0.5, "USD")).toBe("$0.50");
    expect(money(3, "")).toBe("3.0000 (no currency)");
  });
  it("treats Go's zero time as unset", () => {
    expect(isZeroTime("0001-01-01T00:00:00Z")).toBe(true);
    expect(utc("0001-01-01T00:00:00Z")).toBe("—");
    expect(relative("0001-01-01T00:00:00Z")).toBe("never");
    expect(utc("2026-11-09T10:11:12.345Z")).toBe("2026-11-09 10:11:12 UTC");
  });
});

describe("goDuration", () => {
  it("renders Go duration strings compactly", () => {
    expect(goDuration("1h0m0s")).toBe("1h");
    expect(goDuration("24h0m0s")).toBe("24h");
    expect(goDuration("30m0s")).toBe("30m");
    expect(goDuration("1h30m0s")).toBe("1h30m");
  });
});
