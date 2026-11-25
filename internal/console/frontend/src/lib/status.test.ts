import { describe, expect, it } from "vitest";
import { claimsNoFinding, statusFor, statusTone } from "./status";
import type { UseCaseStatus, UseCaseStatusCode, UseCaseStatuses } from "../api/types";

const codes: UseCaseStatusCode[] = [
  "working",
  "disabled",
  "not_active",
  "runtime_not_confirmed",
  "waiting_for_first_request",
  "needs_attention",
  "blocked",
  "not_determined",
];

const item = (name: string, tenant: string, code: UseCaseStatusCode): UseCaseStatus => ({ name, tenant_id: tenant, code, headline: code });

// #575: the status is Go's; the browser only colours it. Green is "working"
// alone: unknown stays unknown, and a use case nothing serves is not fine.
describe("use-case status presentation", () => {
  it("is green only when working", () => {
    for (const c of codes) expect(statusTone(c) === "ok").toBe(c === "working");
    expect(statusTone(undefined)).toBe("info");
    expect(statusTone("a_code_this_build_does_not_know")).toBe("info");
  });
  it("finds the status of a use case by tenant and name", () => {
    const s: UseCaseStatuses = { availability: { state: "ok", source: "config_files" }, items: [item("bot", "acme", "blocked"), item("bot", "default", "working")] };
    expect(statusFor(s, "default", "bot")?.code).toBe("working");
    expect(statusFor(s, "acme", "bot")?.code).toBe("blocked");
    expect(statusFor(s, "other", "bot")).toBeUndefined();
    expect(statusFor(undefined, "default", "bot")).toBeUndefined();
    expect(statusFor({ ...s, items: null }, "default", "bot")).toBeUndefined();
  });
  it("says 'no finding' only for a working use case", () => {
    for (const c of codes) expect(claimsNoFinding(item("bot", "default", c))).toBe(c === "working");
    expect(claimsNoFinding(undefined)).toBe(false);
  });
});
