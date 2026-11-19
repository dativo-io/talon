import { describe, expect, it } from "vitest";
import { attentionCount, basisLabel, countParts, eligibilityView, expiresIn, outcomeText, whyText } from "./approvals";
import type { ApprovalView, Eligibility } from "../api/types";

const e = (over: Partial<Eligibility>): Eligibility => ({ state: "eligible", class: "actionable", basis: "runtime_confirmed", explanation: "", policy: "unchanged", definition: "unchanged", ...over });

const view = (over: Partial<ApprovalView>): ApprovalView => ({
  approval_id: "apr_1", tenant: "default", use_case: "refund-bot", action: "create_refund_request", status: "pending", unresolved: true,
  eligibility: e({}), approver_groups: ["support-leads"], created_at: "2026-11-19T12:00:00Z", expires_at: "2026-11-19T12:30:00Z",
  disclosure: "operational", arguments: [{ name: "amount" }],
  bound: { rule_id: "refund-needs-approval", rule_source: "use_case", destination: "POST http://127.0.0.1:9", definition_digest: "d", policy_digest: "p", established_at: "2026-11-19T12:00:00Z" },
  current: { basis: "runtime_confirmed", rule: "use_case argument rule refund-needs-approval: …", rule_present: true },
  operation: { operation_id: "op", operation_ref: "op_1", status: "awaiting_approval", verdict: "REQUIRE_APPROVAL", attempt_count: 0, updated_at: "2026-11-19T12:00:00Z" },
  after_approval: "", ...over,
});

describe("approval wording", () => {
  it("never calls a files-only answer decidable", () => {
    expect(eligibilityView(e({}), "pending").label).toBe("Can be decided now");
    expect(eligibilityView(e({ class: "potentially_actionable", basis: "current_files" }), "pending").label).toBe("Eligible per current files");
    expect(basisLabel("current_files")).toContain("not proven");
    expect(eligibilityView(e({ class: "unknown", state: "unknown" }), "pending").label).toBe("Eligibility unknown");
    expect(eligibilityView(e({ class: "not_decidable", state: "expired" }), "pending").label).toBe("Expired, not decidable");
    expect(eligibilityView(e({ class: "decided", state: "decided" }), "rejected").label).toBe("Rejected");
  });

  it("keeps stored counts apart from inferred ones and never renders a missing count as zero", () => {
    expect(countParts(undefined)).toEqual(["unavailable"]);
    expect(countParts({ unresolved: 3 })).toEqual(["3 unresolved in the store", "eligibility not established"]);
    expect(countParts({ unresolved: 3, eligibility: { actionable: 0, potentially_actionable: 2, not_decidable: 1, unknown: 0 } })).toEqual([
      "3 unresolved in the store", "2 eligible per current files", "1 no longer decidable",
    ]);
    expect(attentionCount(undefined)).toBeNull();
    expect(attentionCount({ unresolved: 3 })).toBeNull();
    expect(attentionCount({ unresolved: 0 })).toBe(0);
    expect(attentionCount({ unresolved: 3, eligibility: { actionable: 1, potentially_actionable: 1, not_decidable: 1, unknown: 0 } })).toBe(2);
  });

  it("presents today's rule as the bound rule only when the policy is unchanged", () => {
    expect(whyText(view({})).ruleLabel).toBe("The rule");
    expect(whyText(view({ eligibility: e({ policy: "changed", class: "not_decidable", state: "stale_policy" }) })).ruleLabel).toContain("as it reads today");
    const gone = whyText(view({ current: { basis: "current_files", rule_present: false } }));
    expect(gone.rule).toBeNull();
    expect(gone.ruleLabel).toContain("not recorded");
    expect(whyText(view({})).bound).toBe("Rule refund-needs-approval of the use case's own policy required approval by support-leads.");
  });

  it("claims a destination answer only from a recorded attempt", () => {
    expect(outcomeText(view({}))).toBe("Operation awaiting approval; nothing was dispatched");
    const done = view({ operation: { operation_id: "op", operation_ref: "op_1", status: "succeeded", verdict: "REQUIRE_APPROVAL", attempt_count: 1, updated_at: "", latest_attempt: { ordinal: 1, status: "completed", started_at: "", request_written: true, response_observed: true, http_status: 201, result_provenance: "observed" } } });
    expect(outcomeText(done)).toBe("Operation succeeded; 1 dispatch attempt, latest completed, destination answered HTTP 201 (observed)");
  });

  it("words the remaining lifetime", () => {
    const now = new Date("2026-11-19T12:00:00Z");
    expect(expiresIn("2026-11-19T12:42:10Z", now)).toBe("in 42m");
    expect(expiresIn("2026-11-19T11:59:00Z", now)).toBe("expired");
    expect(expiresIn("2026-11-19T15:00:00Z", now)).toBe("in 3h");
  });
});
