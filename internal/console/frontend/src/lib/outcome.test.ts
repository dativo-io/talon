import { describe, expect, it } from "vitest";
import { outcomeStory } from "./outcome";
import type { Outcome } from "../api/types";

const o = (over: Partial<Outcome>): Outcome => ({ decision: "allowed", dispatch: "dispatched", downstream: "completed", basis: "test", ...over });

describe("outcomeStory", () => {
  it("a denied, not-dispatched tool call never reached the destination", () => {
    const s = outcomeStory(o({ decision: "denied", dispatch: "not_dispatched", downstream: "none", tool: "hr_employee_export" }));
    expect(s.headline).toBe("Talon denied it — not dispatched");
    expect(s.detail).toContain("hr_employee_export");
    expect(s.detail).toContain("never received it");
  });
  it("an allowed call the destination refused is not a Talon denial", () => {
    const s = outcomeStory(o({ downstream: "rejected", tool: "hr_aggregate_sql" }));
    expect(s.headline).toBe("Talon allowed it — dispatched — destination rejected it");
    expect(s.detail).toContain("not a Talon denial");
  });
  it("claims a destination answer only when dispatch and downstream both say so", () => {
    expect(outcomeStory(o({})).headline).toContain("destination responded");
    expect(outcomeStory(o({ dispatch: "unknown", downstream: "unknown" })).headline).toBe("Outcome unknown");
    expect(outcomeStory(o({ dispatch: "not_recorded", downstream: "not_recorded" })).headline).not.toContain("responded");
    expect(outcomeStory(o({ dispatch: "dispatched", downstream: "unknown" })).headline).not.toContain("responded");
  });
  it("a cache hit made no destination call", () => {
    expect(outcomeStory(o({ dispatch: "not_dispatched", downstream: "cache" })).detail).toContain("no destination was called");
  });
  it("an answer withheld after dispatch says the destination answered and Talon withheld it", () => {
    expect(outcomeStory(o({ decision: "denied", response_withheld: true })).headline).toBe("Dispatched — answer withheld by Talon");
  });
  it("no outcome is not invented", () => {
    expect(outcomeStory(undefined).headline).toBe("Outcome not recorded");
  });
});

import { evidenceProof, sessionProof } from "./proof";
import type { EvidenceRecord, SessionSummary } from "../api/types";

const rec = (over: Partial<EvidenceRecord>): EvidenceRecord => ({
  id: "e1", correlation_id: "c1", timestamp: "2026-01-01T00:00:00Z", tenant_id: "default", agent_id: "hr", invocation_type: "proxy_tool_blocked",
  policy_decision: { allowed: false, action: "deny", policy_version: "" },
  execution: { model_used: "", cost: 0, duration_ms: 1 }, signature: "s", ...over,
});

describe("proof boundaries", () => {
  it("a denied export: verified decision and not-dispatched outcome, zero cost, nothing application-reported", () => {
    const p = evidenceProof(rec({}), o({ decision: "denied", dispatch: "not_dispatched", downstream: "none", tool: "hr_employee_export" }), { state: "valid", checked_at: "" });
    expect(p.verified.join(" ")).toContain("never received it");
    expect(p.verified.join(" ")).toContain("Recorded cost: none");
    expect(p.reported).toEqual([]);
    expect(p.notVerified.join(" ")).toContain("refund");
    expect(p.signatureInvalid).toBe(false);
  });
  it("a client-asserted session id is application-reported, never verified", () => {
    const p = evidenceProof(rec({ session_id: "pa-1", orchestration: { session_source: "client_asserted", client: "generic" } }), undefined, undefined);
    expect(p.reported[0]).toContain("pa-1");
    expect(p.reported[0]).toContain("asserted by the client");
    expect(p.verified.join(" ")).not.toContain("pa-1");
  });
  it("an invalid signature is flagged", () => {
    expect(evidenceProof(rec({}), undefined, { state: "invalid", checked_at: "" }).signatureInvalid).toBe(true);
  });
  it("a session's cost in several currencies is not summed", () => {
    const s = { session_id: "s", record_count: 2, allowed: 2, denied: 0, agents: ["a"], cost_comparable: false, total_cost: 3 } as unknown as SessionSummary;
    expect(sessionProof(s, false, "default").verified.join(" ")).toContain("not a sum in one currency");
  });
});
