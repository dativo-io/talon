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
    expect(p.recorded.join(" ")).toContain("never received it");
    expect(p.recorded.join(" ")).toContain("Recorded cost: none");
    expect(p.reported).toEqual([]);
    expect(p.notVerified.join(" ")).toContain("refund");
    expect(p.trust).toBe("signature_verified");
  });
  it("a client-asserted session id is application-reported, never verified", () => {
    const p = evidenceProof(rec({ session_id: "pa-1", orchestration: { session_source: "client_asserted", client: "generic" } }), undefined, undefined);
    expect(p.reported[0]).toContain("pa-1");
    expect(p.reported[0]).toContain("asserted by the client");
    expect(p.recorded.join(" ")).not.toContain("pa-1");
  });
  // #558 review P1: Talon-recorded is not signature-verified.
  it("a record whose signature this console checked is signature-verified", () => {
    expect(evidenceProof(rec({}), undefined, { state: "valid", checked_at: "" }).trust).toBe("signature_verified");
  });
  it("a record whose signature was not checked is only Talon-recorded", () => {
    expect(evidenceProof(rec({}), undefined, undefined).trust).toBe("recorded");
  });
  it("an invalid signature invalidates the record's narrative", () => {
    const p = evidenceProof(rec({}), o({ decision: "denied", dispatch: "not_dispatched", downstream: "none" }), { state: "invalid", checked_at: "" });
    expect(p.trust).toBe("signature_invalid");
    expect(p.recorded.join(" ")).not.toContain("Talon denied it — not dispatched:");
  });
  it("a session's tenant comes from the session, not an empty all-tenants scope", () => {
    const s = { session_id: "s", tenant_id: "default", record_count: 1, allowed: 1, denied: 0, agents: ["a"], total_cost: 0 } as unknown as SessionSummary;
    expect(sessionProof(s, false, "").recorded[0]).toContain("in tenant default,");
  });
  it("a session summary is Talon-recorded, never signature-verified (no per-record check)", () => {
    const s = { session_id: "s", record_count: 2, allowed: 2, denied: 0, agents: ["a"], total_cost: 0 } as unknown as SessionSummary;
    const p = sessionProof(s, false, "default");
    expect(p.trust).toBe("recorded");
    expect(p.recorded.join(" ")).not.toContain("signed records");
  });
  it("a session's cost in several currencies is not summed", () => {
    const s = { session_id: "s", record_count: 2, allowed: 2, denied: 0, agents: ["a"], cost_comparable: false, total_cost: 3 } as unknown as SessionSummary;
    expect(sessionProof(s, false, "default").recorded.join(" ")).toContain("not a sum in one currency");
  });
});

// #558 review P1: the wording must hold for every record type that maps to
// the canonical outcome, not just the MCP proxy and the model gateway.
describe("outcomeStory claims no more than every record type supports", () => {
  it("dispatch unknown from an action lifecycle record does not claim a hand-off to the transport", () => {
    const s = outcomeStory(o({ dispatch: "unknown", downstream: "unknown", basis: "action lifecycle: result provenance unknown" }));
    expect(s.headline).toBe("Outcome unknown");
    expect(s.detail).not.toMatch(/transport/i);
    expect(s.detail).toContain("does not establish whether");
    expect(s.detail).toContain("action lifecycle: result provenance unknown");
  });
  it("a failed Action Gateway attempt does not claim a provider HTTP status", () => {
    const s = outcomeStory(o({ dispatch: "dispatched", downstream: "failed", basis: "action lifecycle: result observed, attempt failed" }));
    expect(s.headline).toBe("Talon allowed it — dispatched — attempt failed");
    expect(s.detail).not.toMatch(/provider|HTTP/i);
    expect(s.detail).toContain("action lifecycle: result observed, attempt failed");
  });
  it("an allowed but not-dispatched action does not assume why it was not sent", () => {
    const s = outcomeStory(o({ dispatch: "not_dispatched", downstream: "none", basis: "action lifecycle: result provenance not_dispatched" }));
    expect(s.headline).toBe("Talon allowed it — not dispatched");
    expect(s.detail).not.toMatch(/failed/i);
    expect(s.detail).toContain("never received it");
  });
});
