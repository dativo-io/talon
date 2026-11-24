import { describe, expect, it } from "vitest";
import { installationEventView } from "./installation";
import { evidenceProof } from "./proof";
import type { EvidenceRecord } from "../api/types";

describe("installationEventView", () => {
  it("a rejected reload reads as rejected, never as a denied request", () => {
    const v = installationEventView("config_reload", false);
    expect(v.label).toBe("Configuration reload");
    expect(v.outcome).toBe("Rejected");
    expect(v.tone).toBe("warn");
    expect(v.detail).toContain("kept serving its active generation");
    expect(`${v.outcome} ${v.detail}`).not.toMatch(/denied|tenant/i);
  });
  it("an activated reload reads as activated", () => {
    expect(installationEventView("config_reload", true)).toMatchObject({ outcome: "Activated", tone: "ok" });
  });
  it("backup recovery and the legacy mode change are named", () => {
    expect(installationEventView("recovery_resumed", true)).toMatchObject({ label: "Recovery resumed", outcome: "Hold ended" });
    expect(installationEventView("mode_change", true).detail).toContain("removed in v1.15.0");
  });
  it("an unknown installation type is shown as recorded, not invented", () => {
    expect(installationEventView("future_event", true)).toMatchObject({ label: "future_event", outcome: "Recorded", detail: "" });
  });
});

const reload = (allowed: boolean): EvidenceRecord =>
  ({
    id: "cr_1", correlation_id: "cr_1", timestamp: "2026-11-23T12:00:00Z", tenant_id: "system", agent_id: "talon-serve", invocation_type: "config_reload",
    request_source_id: "reload_loop", policy_decision: { allowed, action: allowed ? "allow" : "deny", reasons: [] }, execution: { cost: 0, duration_ms: 0 },
  }) as unknown as EvidenceRecord;

describe("evidenceProof for an installation event", () => {
  it("names the Talon process and the namespace, never an AI use case in a tenant or a request", () => {
    const p = evidenceProof(reload(false), { decision: "denied", dispatch: "not_recorded", downstream: "none", basis: "x" }, { state: "valid", checked_at: "" }, true);
    const all = [...p.recorded, ...p.reported, ...p.notVerified].join(" ");
    expect(p.trust).toBe("signature_verified");
    expect(p.recorded[0]).toContain("Talon process talon-serve");
    expect(p.recorded[0]).toContain("not an AI use case and not a tenant");
    expect(p.recorded[1]).toBe("Recorded outcome: Configuration reload, rejected (deny).");
    expect(all).not.toMatch(/AI use case talon-serve|in tenant system|the request|destination/);
    expect(p.recorded).toContain("Signature: valid when checked by this console.");
  });
  it("a tampered installation record is a claim, with no story", () => {
    const p = evidenceProof(reload(true), undefined, { state: "invalid", checked_at: "" }, true);
    expect(p.trust).toBe("signature_invalid");
    expect(p.recorded[1]).toMatch(/^Outcome the record claims/);
    expect(p.recorded.join(" ")).not.toContain("activated a new generation");
  });
  it("an ordinary record is unchanged", () => {
    const p = evidenceProof({ ...reload(true), tenant_id: "default", agent_id: "hr-analytics-assistant", invocation_type: "gateway" } as EvidenceRecord, undefined, undefined);
    expect(p.recorded[0]).toBe("AI use case hr-analytics-assistant in tenant default, as Talon resolved it at its boundary.");
  });
});
