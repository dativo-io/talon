import type { EvidenceRecord, Outcome, SessionSummary, Verification } from "../api/types";
import { outcomeStory } from "./outcome";

// Facts sorted into the three proof categories of ProofBoundary (#533 PR 2).
// Only facts the record or summary actually carries are listed; a category
// with nothing in it says so instead of being filled.
export interface ProofLists {
  verified: string[];
  reported: string[];
  notVerified: string[];
  signatureInvalid: boolean;
}

const OUTSIDE = [
  "Actions the application took without going through Talon's LLM gateway or MCP proxy (local commands, file edits, direct API calls).",
  "Whether a business operation outside Talon completed (for example a refund executed or a reply delivered).",
  "Application-internal steps Talon did not intercept.",
];

interface Orchestration {
  session_id?: string;
  agent_id?: string;
  parent_agent_id?: string;
  client?: string;
  session_source?: string;
}

export function evidenceProof(r: EvidenceRecord, o: Outcome | undefined, v: Verification | undefined): ProofLists {
  const story = outcomeStory(o);
  const verified = [
    `AI use case ${r.agent_id} in tenant ${r.tenant_id}, as Talon resolved it at its boundary.`,
    `Talon's decision: ${r.policy_decision.allowed ? "allowed" : "denied"} (${r.policy_decision.action}).`,
    `${story.headline}: ${story.detail}`,
  ];
  if (r.execution.model_used) verified.push(`Recorded model route: ${r.execution.model_used}${r.failover ? ` (${r.failover.role.replace(/_/g, " ")}, provider ${r.failover.provider})` : ""}.`);
  if (r.execution.tools_called && r.execution.tools_called.length > 0) verified.push(`Intercepted tool call: ${r.execution.tools_called.join(", ")}.`);
  verified.push(
    r.execution.cost > 0
      ? `Recorded cost: ${r.execution.cost} ${r.execution.currency || "(no currency recorded)"}${r.execution.pricing_known === false ? ", without a pricing-table price" : ""}.`
      : "Recorded cost: none (no provider cost was recorded for this record).",
  );
  verified.push(v ? (v.state === "valid" ? "Signature: valid when checked by this console." : "Signature: INVALID — the record changed after signing.") : "Signature: not checked.");

  const reported: string[] = [];
  const orch = (r.orchestration ?? {}) as Orchestration;
  if (r.session_id && (orch.session_source === "client_asserted" || orch.session_source === "vendor_asserted")) {
    reported.push(`Session id ${r.session_id}: ${orch.session_source === "vendor_asserted" ? "asserted by the client's adapter" : "asserted by the client"}${orch.client ? ` (${orch.client})` : ""}. Talon grouped the record under it; it did not create or authenticate it.`);
  }
  if (orch.agent_id) reported.push(`Sub-agent ${orch.agent_id}${orch.parent_agent_id ? ` spawned by ${orch.parent_agent_id}` : ""}, as the client asserted.`);
  if (r.request_source_id) reported.push(`Request source ${r.request_source_id}, as the caller stated it.`);

  const what = o?.tool ? `${o.tool}` : "the request";
  const notVerified = [`What the destination did with ${what} beyond the answer Talon recorded.`, ...OUTSIDE];
  return { verified, reported, notVerified, signatureInvalid: v?.state === "invalid" };
}

export function sessionProof(s: SessionSummary, managed: boolean, tenant: string): ProofLists {
  const verified = [
    `AI use case${(s.agents ?? []).length === 1 ? "" : "s"} ${(s.agents ?? []).join(", ") || "(none recorded)"} in tenant ${tenant}, as Talon resolved ${(s.agents ?? []).length === 1 ? "it" : "them"} at its boundary.`,
    `${s.allowed} allowed and ${s.denied} denied decisions by Talon over ${s.record_count} signed records; each timeline row states dispatch and the destination's answer as far as recorded.`,
  ];
  if ((s.provider_path ?? []).length > 0) verified.push(`Recorded provider path: ${(s.provider_path ?? []).join(" → ")}${s.fallbacks ? ` (${s.fallbacks} fallback${s.fallbacks === 1 ? "" : "s"})` : ""}.`);
  if (s.tool_calls) verified.push(`${s.tool_calls} intercepted tool call${s.tool_calls === 1 ? "" : "s"}, ${s.tool_calls_denied ?? 0} denied by Talon.`);
  verified.push(`Recorded cost: ${s.cost_comparable === false ? "not a sum in one currency" : `${s.total_cost} ${s.currency ?? ""}`.trim()}.`);
  verified.push(managed ? "Session lifecycle: tracked by Talon's session store." : "No lifecycle tracked: the session exists only as an id on evidence records.");

  const reported: string[] = [];
  if (s.session_source === "client_asserted" || s.session_source === "vendor_asserted") {
    reported.push(`Session id ${s.session_id}: ${s.session_source === "vendor_asserted" ? "asserted by the client's adapter" : "asserted by the client"}${s.client ? ` (${s.client})` : ""}. Grouping records under it is attribution, not authentication, and no lifecycle is inferred from it.`);
  }
  return { verified, reported, notVerified: ["What each destination did beyond the answers Talon recorded.", ...OUTSIDE], signatureInvalid: false };
}
