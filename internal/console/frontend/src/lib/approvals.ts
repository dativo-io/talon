import type { ApprovalCounts, ApprovalView, Binding, Eligibility } from "../api/types";
import type { Tone } from "./availability";

// Wording of what the approval DTOs carry. Nothing is decided here: the
// class and the basis are Go's (action.classifyApproval). This file keeps
// three statements apart on every page: what the store holds (unresolved),
// what the current configuration FILES say (potentially actionable), and
// what a running process is proven to enforce (actionable).

export interface StateView {
  label: string;
  tone: Tone | "ok" | "accent";
}

const NOT_DECIDABLE: Record<string, string> = {
  expired: "Expired, not decidable",
  stale_policy: "Policy changed, not decidable",
  stale_definition: "Action definition changed, not decidable",
  use_case_not_served: "Use case not served, not decidable",
};

export function eligibilityView(e: Eligibility, status: string): StateView {
  switch (e.class) {
    case "actionable":
      return { label: "Can be decided now", tone: "accent" };
    case "potentially_actionable":
      return { label: "Eligible per current files", tone: "info" };
    case "not_decidable":
      return { label: NOT_DECIDABLE[e.state] ?? "Not decidable", tone: "neutral" };
    case "unknown":
      // The files differ from what the request was bound to, and no running
      // process is proven to run those files: not a refusal.
      if (e.policy === "changed" || e.definition === "changed") return { label: "Files changed, runtime not confirmed", tone: "warn" };
      return { label: "Eligibility unknown", tone: "warn" };
    default:
      return status === "approved"
        ? { label: "Approved", tone: "ok" }
        : status === "rejected"
          ? { label: "Rejected", tone: "error" }
          : { label: status.charAt(0).toUpperCase() + status.slice(1), tone: "neutral" };
  }
}

// basisLabel says what an eligibility statement rests on.
export function basisLabel(basis: string): string {
  switch (basis) {
    case "runtime":
      return "the deciding Talon process";
    case "runtime_confirmed":
      return "the current configuration files, which every running Talon process is proven to have loaded";
    case "current_files":
      return "the current configuration files only (not proven to be what a running process enforces)";
    case "lifetime":
      return "the approval's lifetime";
    case "record":
      return "the stored decision";
    default:
      return "nothing that could be read";
  }
}

export function bindingWord(b: Binding): string {
  return b === "unchanged" ? "unchanged since the request was established" : b === "changed" ? "changed since the request was established" : "cannot be compared here";
}

// expiresIn is a coarse remaining lifetime, or "expired".
export function expiresIn(ts: string, now: Date = new Date()): string {
  const ms = new Date(ts).getTime() - now.getTime();
  if (Number.isNaN(ms)) return "—";
  if (ms <= 0) return "expired";
  const m = Math.floor(ms / 60000);
  if (m < 1) return "in <1m";
  if (m < 60) return `in ${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `in ${h}h`;
  return `in ${Math.floor(h / 24)}d`;
}

// countParts lists the counts with their meaning; an absent eligibility is
// said, never rendered as zeros.
export function countParts(c: ApprovalCounts | undefined | null): string[] {
  if (!c) return ["unavailable"];
  const out = [`${c.unresolved} unresolved in the store`];
  const e = c.eligibility;
  if (!e) {
    if (c.unresolved > 0) out.push("eligibility not established");
    return out;
  }
  if (e.actionable > 0) out.push(`${e.actionable} can be decided now`);
  if (e.potentially_actionable > 0) out.push(`${e.potentially_actionable} eligible per current files`);
  if (e.unknown > 0) out.push(`${e.unknown} of unknown eligibility`);
  if (e.not_decidable > 0) out.push(`${e.not_decidable} no longer decidable`);
  return out;
}

// attention: unresolved approvals not known to be undecidable; null when
// that cannot be said.
export function attentionCount(c: ApprovalCounts | undefined | null): number | null {
  if (!c) return null;
  if (!c.eligibility) return c.unresolved === 0 ? 0 : null;
  return c.eligibility.actionable + c.eligibility.potentially_actionable + c.eligibility.unknown;
}

// whyText words why approval was required. Today's rule text is called the
// rule that required the approval only when the policy is unchanged.
export function whyText(v: ApprovalView): { bound: string; rule: string | null; ruleLabel: string } {
  const layer = v.bound.rule_source === "company" ? "company policy" : v.bound.rule_source === "use_case" ? "use case's own policy" : "policy";
  const bound = `Rule ${v.bound.rule_id ?? "(none recorded)"} of the ${layer} required approval by ${v.approver_groups.join(" or ") || "(no group recorded)"}.`;
  if (!v.current.rule_present || !v.current.rule) {
    return { bound, rule: null, ruleLabel: "The rule's text at that time is not recorded, and the current configuration has no rule with this id." };
  }
  if (v.eligibility.policy === "unchanged") return { bound, rule: v.current.rule, ruleLabel: "The rule" };
  return { bound, rule: v.current.rule, ruleLabel: "The rule as it reads today (not necessarily as it read then)" };
}

// outcomeText says what happened to the operation, from recorded dispatch
// facts only.
export function outcomeText(v: ApprovalView): string {
  const op = v.operation;
  let out = `Operation ${op.status.replace(/_/g, " ")}`;
  if (op.attempt_count === 0) out += "; nothing was dispatched";
  else if (op.latest_attempt) {
    const at = op.latest_attempt;
    out += `; ${op.attempt_count} dispatch attempt${op.attempt_count === 1 ? "" : "s"}, latest ${at.status}`;
    if (at.http_status) out += `, destination answered HTTP ${at.http_status}`;
    if (at.result_provenance) out += ` (${at.result_provenance})`;
  }
  return out;
}
