import { Link } from "react-router-dom";
import type { ApprovalCounts, ApprovalsSummary, Eligibility } from "../api/types";
import { attentionCount, countParts, eligibilityView } from "../lib/approvals";
import { scoped } from "../lib/scope";
import { AvailabilityNotice, Badge, SourceFreshness } from "./ui";

// EligibilityBadge: the class Go computed, worded once for every page.
export function EligibilityBadge({ e, status }: { e: Eligibility; status: string }) {
  const v = eligibilityView(e, status);
  return <Badge tone={v.tone} title={e.explanation}>{v.label}</Badge>;
}

// ApprovalCountsText: the stored count first, then the inferred classes,
// each named. A count that could not be established is said so.
export function ApprovalCountsText({ c }: { c: ApprovalCounts | undefined | null }) {
  return <span>{countParts(c).join(" · ")}</span>;
}

// ApprovalsCard: the approval section of the Overview page.
export function ApprovalsCard({ a, tenant }: { a: ApprovalsSummary | undefined; tenant: string }) {
  if (!a) return null;
  const attention = attentionCount(a.total);
  const rows = (a.use_cases ?? []).filter((u) => u.unresolved > 0);
  return (
    <section className="card" aria-labelledby="approvals-title" data-testid="approvals-card">
      <div className="card-head">
        <h2 id="approvals-title">Approvals</h2>
        <Link to={scoped("/approvals", tenant)} className="small">Open Approvals →</Link>
      </div>
      <div className="card-body stack">
        <AvailabilityNotice a={a.availability} what="Approval counts" />
        {a.total ? (
          <p data-testid="approvals-total">
            <strong>
              {attention === null ? "Unresolved approvals: eligibility not established" : attention === 0 ? "No approval awaits a decision" : `${attention} approval${attention === 1 ? "" : "s"} may await a decision`}
            </strong>
            <span className="small muted"> — <ApprovalCountsText c={a.total} /></span>
          </p>
        ) : null}
        {rows.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>AI use case</th><th>Approvals</th><th /></tr></thead>
              <tbody>
                {rows.map((u) => (
                  <tr key={`${u.tenant_id}/${u.use_case}`}>
                    <td><Link to={scoped(`/use-cases/${encodeURIComponent(u.use_case)}`, u.tenant_id)}>{u.use_case}</Link> <span className="small muted">{u.tenant_id}</span></td>
                    <td className="small"><ApprovalCountsText c={u} /></td>
                    <td><Link to={scoped("/approvals", u.tenant_id, { use_case: u.use_case })} className="small">Open</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        <details>
          <summary className="small">How these counts are established</summary>
          <p className="small muted">
            “Unresolved in the store” is read from the store. Whether an unresolved approval can still be decided is inferred from the current configuration files:
            it reads “can be decided now” only where every running Talon process is proven to have loaded those files, “eligible per current files” otherwise, and
            “unknown” where the files cannot say. The console decides nothing; a decision is taken with an approver credential (<code>talon approvals list</code>).
          </p>
        </details>
        <SourceFreshness a={a.availability} />
      </div>
    </section>
  );
}

// UseCaseApprovalsCell: the indicator on an AI use case row. Kept apart
// from fleet health, which it does not change.
export function UseCaseApprovalsCell({ a, tenant, name }: { a: ApprovalsSummary | undefined; tenant: string; name: string }) {
  if (!a || a.availability.state === "unavailable") return <span className="muted">unavailable</span>;
  const u = (a.use_cases ?? []).find((x) => x.use_case === name && x.tenant_id === tenant);
  if (!u || u.unresolved === 0) return <span className="muted">none</span>;
  const attention = attentionCount(u);
  return (
    <Link to={scoped("/approvals", tenant, { use_case: name })} title={countParts(u).join(" · ")}>
      {attention === null ? `${u.unresolved} unresolved` : attention > 0 ? `${attention} may await a decision` : `${u.unresolved} unresolved, none decidable`}
    </Link>
  );
}
