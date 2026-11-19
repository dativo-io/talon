import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { ApprovalDetail as DetailDTO, ApprovalView } from "../api/types";
import { PageHead } from "../components/Layout";
import { Breadcrumbs, scopeCrumb } from "../components/Breadcrumbs";
import { EligibilityBadge } from "../components/Approvals";
import { AvailabilityNotice, Badge, Chips, CopyableIdentifier, DetailSection, EmptyState, ErrorState, Loading } from "../components/ui";
import { basisLabel, bindingWord, expiresIn, outcomeText, whyText } from "../lib/approvals";
import { humanize, utc, utcShort } from "../lib/format";
import { outcomeStory } from "../lib/outcome";
import { scoped, useScope } from "../lib/scope";

// sentence capitalizes the first letter of a Go-built explanation.
function sentence(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

// ApprovalDetail answers, in this order: what is asked and by whom, can it
// still be decided, which arguments it carries (names only), where it would
// go, why approval is required, whether the configuration it was
// established under is still current, what was decided and what happened,
// and how an approver decides (CLI). Identifiers and digests are under
// "Technical details". The page has no decision control.
export function ApprovalDetail() {
  const { id = "" } = useParams();
  const { tenant } = useScope();
  const res = useApi<DetailDTO>(api(`/approvals/${encodeURIComponent(id)}`), { tenant });
  const d = res.data;
  const v = d?.approval;
  const scopeTenant = d?.meta.tenant_id ?? tenant;
  return (
    <>
      <Breadcrumbs
        items={[
          scopeCrumb(tenant),
          ...(v ? [{ label: v.use_case, to: scoped(`/use-cases/${encodeURIComponent(v.use_case)}`, scopeTenant) }] : []),
          { label: "Approvals", to: scoped("/approvals", scopeTenant, v ? { use_case: v.use_case } : undefined) },
          { label: id },
        ]}
      />
      <PageHead
        title={v ? (v.action_description || v.action) : "Approval"}
        lede={v ? <>Requested by AI use case <Link to={scoped(`/use-cases/${encodeURIComponent(v.use_case)}`, scopeTenant)}>{v.use_case}</Link> in tenant {v.tenant} · action <code>{v.action}</code></> : undefined}
        actions={<button type="button" onClick={res.reload} disabled={res.loading}>Refresh</button>}
      />
      {res.error ? <ErrorState error={res.error} what="the approval" onRetry={res.reload} /> : null}
      {!d && res.loading ? <Loading what="approval" /> : null}
      {d && v ? <Body d={d} v={v} tenant={scopeTenant} /> : null}
    </>
  );
}

function Body({ d, v, tenant }: { d: DetailDTO; v: ApprovalView; tenant: string }) {
  const why = whyText(v);
  const records = d.lifecycle.records ?? [];
  return (
    <div className="stack" data-testid="approval-detail">
      <AvailabilityNotice a={d.availability} what="The approval" />
      <DetailSection title="Status" id="ap-status">
        <dl className="facts">
          <dt>Can it be decided</dt>
          <dd data-testid="approval-eligibility">
            <EligibilityBadge e={v.eligibility} status={v.status} /> <span>{sentence(v.eligibility.explanation)}</span>
          </dd>
          <dt>Stored status</dt>
          <dd>{humanize(v.status)}{v.unresolved ? <span className="small muted"> — unresolved in the store</span> : null}</dd>
          <dt>{v.unresolved ? "Expires" : "Lifetime ended"}</dt>
          <dd title={utc(v.expires_at)}>{utc(v.expires_at)}{v.unresolved ? <span className="small muted"> ({expiresIn(v.expires_at)})</span> : null}</dd>
          <dt>Required reviewer group</dt>
          <dd><Chips items={v.approver_groups} empty="none recorded" /></dd>
        </dl>
      </DetailSection>

      <DetailSection title="Arguments" id="ap-arguments">
        <div className="stack">
          <div><Chips items={v.arguments.map((a) => a.name)} empty="no argument is declared for review" /></div>
          <div className="small muted" data-testid="approval-arguments-note">
            Names only: this console does not receive argument values. An approver of the required group reads the exact values with the CLI.
          </div>
          <CopyableIdentifier value={d.commands.show} label="command to read the exact arguments" />
        </div>
      </DetailSection>

      <DetailSection title="Why approval is required" id="ap-why">
        <div className="stack">
          <div>{why.bound}</div>
          {why.rule ? <div><span className="muted">{why.ruleLabel}:</span> {why.rule}</div> : <div className="muted">{why.ruleLabel}</div>}
        </div>
        <dl className="facts ap-facts">
          <dt>Policy</dt><dd>{bindingWord(v.eligibility.policy)}</dd>
          <dt>Action definition</dt><dd>{bindingWord(v.eligibility.definition)}</dd>
          <dt>Trusted destination</dt>
          <dd>
            {v.bound.destination || <span className="muted">not recorded</span>} <span className="small muted">(bound when the request was established; method and host)</span>
            {v.eligibility.definition === "changed" && v.current.destination ? <div className="small">Today: {v.current.destination}</div> : null}
          </dd>
          <dt>Compared with</dt><dd className="small">{basisLabel(v.current.basis)}{v.current.note ? <div className="muted">{v.current.note}</div> : null}</dd>
        </dl>
      </DetailSection>

      <DetailSection title="Decision and outcome" id="ap-decision">
        <dl className="facts">
          <dt>Decision</dt>
          <dd data-testid="approval-decision">
            {v.decision ? (
              <>
                <Badge tone={v.decision.status === "approved" ? "ok" : v.decision.status === "rejected" ? "error" : "neutral"}>{humanize(v.decision.status)}</Badge>{" "}
                by {v.decision.decided_by || "—"}{v.decision.decided_group ? ` (group ${v.decision.decided_group})` : ""}
                {v.decision.decided_at ? <> at <span title={utc(v.decision.decided_at)}>{utc(v.decision.decided_at)}</span></> : null}
                {v.decision.reason ? <div>Reason given: “{v.decision.reason}”</div> : null}
              </>
            ) : (
              <span>None yet</span>
            )}
          </dd>
          <dt>What happened</dt>
          <dd data-testid="approval-outcome">{outcomeText(v)}</dd>
        </dl>
        <p className="small muted">{v.after_approval}</p>
      </DetailSection>

      <DetailSection title="Decide with the CLI" id="ap-cli">
        {d.commands.approve ? (
          <div className="stack">
            <p className="small muted">The console takes no decision. An approver of {v.approver_groups.join(" or ")} decides with the credential in <code>TALON_APPROVER_KEY</code>; the reason is recorded in signed evidence.</p>
            <CopyableIdentifier value={d.commands.approve} label="approve command" />
            <CopyableIdentifier value={d.commands.reject ?? ""} label="reject command" />
          </div>
        ) : (
          <p className="small muted">No decision is possible for this approval any more.</p>
        )}
      </DetailSection>

      <DetailSection title="Signed lifecycle records" id="ap-evidence">
        <AvailabilityNotice a={d.lifecycle.availability} what="Lifecycle records" />
        {records.length === 0 ? <EmptyState title="No lifecycle record found" /> : (
          <div className="table-wrap">
            <table data-testid="approval-lifecycle">
              <thead><tr><th>Time (UTC)</th><th>What happened</th><th>Evidence</th></tr></thead>
              <tbody>
                {records.map((e) => (
                  <tr key={e.id}>
                    <td title={utc(e.timestamp)}>{utcShort(e.timestamp)}</td>
                    <td>{outcomeStory(e.outcome).headline}{e.primary_explanation_code ? <span className="small muted"> · <code>{e.primary_explanation_code}</code></span> : null}</td>
                    <td><Link to={scoped(`/evidence/${encodeURIComponent(e.id)}`, tenant)}><code>{e.id}</code></Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {d.session_id ? <p className="small">Session: <Link to={scoped(`/sessions/${encodeURIComponent(d.session_id)}`, tenant, { agent: v.use_case })}>{d.session_id}</Link></p> : null}
        <p className="small muted">Verify the whole lifecycle offline:</p>
        <CopyableIdentifier value={d.commands.verify} label="verify command" />
      </DetailSection>

      <details className="card section" data-testid="approval-technical">
        <summary className="card-head">Technical details</summary>
        <div className="card-body">
          <dl className="facts">
            <dt>Approval</dt><dd><CopyableIdentifier value={v.approval_id} label="approval id" /></dd>
            <dt>Operation</dt><dd><CopyableIdentifier value={v.operation.operation_id} label="operation id" /> <span className="small muted">ref {v.operation.operation_ref} · verdict {v.operation.verdict}</span></dd>
            <dt>Established</dt><dd>{utc(v.bound.established_at)}</dd>
            <dt>Rule</dt><dd><code>{v.bound.rule_id ?? "—"}</code> {v.bound.rule_source ? `(${humanize(v.bound.rule_source)})` : ""}</dd>
            <dt>Policy digest (bound)</dt><dd><CopyableIdentifier value={v.bound.policy_digest} label="policy digest" /></dd>
            <dt>Definition digest (bound)</dt><dd><CopyableIdentifier value={v.bound.definition_digest} label="definition digest" /></dd>
            <dt>Eligibility</dt><dd><code>{v.eligibility.state}</code> · class <code>{v.eligibility.class}</code> · basis <code>{v.eligibility.basis}</code></dd>
            <dt>Disclosure</dt><dd><code>{v.disclosure}</code> — argument values and the argument digest are not part of this view</dd>
          </dl>
        </div>
      </details>
    </div>
  );
}
