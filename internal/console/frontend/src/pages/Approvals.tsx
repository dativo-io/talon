import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { ApprovalList } from "../api/types";
import { PageHead } from "../components/Layout";
import { Breadcrumbs, scopeCrumb } from "../components/Breadcrumbs";
import { EligibilityBadge } from "../components/Approvals";
import { AvailabilityNotice, EmptyState, ErrorState, Loading, SourceFreshness } from "../components/ui";
import { isMeasurement } from "../lib/availability";
import { expiresIn } from "../lib/approvals";
import { utc, utcShort } from "../lib/format";
import { scoped, useScope } from "../lib/scope";

const STATES: { value: ApprovalList["state"]; label: string; lede: string }[] = [
  { value: "attention", label: "May await a decision", lede: "Unresolved approvals that can be decided, may be decidable, or whose eligibility is unknown. Oldest first." },
  { value: "unresolved", label: "All unresolved", lede: "Every approval still pending in the store, including expired and stale ones that can no longer be decided. Oldest first." },
  { value: "decided", label: "Decided and closed", lede: "Approved, rejected, expired and invalidated approvals. Newest first." },
];

// Approvals: discovery only. The console lists approvals and shows why they
// are required; it offers no decision and no argument value. The cursor
// stack belongs to one (tenant, use case, state) scope.
export function Approvals() {
  const { tenant, params, set } = useScope();
  const useCase = params.get("use_case") ?? "";
  const state = (STATES.find((s) => s.value === params.get("state"))?.value ?? "attention") as ApprovalList["state"];
  const scope = JSON.stringify([tenant, useCase, state]);
  const [pages, setPages] = useState<{ scope: string; stack: string[] }>({ scope, stack: [] });
  const stack = pages.scope === scope ? pages.stack : [];
  const res = useApi<ApprovalList>(api("/approvals"), { tenant, use_case: useCase, state, after: stack[stack.length - 1] });
  const d = res.data;
  const current = STATES.find((s) => s.value === state)!;
  const decided = state === "decided";
  return (
    <>
      {useCase ? <Breadcrumbs items={[scopeCrumb(tenant), { label: useCase, to: scoped(`/use-cases/${encodeURIComponent(useCase)}`, tenant) }, { label: "Approvals" }]} /> : null}
      <PageHead
        title={useCase ? `Approvals of ${useCase}` : "Approvals"}
        lede="Action Gateway requests that wait for a person, and what was decided. This page is read-only: a decision is taken with an approver credential through the CLI, and argument values are not shown here."
        actions={<button type="button" onClick={res.reload} disabled={res.loading}>Refresh</button>}
      />
      <div className="filter-bar">
        <label>
          Show
          <select value={state} onChange={(e) => set("state", e.target.value === "attention" ? "" : e.target.value)} aria-label="Approval selection">
            {STATES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
        </label>
        <label>
          AI use case
          <input defaultValue={useCase} key={useCase} placeholder="any" onBlur={(e) => set("use_case", e.target.value.trim())} onKeyDown={(e) => { if (e.key === "Enter") set("use_case", (e.target as HTMLInputElement).value.trim()); }} />
        </label>
        <span className="small muted">{tenant ? `Tenant ${tenant}` : "All tenants"} (a filter, not an access control). {current.lede}</span>
      </div>
      {res.error ? <ErrorState error={res.error} what="approvals" onRetry={res.reload} /> : null}
      {!d && res.loading ? <Loading what="approvals" /> : null}
      {d ? (
        <section className="card" aria-labelledby="approvals-list-title">
          <div className="card-head">
            <h2 id="approvals-list-title">{current.label}</h2>
            <SourceFreshness a={d.availability} />
          </div>
          <AvailabilityNotice a={d.availability} what="Approvals" />
          {isMeasurement(d.availability) && d.items.length === 0 ? (
            <EmptyState title={state === "attention" ? "No approval awaits a decision in this scope" : "No approval in this selection"}>
              {state === "attention" ? <>Expired or stale requests are under <Link to={scoped("/approvals", tenant, { use_case: useCase, state: "unresolved" })}>All unresolved</Link>; past decisions under <Link to={scoped("/approvals", tenant, { use_case: useCase, state: "decided" })}>Decided and closed</Link>.</> : null}
            </EmptyState>
          ) : null}
          {d.items.length > 0 ? (
            <div className="table-wrap">
              <table data-testid="approvals-table">
                <thead>
                  <tr>
                    <th>Approval</th><th>Action</th><th>AI use case</th><th>State</th>
                    {decided ? <><th className="num">Decided (UTC)</th><th>By</th></> : <><th className="num">Expires</th><th>Required group</th></>}
                  </tr>
                </thead>
                <tbody>
                  {d.items.map((a) => (
                    <tr key={a.approval_id} data-approval={a.approval_id}>
                      <td><Link to={scoped(`/approvals/${encodeURIComponent(a.approval_id)}`, a.tenant)}><code>{a.approval_id}</code></Link></td>
                      <td><code>{a.action}</code></td>
                      <td><Link to={scoped(`/use-cases/${encodeURIComponent(a.use_case)}`, a.tenant)}>{a.use_case}</Link> <span className="small muted">{a.tenant}</span></td>
                      <td><EligibilityBadge e={a.eligibility} status={a.status} /></td>
                      {decided ? (
                        <><td className="num" title={utc(a.decided_at)}>{utcShort(a.decided_at)}</td><td>{a.decided_by || <span className="muted">—</span>}</td></>
                      ) : (
                        <><td className="num" title={utc(a.expires_at)}>{expiresIn(a.expires_at)}</td><td>{a.approver_groups.join(", ")}</td></>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          <div className="table-foot">
            <span className="small muted">
              No argument name or value is listed. Order and paging use each approval's creation time: an approval decided while you page leaves this selection and appears under “Decided and closed”.
            </span>
            <div className="row">
              <button type="button" disabled={stack.length === 0} onClick={() => setPages({ scope, stack: stack.slice(0, -1) })}>Previous</button>
              <button type="button" disabled={!d.next} onClick={() => d.next && setPages({ scope, stack: [...stack, d.next] })}>Next</button>
            </div>
          </div>
        </section>
      ) : null}
    </>
  );
}
