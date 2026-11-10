import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { ObservedCursor, SessionCursor, SessionList } from "../api/types";
import { PageHead } from "../components/Layout";
import { Breadcrumbs, scopeCrumb } from "../components/Breadcrumbs";
import { AvailabilityNotice, EmptyState, ErrorState, Loading, SourceFreshness } from "../components/ui";
import { isMeasurement } from "../lib/availability";
import { humanize, integer, money, utc, utcShort } from "../lib/format";
import { scoped, useScope } from "../lib/scope";

const STATUSES = ["active", "pending_approval", "executing", "completed", "failed", "timed_out"];

// Two sources, kept apart: session-store rows (lifecycle Talon tracks) and
// session ids that appear only in evidence (no lifecycle is invented for
// them). Each pages with its own keyset cursor; the observed cursor carries
// all three keys (last_seen, session_id, agent_id).
export function Sessions() {
  const { tenant, params, set } = useScope();
  const agent = params.get("agent") ?? "";
  const status = params.get("status") ?? "";
  const limit = params.get("limit") ?? ""; // page size; the server clamps it
  // Cursor stacks belong to one query scope (tenant, use case, status): a
  // cursor from another scope is never sent, whichever control changed it.
  const scope = JSON.stringify([tenant, agent, status, limit]);
  const [pages, setPages] = useState<{ scope: string; managed: SessionCursor[]; observed: ObservedCursor[] }>({ scope, managed: [], observed: [] });
  const owned = pages.scope === scope;
  const managedStack = owned ? pages.managed : [];
  const observedStack = owned ? pages.observed : [];
  const setManagedStack = (f: (s: SessionCursor[]) => SessionCursor[]) => setPages({ scope, managed: f(managedStack), observed: observedStack });
  const setObservedStack = (f: (s: ObservedCursor[]) => ObservedCursor[]) => setPages({ scope, managed: managedStack, observed: f(observedStack) });
  const mc = managedStack[managedStack.length - 1];
  const oc = observedStack[observedStack.length - 1];
  const res = useApi<SessionList>(api("/sessions"), {
    tenant,
    agent,
    status,
    limit,
    before: mc?.created_at,
    before_id: mc?.id,
    observed_before: oc?.last_seen,
    observed_before_id: oc?.session_id,
    observed_before_agent: oc?.agent_id,
  });
  const reset = () => setPages({ scope, managed: [], observed: [] });
  const d = res.data;
  const scopeTenant = d?.meta.tenant_id ?? (tenant || "default");
  return (
    <>
      {agent ? <Breadcrumbs items={[scopeCrumb(tenant), { label: agent, to: scoped(`/use-cases/${encodeURIComponent(agent)}`, scopeTenant) }, { label: "Sessions" }]} /> : null}
      <PageHead
        title={agent ? `Sessions of ${agent}` : "Sessions"}
        lede="Managed sessions with the lifecycle Talon tracks, and session ids observed only in evidence. Open one to see what Talon decided and what happened."
        actions={<button type="button" onClick={res.reload} disabled={res.loading}>Refresh</button>}
      />
      <div className="filter-bar">
        <label>
          AI use case
          <input defaultValue={agent} placeholder="any" onBlur={(e) => { reset(); set("agent", e.target.value.trim()); }} onKeyDown={(e) => { if (e.key === "Enter") { reset(); set("agent", (e.target as HTMLInputElement).value.trim()); } }} />
        </label>
        <label>
          Managed status
          <select value={status} onChange={(e) => { reset(); set("status", e.target.value); }}>
            <option value="">Any</option>
            {STATUSES.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
          </select>
        </label>
        <span className="small muted">Tenant: {scopeTenant}. Newest first.</span>
      </div>
      {res.error ? <ErrorState error={res.error} what="sessions" onRetry={res.reload} /> : null}
      {!d && res.loading ? <Loading what="sessions" /> : null}
      {d ? (
        <div className="grid">
          <section className="card" aria-labelledby="managed-title">
            <div className="card-head">
              <h2 id="managed-title">Managed sessions</h2>
              <SourceFreshness a={d.availability} />
            </div>
            <AvailabilityNotice a={d.availability} what="Managed sessions" />
            {isMeasurement(d.availability) && (d.sessions ?? []).length === 0 ? <EmptyState title="No managed sessions in this scope" /> : null}
            {(d.sessions ?? []).length > 0 ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr><th>Session</th><th>AI use case</th><th>Status</th><th>Source</th><th className="num">Created (UTC)</th><th className="num">Recorded cost</th><th className="num">Tokens</th></tr>
                  </thead>
                  <tbody>
                    {(d.sessions ?? []).map((s) => (
                      <tr key={s.id}>
                        <td>
                          <Link to={scoped(`/sessions/${encodeURIComponent(s.id)}`, s.tenant_id)}>{s.external_session_id || s.id}</Link>
                          {s.external_session_id ? <div className="small muted"><code>{s.id}</code></div> : null}
                        </td>
                        <td>{s.agent_id}</td>
                        <td>{humanize(s.status)}</td>
                        <td>{s.source ? humanize(s.source) : "talon"}</td>
                        <td className="num" title={utc(s.created_at)}>{utcShort(s.created_at)}</td>
                        <td className="num">{money(s.total_cost, "")}</td>
                        <td className="num">{integer(s.total_tokens)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
            <Pager
              canBack={managedStack.length > 0}
              next={d.next_cursor}
              onBack={() => setManagedStack((s) => s.slice(0, -1))}
              onNext={() => d.next_cursor && setManagedStack((s) => [...s, d.next_cursor!])}
              note="Session-row cost is the session store's running total; see the session for evidence-backed spend and its currency."
            />
          </section>

          <section className="card" aria-labelledby="observed-title">
            <div className="card-head">
              <h2 id="observed-title">Observed in evidence</h2>
              <SourceFreshness a={d.observed_availability} />
            </div>
            <div className="card-body small muted">
              Session ids that appear on evidence records with no session-store row, for example asserted by a client on the MCP proxy path. Talon does not track a lifecycle for them; nothing here is inferred.
            </div>
            <AvailabilityNotice a={d.observed_availability} what="Observed sessions" />
            {isMeasurement(d.observed_availability) && (d.observed ?? []).length === 0 ? <EmptyState title="No evidence-only sessions in this scope" /> : null}
            {(d.observed ?? []).length > 0 ? (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Session id</th><th>AI use case</th><th className="num">Records</th><th className="num">First seen (UTC)</th><th className="num">Last seen (UTC)</th></tr></thead>
                  <tbody>
                    {(d.observed ?? []).map((o) => (
                      <tr key={`${o.session_id}/${o.agent_id}`}>
                        <td><Link to={scoped(`/sessions/${encodeURIComponent(o.session_id)}`, o.tenant_id, { agent: o.agent_id })}>{o.session_id}</Link></td>
                        <td>{o.agent_id}</td>
                        <td className="num">{integer(o.record_count)}</td>
                        <td className="num">{utcShort(o.first_seen)}</td>
                        <td className="num">{utcShort(o.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
            <Pager
              canBack={observedStack.length > 0}
              next={d.observed_next_cursor}
              onBack={() => setObservedStack((s) => s.slice(0, -1))}
              onNext={() => d.observed_next_cursor && setObservedStack((s) => [...s, d.observed_next_cursor!])}
            />
          </section>
        </div>
      ) : null}
    </>
  );
}

function Pager({ canBack, next, onBack, onNext, note }: { canBack: boolean; next: unknown; onBack: () => void; onNext: () => void; note?: string }) {
  if (!canBack && !next && !note) return null;
  return (
    <div className="table-foot">
      <span className="small muted">{note}</span>
      <div className="row">
        <button type="button" disabled={!canBack} onClick={onBack}>Newer</button>
        <button type="button" disabled={!next} onClick={onNext}>Older</button>
      </div>
    </div>
  );
}
