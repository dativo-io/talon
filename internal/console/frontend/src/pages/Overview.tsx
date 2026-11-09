import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { Activity, AgentRow, Overview as OverviewDTO } from "../api/types";
import { ActivityChart } from "../components/ActivityChart";
import { PageHead } from "../components/Layout";
import { AvailabilityNotice, Badge, CurrencyAmount, EmptyState, ErrorState, Loading, SourceFreshness, UseCaseHealth } from "../components/ui";
import { TimeRangeSelector, rangeQuery, type Range } from "../components/TimeRange";
import { isMeasurement } from "../lib/availability";
import { humanize, integer, money, relative, utc, utcShort } from "../lib/format";
import { scoped, useScope } from "../lib/scope";
import { rowSpend } from "../lib/costs";
import { runtimeSummary } from "../components/RuntimeStatus";

export function Overview() {
  const { tenant } = useScope();
  const ov = useApi<OverviewDTO>(api("/overview"), { tenant });
  return (
    <>
      <PageHead
        title="Overview"
        lede="Which AI use cases need attention right now, and why."
        actions={<button type="button" onClick={ov.reload} disabled={ov.loading}>Refresh</button>}
      />
      {ov.error ? <ErrorState error={ov.error} what="the overview" onRetry={ov.reload} /> : null}
      {!ov.data && ov.loading ? <Loading what="overview" /> : null}
      {ov.data ? <OverviewBody o={ov.data} tenant={tenant} /> : null}
    </>
  );
}

function OverviewBody({ o, tenant }: { o: OverviewDTO; tenant: string }) {
  const uc = o.use_cases;
  const rows = uc.rows ?? [];
  const attention = uc.attention ?? [];
  const ucMeasured = isMeasurement(uc.availability);
  const scopeLabel = o.meta.tenant_scope === "all_tenants" ? "all tenants" : `tenant ${o.meta.tenant_id}`;
  return (
    <div className="stack">
      <RuntimeConfidence o={o} />
      <AvailabilityNotice a={uc.availability} what="AI use cases" />
      {ucMeasured && rows.length === 0 ? (
        <div className="card">
          <EmptyState title="No AI use case is configured">
            Talon found no <code>agent.talon.yaml</code> in its configured agents directory. Each agent file is one AI use case; see{" "}
            <code>talon init</code>.
          </EmptyState>
        </div>
      ) : null}
      {ucMeasured && rows.length > 0 ? <AttentionQueue rows={attention} total={rows.length} tenant={tenant} scope={scopeLabel} /> : null}
      <Summary o={o} configured={ucMeasured ? rows.length : null} attention={ucMeasured ? attention.length : null} />
      <ActivitySection tenant={o.meta.tenant_id ?? ""} />
      <RecentEvents o={o} tenant={tenant} />
      {uc.issues && uc.issues.length > 0 ? (
        <section className="card">
          <div className="card-head"><h2>Configuration issues</h2></div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>File</th><th>Status</th><th>Reason</th></tr></thead>
              <tbody>
                {uc.issues.map((i) => (
                  <tr key={i.path}><td><code>{i.path}</code></td><td>{humanize(i.status)}</td><td>{i.reason}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}
    </div>
  );
}

function RuntimeConfidence({ o }: { o: OverviewDTO }) {
  const projected = o.use_cases.health_basis === "projected_from_store";
  return (
    <div className="notice info" role="note">
      <div>
        <strong>{projected ? "Health projected from persisted data." : "Health from the live runtime."}</strong>{" "}
        {projected
          ? "States are evaluated from recorded evidence and the configuration files; they are not a liveness check of the gateway or MCP proxy. "
          : ""}
        {runtimeSummary(o.use_cases.runtime)}. <Link to="/system">System</Link>
      </div>
    </div>
  );
}

function AttentionQueue({ rows, total, tenant, scope }: { rows: AgentRow[]; total: number; tenant: string; scope: string }) {
  return (
    <section className="card" aria-labelledby="attention-title">
      <div className="card-head">
        <h2 id="attention-title">Attention queue</h2>
        <span className="small muted">Talon's order: health, then name · {scope}</span>
      </div>
      {rows.length === 0 ? (
        <div className="card-body">
          <p>
            <strong>No AI use case needs attention</strong> among the {total} configured, within the projection's scope: recorded evidence and the
            current configuration. This does not prove that the gateway or MCP processes are running.
          </p>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>AI use case</th>
                <th>State</th>
                <th>Health</th>
                <th>Why</th>
                <th className="num">Month spend / cap</th>
                <th className="num">Last request</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={`${r.tenant_id}/${r.name}`}>
                  <td>
                    <Link to={scoped(`/use-cases/${encodeURIComponent(r.name)}`, tenant || r.tenant_id)}>{r.name}</Link>
                    <div className="small muted">{r.tenant_id}</div>
                  </td>
                  <td>{r.state === "enabled" ? "Enabled" : <Badge tone="neutral">Disabled</Badge>}</td>
                  <td><UseCaseHealth health={r.health} /></td>
                  <td>{r.why}</td>
                  <td className="num">
                    <CurrencyAmount amount={rowSpend(r, "spend_month")} currency={r.currency} reason="priced records in another currency: not comparable with the cap" />
                    <div className="small muted">{r.monthly_cap > 0 ? `cap ${money(r.monthly_cap, r.currency)}` : "no monthly cap"}</div>
                  </td>
                  <td className="num" title={utc(r.last_run)}>{relative(r.last_run)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function Summary({ o, configured, attention }: { o: OverviewDTO; configured: number | null; attention: number | null }) {
  const t = o.today;
  const reqOk = isMeasurement(t.availability, "requests");
  const costOk = isMeasurement(t.availability, "cost");
  return (
    <section aria-labelledby="summary-title">
      <h2 id="summary-title" className="visually-hidden">Today</h2>
      <div className="grid stats">
        <Stat label="Configured AI use cases" value={configured === null ? null : integer(configured)} sub="agent files discovered" />
        <Stat label="Needing attention" value={attention === null ? null : integer(attention)} sub="canonical fleet health" />
        <Stat label="Requests today" value={reqOk ? integer(t.requests) : null} sub={`UTC day from ${utcShort(t.window.day_start)}`} />
        <Stat label="Denied today" value={reqOk ? integer(t.denied) : null} sub="request-class records" />
        <Stat
          label="Recorded spend today"
          value={costOk ? money(t.cost, t.currency) : null}
          sub={costOk ? "all record classes" : (t.availability.note ?? t.availability.error ?? "not a measurement")}
        />
      </div>
      <div className="row">
        <SourceFreshness a={t.availability} />
      </div>
      <AvailabilityNotice a={t.availability} what="Today's figures" />
    </section>
  );
}

function Stat({ label, value, sub }: { label: string; value: string | null; sub?: string }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value">{value ?? <span className="muted">unavailable</span>}</div>
      {sub ? <div className="sub">{sub}</div> : null}
    </div>
  );
}

function ActivitySection({ tenant, agent }: { tenant: string; agent?: string }) {
  const [range, setRange] = useState<Range>("24h");
  const act = useApi<Activity>(api("/activity"), { tenant, agent, ...rangeQuery(range) });
  return (
    <section className="card" aria-labelledby="activity-title">
      <div className="card-head">
        <h2 id="activity-title">Operational activity</h2>
        <div className="row">
          <TimeRangeSelector value={range} onChange={setRange} />
        </div>
      </div>
      <div className="card-body">
        {act.error ? <ErrorState error={act.error} what="activity" onRetry={act.reload} /> : null}
        {act.data ? (
          <>
            <AvailabilityNotice a={act.data.availability} what="Activity" />
            {act.data.series && isMeasurement(act.data.availability) ? (
              (act.data.series.buckets ?? []).every((b) => b.requests === 0) ? (
                <EmptyState title="No requests recorded in this range">The evidence store was read; it holds no request-class records here.</EmptyState>
              ) : (
                <ActivityChart buckets={act.data.series.buckets ?? []} label={`Requests per ${act.data.series.bucket}`} />
              )
            ) : null}
            <div className="row small muted">
              <SourceFreshness a={act.data.availability} />
              {act.data.series ? (
                <span>
                  · tenant {act.data.series.tenant_id} · {utcShort(act.data.series.from)} – {utcShort(act.data.series.to)} UTC · {act.data.series.bucket} buckets · request-class records
                </span>
              ) : null}
            </div>
          </>
        ) : act.loading ? <Loading what="activity" /> : null}
      </div>
    </section>
  );
}
export { ActivitySection };

function RecentEvents({ o, tenant }: { o: OverviewDTO; tenant: string }) {
  const re = o.recent_events;
  const events = re.events ?? [];
  return (
    <section className="card" aria-labelledby="events-title">
      <div className="card-head">
        <h2 id="events-title">Recent events</h2>
        <SourceFreshness a={re.availability} />
      </div>
      <AvailabilityNotice a={re.availability} what="Recent events" />
      {isMeasurement(re.availability) && events.length === 0 ? <EmptyState title="No events recorded yet" /> : null}
      {events.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Time (UTC)</th><th>AI use case</th><th>Type</th><th>Decision</th><th>Reason</th><th>Evidence</th></tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.event_id}>
                  <td title={utc(e.timestamp)}>{utcShort(e.timestamp)}</td>
                  <td>{e.agent_id ? <Link to={scoped(`/use-cases/${encodeURIComponent(e.agent_id)}`, tenant || e.tenant_id)}>{e.agent_id}</Link> : <span className="muted">—</span>}</td>
                  <td><code>{e.invocation_type}</code></td>
                  <td><Badge tone={e.allowed ? "ok" : "error"}>{e.allowed ? "allowed" : "denied"}</Badge>{e.has_error ? <> <Badge tone="warn" plain>error</Badge></> : null}</td>
                  <td>
                    {e.primary_explanation_code ? <code>{e.primary_explanation_code}</code> : null}
                    <div className="small">{e.primary_explanation_reason ?? e.reason_text ?? ""}</div>
                  </td>
                  <td><Link to={scoped(`/evidence/${encodeURIComponent(e.evidence_id)}`, e.tenant_id)}>{e.evidence_id}</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
