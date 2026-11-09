import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { UseCaseDetail as DetailDTO } from "../api/types";
import { BackLink, PageHead } from "../components/Layout";
import {
  AvailabilityNotice,
  Badge,
  BudgetUtilization,
  CopyableIdentifier,
  CurrencyAmount,
  DetailSection,
  EmptyState,
  ErrorState,
  Loading,
  SourceFreshness,
  UseCaseHealth,
} from "../components/ui";
import { ActivityChart } from "../components/ActivityChart";
import { isMeasurement } from "../lib/availability";
import { fieldValue, warningsFor } from "../lib/costs";
import { goDuration, humanize, integer, relative, utc, utcShort } from "../lib/format";
import { scoped, useScope } from "../lib/scope";

export function UseCaseDetail() {
  const { name = "" } = useParams();
  const { tenant } = useScope();
  const res = useApi<DetailDTO>(api(`/use-cases/${encodeURIComponent(name)}`), { tenant });
  const d = res.data;
  const row = d?.row;
  return (
    <>
      <BackLink to={scoped("/use-cases", tenant)} label="AI Use Cases" />
      <PageHead
        title={name}
        lede={row?.use_case?.purpose ?? "AI use case"}
        actions={<button type="button" onClick={res.reload} disabled={res.loading}>Refresh</button>}
      />
      {res.error ? <ErrorState error={res.error} what={`AI use case ${name}`} onRetry={res.reload} /> : null}
      {!d && res.loading ? <Loading what="AI use case" /> : null}
      {d ? <AvailabilityNotice a={d.availability} what="This AI use case" /> : null}
      {d && row ? (
        <div className="grid">
          <div className="grid two">
            <DetailSection title="Identity" id="uc-identity">
              <dl className="facts">
                <dt>Name</dt><dd>{row.name}</dd>
                <dt>Tenant</dt><dd>{row.tenant_id}</dd>
                <dt>State</dt><dd>{row.state === "enabled" ? "Enabled" : <Badge tone="neutral">Disabled intentionally</Badge>}</dd>
                <dt>Health</dt><dd><UseCaseHealth health={row.health} /> <span className="small">{row.why}</span></dd>
                <dt>Configuration</dt><dd><code>{row.config_path}</code></dd>
                <dt>Policy digest</dt><dd>{row.policy_digest ? <CopyableIdentifier value={row.policy_digest} label="policy digest" /> : "—"}</dd>
                {row.config_error ? (<><dt>Config error</dt><dd className="small">{row.config_error}</dd></>) : null}
                {row.use_case?.department ? (<><dt>Department</dt><dd>{row.use_case.department}</dd></>) : null}
                {row.use_case?.owner_technical ? (<><dt>Technical owner</dt><dd>{row.use_case.owner_technical}</dd></>) : null}
                {row.use_case?.owner_business ? (<><dt>Business owner</dt><dd>{row.use_case.owner_business}</dd></>) : null}
                {row.use_case?.criticality ? (<><dt>Criticality</dt><dd>{row.use_case.criticality}</dd></>) : null}
              </dl>
              <p className="small muted">
                Health basis: {d.health_basis === "projected_from_store" ? "projected from persisted data; " : ""}runtime {d.runtime.availability.state}.
              </p>
            </DetailSection>
            <DetailSection title="Reliability and traffic" id="uc-reliability">
              <dl className="facts">
                <dt>Requests, last {goDuration(d.counter_windows?.requests_denied)}</dt><dd>{integer(row.requests)}</dd>
                <dt>Denied by Talon, last {goDuration(d.counter_windows?.requests_denied)}</dt><dd>{integer(row.denied)}</dd>
                <dt>Fallbacks, last {goDuration(d.counter_windows?.fallbacks)}</dt><dd>{integer(row.fallbacks)}</dd>
                <dt>Failed sessions, last {goDuration(d.counter_windows?.failed_sessions)}</dt><dd>{integer(row.failed_sessions)}</dd>
                <dt>Last request</dt><dd title={utc(row.last_run)}>{relative(row.last_run)}</dd>
              </dl>
              {row.causes && row.causes.length > 0 ? (
                <>
                  <h3>Why this health</h3>
                  <ul className="small">
                    {row.causes.map((c) => (<li key={c.kind}><code>{c.kind}</code> — {c.detail}</li>))}
                  </ul>
                </>
              ) : null}
              <p className="small muted">The windows Talon's health evaluation uses; the activity chart below covers 24 hours. Per-request retries and provider paths are in each session.</p>
            </DetailSection>
          </div>

          <DetailSection
            title="Costs"
            id="uc-costs"
            actions={<Link to={scoped("/costs", tenant || row.tenant_id, { agent: row.name })}>Open in Costs</Link>}
          >
            <AvailabilityNotice a={d.costs.availability} what="Costs" />
            {d.costs.report ? (
              <div className="grid two">
                <dl className="facts">
                  <dt>Today (UTC)</dt>
                  <dd><CurrencyAmount amount={fieldValue(d.costs.report, "today_eur")} currency={d.costs.report.currency} reason={warningsFor(d.costs.report, ["day window"]).join("; ")} /></dd>
                  <dt>This month (UTC)</dt>
                  <dd><CurrencyAmount amount={fieldValue(d.costs.report, "month_eur")} currency={d.costs.report.currency} reason={warningsFor(d.costs.report, ["month window"]).join("; ")} /></dd>
                  <dt>Unpriced records</dt>
                  <dd>{d.costs.report.unpriced_records > 0 ? <Badge tone="warn" plain>{integer(d.costs.report.unpriced_records)} — amounts understate spend</Badge> : "0"}</dd>
                </dl>
                <div className="stack">
                  <div><strong className="small">Daily budget</strong></div>
                  <BudgetUtilization b={d.costs.report.daily_budget} currency={d.costs.report.currency} unavailable={(d.costs.report.unavailable_fields ?? []).includes("daily_budget")} reason={warningsFor(d.costs.report, ["budget"]).join("; ")} />
                  <div><strong className="small">Monthly budget</strong></div>
                  <BudgetUtilization b={d.costs.report.monthly_budget} currency={d.costs.report.currency} unavailable={(d.costs.report.unavailable_fields ?? []).includes("monthly_budget")} reason={warningsFor(d.costs.report, ["budget"]).join("; ")} />
                  {d.costs.budget_note ? <span className="small muted">{d.costs.budget_note}</span> : null}
                </div>
              </div>
            ) : null}
          </DetailSection>

          <DetailSection title="Activity (last 24 hours)" id="uc-activity">
            <AvailabilityNotice a={d.activity.availability} what="Activity" />
            {d.activity.series && isMeasurement(d.activity.availability) ? (
              (d.activity.series.buckets ?? []).every((b) => b.requests === 0) ? (
                <EmptyState title="No requests recorded in the last 24 hours" />
              ) : (
                <ActivityChart buckets={d.activity.series.buckets ?? []} label="Requests per hour" />
              )
            ) : null}
            <SourceFreshness a={d.activity.availability} />
          </DetailSection>

          <DetailSection
            title="Policy"
            id="uc-policy"
            actions={<Link to={scoped("/configuration", tenant || row.tenant_id, { use_case: row.name })}>Open in Configuration</Link>}
          >
            <div className="notice info" role="note">
              <div>
                <strong>Effective policy provenance not available.</strong> {d.effective_policy.note}
              </div>
            </div>
          </DetailSection>

          <DetailSection
            title="Recent sessions"
            id="uc-sessions"
            actions={<Link to={scoped("/sessions", tenant || row.tenant_id, { agent: row.name })}>All sessions</Link>}
          >
            <RecentSessions d={d} tenant={tenant || row.tenant_id} />
          </DetailSection>
        </div>
      ) : null}
    </>
  );
}

function RecentSessions({ d, tenant }: { d: DetailDTO; tenant: string }) {
  const list = d.recent_sessions;
  const managed = list.sessions ?? [];
  const observed = list.observed ?? [];
  return (
    <div className="stack">
      <AvailabilityNotice a={list.availability} what="Managed sessions" />
      <AvailabilityNotice a={list.observed_availability} what="Observed sessions" />
      {managed.length === 0 && observed.length === 0 && isMeasurement(list.availability) ? <EmptyState title="No sessions recorded for this AI use case" /> : null}
      {managed.length + observed.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Session</th><th>Source</th><th>Status</th><th className="num">Last activity (UTC)</th></tr></thead>
            <tbody>
              {managed.map((s) => (
                <tr key={`m${s.id}`}>
                  <td><Link to={scoped(`/sessions/${encodeURIComponent(s.id)}`, tenant)}>{s.external_session_id || s.id}</Link></td>
                  <td>managed{s.source ? ` · ${humanize(s.source)}` : ""}</td>
                  <td>{humanize(s.status)}</td>
                  <td className="num">{utcShort(s.updated_at)}</td>
                </tr>
              ))}
              {observed.map((o) => (
                <tr key={`o${o.session_id}/${o.agent_id}`}>
                  <td><Link to={scoped(`/sessions/${encodeURIComponent(o.session_id)}`, tenant, { agent: o.agent_id })}>{o.session_id}</Link></td>
                  <td>observed in evidence · {o.record_count} records</td>
                  <td className="muted">no lifecycle tracked</td>
                  <td className="num">{utcShort(o.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <span className="small muted">Showing at most {list.limit} of each kind.</span>
    </div>
  );
}
