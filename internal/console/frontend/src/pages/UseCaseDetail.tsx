import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { Costs as CostsDTO, EvidenceIndex, UseCaseDetail as DetailDTO } from "../api/types";
import { PageHead } from "../components/Layout";
import {
  AvailabilityNotice,
  Badge,
  BudgetUtilization,
  CopyableIdentifier,
  CurrencyAmount,
  EmptyState,
  ErrorState,
  Loading,
  UseCaseHealth,
} from "../components/ui";
import { Breadcrumbs, scopeCrumb } from "../components/Breadcrumbs";
import { EffectivePolicySection } from "../components/EffectivePolicy";
import { FindingsList, OverallBadge, ReadyBadge } from "../components/Readiness";
import { RoleTable } from "../components/RuntimeStatus";
import { ActivitySection } from "./Overview";
import type { Range } from "../components/TimeRange";
import { isMeasurement } from "../lib/availability";
import { breakdownRows, fieldValue, warningsFor, type Breakdown } from "../lib/costs";
import { goDuration, humanize, integer, money, relative, utc, utcShort } from "../lib/format";
import { outcomeStory } from "../lib/outcome";
import { scoped, useScope } from "../lib/scope";

// The AI use case page answers four questions, one section each (#533 PR 2):
// Summary (is it operating as expected?), Sessions & Activity (what happened
// when it ran?), Policy & Runtime (what is permitted, and which policy is
// active?), Costs (what does it cost?). Every value is a backend
// projection; nothing is recomputed here.
const SECTIONS = [
  { id: "uc-summary", label: "Summary" },
  { id: "uc-activity", label: "Sessions & Activity" },
  { id: "uc-policy", label: "Policy & Runtime" },
  { id: "uc-costs", label: "Costs" },
];

const RANGES: Range[] = ["24h", "7d", "30d"];

export function UseCaseDetail() {
  const { name = "" } = useParams();
  const { tenant, params, set } = useScope();
  const res = useApi<DetailDTO>(api(`/use-cases/${encodeURIComponent(name)}`), { tenant });
  const d = res.data;
  const row = d?.row;
  const ucTenant = tenant || row?.tenant_id || "";
  const rangeParam = params.get("range") as Range | null;
  const range: Range = rangeParam && RANGES.includes(rangeParam) ? rangeParam : "24h";
  return (
    <>
      <Breadcrumbs items={[scopeCrumb(tenant), { label: "AI Use Cases", to: scoped("/use-cases", tenant) }, { label: name }]} />
      <PageHead
        title={name}
        lede={row?.use_case?.purpose ?? (row ? `AI use case in tenant ${row.tenant_id}` : "AI use case")}
        actions={<button type="button" onClick={res.reload} disabled={res.loading}>Refresh</button>}
      />
      {res.error ? <ErrorState error={res.error} what={`AI use case ${name}`} onRetry={res.reload} /> : null}
      {!d && res.loading ? <Loading what="AI use case" /> : null}
      {d ? <AvailabilityNotice a={d.availability} what="This AI use case" /> : null}
      {d && row ? (
        <div className="stack">
          <nav className="uc-nav" aria-label="Sections of this AI use case">
            {SECTIONS.map((s) => <a key={s.id} href={`#${s.id}`}>{s.label}</a>)}
          </nav>
          <SummarySection d={d} tenant={ucTenant} />
          <ActivityAndSessions d={d} tenant={ucTenant} range={range} onRange={(r) => set("range", r === "24h" ? "" : r)} />
          <PolicyAndRuntime d={d} tenant={ucTenant} />
          <CostsSection d={d} tenant={ucTenant} />
        </div>
      ) : null}
    </>
  );
}

function SectionHead({ id, title, question }: { id: string; title: string; question: string }) {
  return (
    <div>
      <div className="section-head"><h2 id={`${id}-title`}>{title}</h2></div>
      <p className="uc-question">{question}</p>
    </div>
  );
}

// ------------------------------------------------------------ 1. Summary

function SummarySection({ d, tenant }: { d: DetailDTO; tenant: string }) {
  const row = d.row!;
  const uc = row.use_case;
  const r = d.readiness;
  const dims = (r?.dimensions ?? []).filter((x) => ["runtime.gateway", "runtime.mcp_proxy", "authentication.agent_keys"].includes(x.key));
  const report = d.costs.report;
  const top = (d.findings ?? [])[0];
  return (
    <section id="uc-summary" className="uc-section stack" aria-labelledby="uc-summary-title">
      <SectionHead id="uc-summary" title="Summary" question="Is this AI use case operating as expected?" />
      <div className="grid two">
        <section className="card" aria-labelledby="uc-identity">
          <div className="card-head"><h3 id="uc-identity">Identity</h3></div>
          <div className="card-body">
            <dl className="facts">
              <dt>Name</dt><dd>{row.name}</dd>
              <dt>Tenant</dt><dd>{row.tenant_id}</dd>
              <dt>State</dt><dd>{row.state === "enabled" ? "Enabled" : <Badge tone="neutral">Disabled intentionally</Badge>}</dd>
              <dt>Purpose</dt><dd>{uc?.purpose ?? <span className="muted">not declared</span>}</dd>
              <dt>Business owner</dt><dd>{uc?.owner_business ?? <span className="muted">not declared</span>}</dd>
              <dt>Technical owner</dt><dd>{uc?.owner_technical ?? <span className="muted">not declared</span>}</dd>
              {uc?.department ? (<><dt>Department</dt><dd>{uc.department}</dd></>) : null}
              {uc?.criticality ? (<><dt>Criticality</dt><dd>{uc.criticality}</dd></>) : null}
              <dt>Configuration</dt><dd><code>{row.config_path}</code></dd>
            </dl>
            <p className="small muted">Owners and purpose are what the agent file declares (attribution for people reading the fleet); nothing here authenticates them.</p>
          </div>
        </section>
        <section className="card" aria-labelledby="uc-state">
          <div className="card-head"><h3 id="uc-state">State now</h3></div>
          <div className="card-body">
            <dl className="facts">
              <dt>Fleet health</dt><dd><UseCaseHealth health={row.health} /> <span className="small">{row.why}</span></dd>
              <dt>Installation readiness</dt>
              <dd>{r ? <><OverallBadge overall={r.overall} /> <span className="small">{r.summary}</span></> : <span className="muted">not reported</span>}</dd>
              {dims.map((x) => (
                <div key={x.key} className="contents">
                  <dt>{x.label}</dt><dd><ReadyBadge state={x.state} /></dd>
                </div>
              ))}
              <dt>Requests, last {goDuration(d.counter_windows?.requests_denied)}</dt><dd>{integer(row.requests)} ({integer(row.denied)} denied by Talon)</dd>
              <dt>Last request</dt><dd title={utc(row.last_run)}>{relative(row.last_run)}</dd>
              <dt>Spend today / this month</dt>
              <dd>
                {report ? <>
                  <CurrencyAmount amount={fieldValue(report, "today_eur")} currency={report.currency} reason={warningsFor(report, ["day window"]).join("; ")} />
                  {" / "}
                  <CurrencyAmount amount={fieldValue(report, "month_eur")} currency={report.currency} reason={warningsFor(report, ["month window"]).join("; ")} />
                  {report.monthly_budget ? <span className="small muted"> · {Math.round(report.monthly_budget.percent)}% of the monthly cap</span> : null}
                </> : <span className="muted">unavailable</span>}
              </dd>
            </dl>
            <p className="small muted">Readiness is installation-wide: the runtimes serve every use case. Per-boundary proof that this use case's policy is active is under Policy &amp; Runtime.</p>
          </div>
        </section>
      </div>
      {top ? (
        <FindingsList findings={[top]} tenant={tenant} title="Most urgent finding" />
      ) : (
        <div className="notice info" role="status"><div>No finding: readiness reports no problem and fleet health flags nothing for this use case.</div></div>
      )}
      <div className="row small">
        <span className="muted">Investigate:</span>
        <a href="#uc-activity">Sessions and decisions</a>
        <a href="#uc-effective">Effective policy</a>
        <a href="#uc-costs">Costs</a>
        <Link to={scoped("/configuration", tenant, { use_case: row.name })}>Configuration file</Link>
      </div>
    </section>
  );
}

// ------------------------------------------------- 2. Sessions & Activity

function ActivityAndSessions({ d, tenant, range, onRange }: { d: DetailDTO; tenant: string; range: Range; onRange: (r: Range) => void }) {
  const row = d.row!;
  return (
    <section id="uc-activity" className="uc-section stack" aria-labelledby="uc-activity-title">
      <SectionHead id="uc-activity" title="Sessions & Activity" question="What happened when this AI use case ran?" />
      <div className="grid stats">
        <Stat label={`Requests, last ${goDuration(d.counter_windows?.requests_denied)}`} value={integer(row.requests)} />
        <Stat label="Denied by Talon" value={integer(row.denied)} />
        <Stat label={`Provider fallbacks, last ${goDuration(d.counter_windows?.fallbacks)}`} value={integer(row.fallbacks)} />
        <Stat label={`Failed sessions, last ${goDuration(d.counter_windows?.failed_sessions)}`} value={integer(row.failed_sessions)} />
      </div>
      {row.causes && row.causes.length > 0 ? (
        <div className="notice warn" role="status">
          <div>
            <strong>Why this health:</strong>
            <ul className="small">{row.causes.map((c) => <li key={c.kind}><code>{c.kind}</code> — {c.detail}</li>)}</ul>
          </div>
        </div>
      ) : null}
      <ActivitySection tenant={tenant} agent={row.name} range={range} onRange={onRange} />
      <RecentDecisions d={d} />
      <section className="card" aria-labelledby="uc-sessions">
        <div className="card-head">
          <h3 id="uc-sessions">Recent sessions</h3>
          <Link to={scoped("/sessions", tenant, { agent: row.name })}>All sessions of {row.name}</Link>
        </div>
        <div className="card-body"><RecentSessions d={d} tenant={tenant} /></div>
      </section>
    </section>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
    </div>
  );
}

// RecentDecisions: this use case's newest decisions in plain language first,
// then the record type and the explanation code, each linked to its signed
// evidence and, when it has one, its session.
function RecentDecisions({ d }: { d: DetailDTO }) {
  const rd = d.recent_decisions;
  const records: EvidenceIndex[] = rd?.records ?? [];
  return (
    <section className="card" aria-labelledby="uc-decisions">
      <div className="card-head">
        <h3 id="uc-decisions">Recent decisions</h3>
        <span className="small muted">newest first · at most {rd?.limit ?? 0} · the rows <code>talon audit list --json</code> prints</span>
      </div>
      {rd ? <AvailabilityNotice a={rd.availability} what="Recent decisions" /> : null}
      {rd && isMeasurement(rd.availability) && records.length === 0 ? <EmptyState title="No decision recorded for this AI use case" /> : null}
      {records.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Time (UTC)</th><th>What happened</th><th>Record</th><th>Session</th><th>Evidence</th></tr></thead>
            <tbody>
              {records.map((e) => {
                const story = outcomeStory(e.outcome);
                return (
                  <tr key={e.id} data-evidence={e.id}>
                    <td title={utc(e.timestamp)}>{utcShort(e.timestamp)}</td>
                    <td>
                      <span className="story">
                        <span><Badge tone={story.tone}>{story.headline}</Badge>{e.outcome?.tool ? <> <span className="chip">{e.outcome.tool}</span></> : null}{e.model_used ? <> <span className="chip">{e.model_used}</span></> : null}</span>
                        <span className="small muted">{e.primary_explanation_reason ?? ""}</span>
                      </span>
                    </td>
                    <td><code className="small">{e.invocation_type}</code>{e.primary_explanation_code ? <div className="small"><code>{e.primary_explanation_code}</code></div> : null}</td>
                    <td>{e.session_id ? <Link to={scoped(`/sessions/${encodeURIComponent(e.session_id)}`, e.tenant_id, { agent: e.agent_id })}>{e.session_id}</Link> : <span className="muted small">standalone</span>}</td>
                    <td><Link to={scoped(`/evidence/${encodeURIComponent(e.id)}`, e.tenant_id)}>{e.id}</Link></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
      <div className="card-body small muted">
        Advertised tools are not invocations: a forbidden tool removed from the tool list appears here only if a client actually attempted it. Only traffic through Talon's gateway and MCP proxy is listed.
      </div>
    </section>
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
                  <td><Link to={scoped(`/sessions/${encodeURIComponent(s.id)}`, tenant, { agent: d.row?.name })}>{s.external_session_id || s.id}</Link></td>
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
      <span className="small muted">Showing at most {list.limit} of each kind. Managed sessions have a lifecycle Talon tracks; observed ones are ids seen on evidence (for example asserted by the client), with no lifecycle inferred.</span>
    </div>
  );
}

// ---------------------------------------------------- 3. Policy & Runtime

function PolicyAndRuntime({ d, tenant }: { d: DetailDTO; tenant: string }) {
  const row = d.row!;
  const roles = (d.runtime.roles ?? []).filter((r) => r.role !== "native" || r.state !== "not_configured");
  const rejected = (d.runtime.processes ?? []).filter((p) => p.current && p.catalog?.reload_rejected);
  const issues = d.issues ?? [];
  return (
    <section id="uc-policy" className="uc-section stack" aria-labelledby="uc-policy-title">
      <SectionHead id="uc-policy" title="Policy & Runtime" question="What is permitted, and which policy is currently active?" />
      {row.config_error ? <div className="notice error" role="alert"><div><strong>Configuration error:</strong> {row.config_error}</div></div> : null}
      {issues.map((i) => (
        <div key={i.path} className="notice warn" role="status"><div><strong>{humanize(i.status)}:</strong> <code>{i.path}</code> — {i.reason}</div></div>
      ))}
      {rejected.map((p) => (
        <div key={p.instance_id} className="notice warn" role="status">
          <div><strong>Rejected reload</strong> on process <code>{p.instance_id}</code>: it keeps serving its previous generation{p.catalog?.rejected_at ? ` since ${utc(p.catalog.rejected_at)}` : ""}.
            {(p.catalog?.rejected_causes ?? []).map((c) => <div key={c} className="small">{c}</div>)}
          </div>
        </div>
      ))}
      <section className="card section" aria-labelledby="uc-effective">
        <div className="card-head">
          <h2 id="uc-effective">Effective policy</h2>
          <Link to={scoped("/configuration", tenant, { use_case: row.name })}>Open in Configuration</Link>
        </div>
        <div className="card-body">
          <p className="small muted">
            The organization baseline, this agent file's override and the hard constraints, as the gateway's own resolver combines them, with the winning rule. The LLM gateway and the MCP proxy are proved active separately: a running proxy proves nothing about the gateway policy, and the reverse.
          </p>
          <EffectivePolicySection name={row.name} tenant={tenant} />
        </div>
      </section>
      <section className="card" aria-labelledby="uc-runtime">
        <div className="card-head">
          <h3 id="uc-runtime">Runtime processes</h3>
          <Link to={scoped("/system", tenant)}>System</Link>
        </div>
        <div className="card-body">
          <AvailabilityNotice a={d.runtime.availability} what="Runtime" />
          {d.runtime.availability.state === "ok" ? <RoleTable roles={roles} /> : null}
          <p className="small muted">Shared by every AI use case of this installation. Policy digest of the current file: {row.policy_digest ? <CopyableIdentifier value={row.policy_digest} label="policy digest" /> : "—"}</p>
        </div>
      </section>
    </section>
  );
}

// -------------------------------------------------------------- 4. Costs

function CostsSection({ d, tenant }: { d: DetailDTO; tenant: string }) {
  const row = d.row!;
  const report = d.costs.report;
  return (
    <section id="uc-costs" className="uc-section stack" aria-labelledby="uc-costs-title">
      <SectionHead id="uc-costs" title="Costs" question="What does this AI use case cost?" />
      <section className="card section" aria-labelledby="uc-costs-summary">
        <div className="card-head">
          <h2 id="uc-costs-summary">Spend and budgets</h2>
          <div className="row">
            <Link to={scoped("/sessions", tenant, { agent: row.name })}>Sessions behind these amounts</Link>
            <Link to={scoped("/costs", tenant, { agent: row.name })}>Open in Costs</Link>
          </div>
        </div>
        <div className="card-body">
          <AvailabilityNotice a={d.costs.availability} what="Costs" />
          {report ? (
            <div className="grid two">
              <dl className="facts">
                <dt>Today (UTC day)</dt>
                <dd><CurrencyAmount amount={fieldValue(report, "today_eur")} currency={report.currency} reason={warningsFor(report, ["day window"]).join("; ")} /></dd>
                <dt>Last 7 days</dt>
                <dd><CurrencyAmount amount={fieldValue(report, "seven_days_eur")} currency={report.currency} reason={warningsFor(report, ["7-day", "seven"]).join("; ")} /></dd>
                <dt>This month (UTC)</dt>
                <dd><CurrencyAmount amount={fieldValue(report, "month_eur")} currency={report.currency} reason={warningsFor(report, ["month window"]).join("; ")} /></dd>
                <dt>Unpriced records</dt>
                <dd>{report.unpriced_records > 0 ? <Badge tone="warn" plain>{integer(report.unpriced_records)} — amounts understate spend</Badge> : "0"}</dd>
              </dl>
              <div className="stack">
                <div><strong className="small">Daily budget</strong></div>
                <BudgetUtilization b={report.daily_budget} currency={report.currency} unavailable={(report.unavailable_fields ?? []).includes("daily_budget")} reason={warningsFor(report, ["budget"]).join("; ")} />
                <div><strong className="small">Monthly budget</strong></div>
                <BudgetUtilization b={report.monthly_budget} currency={report.currency} unavailable={(report.unavailable_fields ?? []).includes("monthly_budget")} reason={warningsFor(report, ["budget"]).join("; ")} />
                {d.costs.budget_note ? <span className="small muted">{d.costs.budget_note}</span> : null}
              </div>
            </div>
          ) : null}
          {(row.causes ?? []).filter((c) => c.kind.includes("budget")).map((c) => (
            <div key={c.kind} className="notice warn" role="status"><div><strong>Cost intervention:</strong> <code>{c.kind}</code> — {c.detail}</div></div>
          ))}
          <p className="small muted">Recorded cost per evidence record, in the pricing table's currency; denied requests record no provider cost. No forecast or savings estimate is made.</p>
        </div>
      </section>
      <div className="grid two">
        <Attribution tenant={tenant} agent={row.name} breakdown="model" />
        <Attribution tenant={tenant} agent={row.name} breakdown="provider" />
      </div>
    </section>
  );
}

function Attribution({ tenant, agent, breakdown }: { tenant: string; agent: string; breakdown: Breakdown }) {
  const res = useApi<CostsDTO>(api("/costs"), { tenant, agent, breakdown });
  const r = res.data?.report;
  const rows = r ? breakdownRows(r, breakdown) : [];
  const title = breakdown === "model" ? "By model" : "By provider";
  return (
    <section className="card" aria-labelledby={`uc-by-${breakdown}`}>
      <div className="card-head"><h3 id={`uc-by-${breakdown}`}>{title}</h3></div>
      {res.error ? <ErrorState error={res.error} what={title.toLowerCase()} onRetry={res.reload} /> : null}
      {!res.data && res.loading ? <Loading what={title.toLowerCase()} /> : null}
      {res.data ? <AvailabilityNotice a={res.data.availability} what={title} /> : null}
      {r && rows.length === 0 ? <div className="card-body small muted">No priced record this month.</div> : null}
      {r && rows.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead><tr><th>{breakdown === "model" ? "Model" : "Provider"}</th><th className="num">Today</th><th className="num">Month</th></tr></thead>
            <tbody>
              {rows.map((x) => (
                <tr key={x.key}>
                  <td><code>{x.key || "(not recorded)"}</code></td>
                  <td className="num">{x.day === null ? <span className="muted">unavailable</span> : money(x.day, r.currency)}</td>
                  <td className="num">{x.month === null ? <span className="muted">unavailable</span> : money(x.month, r.currency)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
