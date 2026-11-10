import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { Costs as CostsDTO, Meta, UseCases as UseCasesDTO } from "../api/types";
import { PageHead } from "../components/Layout";
import { AvailabilityNotice, Badge, BudgetUtilization, CurrencyAmount, DetailSection, EmptyState, ErrorState, Loading, SourceFreshness } from "../components/ui";
import { BREAKDOWN_FIELDS, breakdownRows, fieldValue, rowSpend, warningsFor, type Breakdown } from "../lib/costs";
import { integer, money, utc } from "../lib/format";
import { scoped, useScope } from "../lib/scope";

// Costs from costs.Build, the projection behind `talon costs --json`. The
// windows are fixed UTC accounting windows; every figure the report lists in
// unavailable_fields is shown as unavailable with its warning, never as the
// number it still carries for compatibility.
export function Costs() {
  const { tenant, params, set } = useScope();
  const agent = params.get("agent") ?? "";
  const breakdown = (params.get("breakdown") as Breakdown) || "agents";
  const res = useApi<CostsDTO>(api("/costs"), { tenant, agent, breakdown });
  const c = res.data;
  const r = c?.report;
  const unavailable = new Set(r?.unavailable_fields ?? []);
  return (
    <>
      <PageHead
        title="Costs"
        lede="Recorded spend by AI use case, model and provider against the effective caps, from the same projection as talon costs."
        actions={<button type="button" onClick={res.reload} disabled={res.loading}>Refresh</button>}
      />
      <div className="filter-bar">
        <label>
          AI use case
          <input defaultValue={agent} placeholder="all in tenant" onBlur={(e) => set("agent", e.target.value.trim())} onKeyDown={(e) => { if (e.key === "Enter") set("agent", (e.target as HTMLInputElement).value.trim()); }} />
        </label>
        <div className="segmented" role="group" aria-label="Breakdown">
          {(Object.keys(BREAKDOWN_FIELDS) as Breakdown[]).map((b) => (
            <button key={b} type="button" aria-pressed={breakdown === b} onClick={() => set("breakdown", b === "agents" ? "" : b)}>
              {BREAKDOWN_FIELDS[b].label}
            </button>
          ))}
        </div>
      </div>
      {!tenant && !agent ? <FleetSpend /> : null}
      {!tenant ? (
        <div className="notice info" role="note">
          <div>The cost report below needs one tenant: with all tenants selected it shows tenant <strong>{r?.tenant_id ?? "default"}</strong>. Pick a tenant in the header to change it.</div>
        </div>
      ) : null}
      {res.error ? <ErrorState error={res.error} what="costs" onRetry={res.reload} /> : null}
      {!c && res.loading ? <Loading what="costs" /> : null}
      {c ? <AvailabilityNotice a={c.availability} what="Cost report" /> : null}
      {c && r ? (
        <div className="grid">
          <section aria-labelledby="cost-summary">
            <h2 id="cost-summary" className="visually-hidden">Summary</h2>
            <div className="grid stats">
              <Figure label="Today" sub={`UTC ${utc(r.window.day_start)} – ${utc(r.window.day_end)}`} amount={fieldValue(r, "today_eur")} currency={r.currency} reason={warningsFor(r, ["day window"]).join("; ")} />
              <Figure label="Last 7 days" sub={`from ${utc(r.window.week_start)}`} amount={fieldValue(r, "seven_days_eur")} currency={r.currency} reason={warningsFor(r, ["seven_days window", "seven_days_eur"]).join("; ")} />
              <Figure label="This calendar month" sub={`UTC ${utc(r.window.month_start)} – ${utc(r.window.month_end)}`} amount={fieldValue(r, "month_eur")} currency={r.currency} reason={warningsFor(r, ["month window"]).join("; ")} />
              <div className="card stat">
                <div className="label">Pricing</div>
                <div className="value">{r.unpriced_records > 0 ? <Badge tone="warn">{integer(r.unpriced_records)} unpriced</Badge> : <Badge tone="ok" plain>all priced</Badge>}</div>
                <div className="sub">{r.unpriced_records > 0 ? "allowed model calls this month without a pricing-table price: amounts understate spend" : "every allowed model call this month had a price"}</div>
              </div>
            </div>
            <div className="row small muted">
              <span>Currency: <strong>{r.currency}</strong> (the active pricing table; amounts are never converted).</span>
              <span>Scope: tenant {r.tenant_id}{r.agent_id ? `, AI use case ${r.agent_id}` : ""}.</span>
              <SourceFreshness a={c.availability} />
            </div>
          </section>

          {r.warnings && r.warnings.length > 0 ? (
            <div className="notice warn" role="status">
              <div>
                <strong>Some figures are not measurements.</strong>
                <ul className="small">{r.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
              </div>
            </div>
          ) : null}

          <div className="grid two">
            <DetailSection title="Daily budget" id="budget-daily">
              <BudgetUtilization b={r.daily_budget} currency={r.currency} unavailable={unavailable.has("daily_budget")} reason={warningsFor(r, ["budget"]).join("; ")} />
            </DetailSection>
            <DetailSection title="Monthly budget" id="budget-monthly">
              <BudgetUtilization b={r.monthly_budget} currency={r.currency} unavailable={unavailable.has("monthly_budget")} reason={warningsFor(r, ["budget"]).join("; ")} />
            </DetailSection>
          </div>
          {c.budget_note ? <p className="small muted">{c.budget_note}</p> : null}
          {!r.agent_id && !r.daily_budget && !r.monthly_budget && !unavailable.has("daily_budget") ? (
            <p className="small muted">Effective caps are per AI use case: choose one above, or open it from the table below.</p>
          ) : null}

          <Breakdowns c={c} breakdown={breakdown} tenant={tenant} />

          {r.currencies ? (
            <DetailSection title="Priced records by currency" id="currencies">
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Window</th><th>Currencies (records)</th></tr></thead>
                  <tbody>
                    {Object.entries(r.currencies).map(([win, m]) => (
                      <tr key={win}><td>{win.replace("_", " ")}</td><td>{Object.entries(m).map(([cur, n]) => `${cur || `(unstamped, counted as ${r.currency})`}: ${n}`).join(", ")}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </DetailSection>
          ) : null}
        </div>
      ) : null}
    </>
  );
}

// FleetSpend: with all tenants selected, the month-to-date spend of every AI
// use case in every tenant against its effective cap, from the canonical
// fleet rows (the same as talon agents). Rows are per (tenant, use case), so
// two tenants' use cases with one name are never merged, and amounts in
// different currencies are not summed.
function FleetSpend() {
  const res = useApi<{ meta: Meta; use_cases: UseCasesDTO }>(api("/use-cases"), {});
  const rows = [...(res.data?.use_cases.rows ?? [])].sort((a, b) => (rowSpend(b, "spend_month") ?? -1) - (rowSpend(a, "spend_month") ?? -1) || a.name.localeCompare(b.name));
  return (
    <section className="card" aria-labelledby="fleet-spend" data-testid="fleet-spend">
      <div className="card-head">
        <h2 id="fleet-spend">All tenants: month-to-date spend per configured AI use case</h2>
        <span className="small muted">month to date (UTC) · canonical fleet rows, as <code>talon agents</code></span>
      </div>
      <div className="card-body"><p className="small muted">Only use cases in the current configuration are listed. Spend recorded for a use case that is no longer configured is not in this table; choose a tenant for its full cost report.</p></div>
      {res.error ? <ErrorState error={res.error} what="fleet spend" onRetry={res.reload} /> : null}
      {!res.data && res.loading ? <Loading what="fleet spend" /> : null}
      {res.data ? <AvailabilityNotice a={res.data.use_cases.availability} what="Fleet spend" /> : null}
      {rows.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead><tr><th>AI use case</th><th>Tenant</th><th className="num">Today</th><th className="num">Month to date</th><th className="num">Effective monthly cap</th><th>Investigate</th></tr></thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.tenant_id}/${row.name}`}>
                  <td><Link to={scoped(`/use-cases/${encodeURIComponent(row.name)}`, row.tenant_id)}>{row.name}</Link></td>
                  <td>{row.tenant_id}</td>
                  <td className="num"><CurrencyAmount amount={rowSpend(row, "spend_day")} currency={row.currency} reason="priced records in another currency" /></td>
                  <td className="num"><CurrencyAmount amount={rowSpend(row, "spend_month")} currency={row.currency} reason="priced records in another currency" /></td>
                  <td className="num">{row.monthly_cap > 0 ? money(row.monthly_cap, row.currency) : <span className="muted">no cap</span>}</td>
                  <td className="row small">
                    <Link to={`${scoped(`/use-cases/${encodeURIComponent(row.name)}`, row.tenant_id)}#uc-costs`}>Costs</Link>
                    <Link to={scoped("/sessions", row.tenant_id, { agent: row.name })}>Sessions</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <div className="card-body small muted">Spend across tenants is not added up: each row keeps its own currency and tenant.</div>
    </section>
  );
}

function Figure({ label, sub, amount, currency, reason }: { label: string; sub: string; amount: number | null; currency: string; reason?: string }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value"><CurrencyAmount amount={amount} currency={currency} reason={reason} /></div>
      <div className="sub">{amount === null && reason ? reason : sub}</div>
    </div>
  );
}

function Breakdowns({ c, breakdown, tenant }: { c: CostsDTO; breakdown: Breakdown; tenant: string }) {
  const r = c.report!;
  const rows = breakdownRows(r, breakdown);
  const label = BREAKDOWN_FIELDS[breakdown].label;
  return (
    <section className="card" aria-labelledby="breakdown-title">
      <div className="card-head">
        <h2 id="breakdown-title">By {label === "AI use case" ? label : label.toLowerCase()}</h2>
        <span className="small muted">Today and this calendar month, UTC, in {r.currency}</span>
      </div>
      {rows.length === 0 ? (
        <EmptyState title="No recorded spend in this scope" />
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>{label}</th><th className="num">Today</th><th className="num">This month</th>{breakdown === "agents" ? <th>Drill down</th> : null}</tr></thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.key}>
                  <td>{breakdown === "agents" ? <Link to={scoped(`/use-cases/${encodeURIComponent(row.key)}`, tenant || r.tenant_id)}>{row.key}</Link> : <code>{row.key}</code>}</td>
                  <td className="num"><CurrencyAmount amount={row.day} currency={r.currency} reason="not comparable in this currency; see warnings" /></td>
                  <td className="num"><CurrencyAmount amount={row.month} currency={r.currency} reason="not comparable in this currency; see warnings" /></td>
                  {breakdown === "agents" ? <td><Link to={scoped("/sessions", tenant || r.tenant_id, { agent: row.key })}>Sessions</Link></td> : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
