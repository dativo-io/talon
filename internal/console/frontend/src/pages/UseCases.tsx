import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { Health, UseCases as UseCasesDTO, Meta } from "../api/types";
import { PageHead } from "../components/Layout";
import { AvailabilityNotice, Badge, EmptyState, ErrorState, Loading, SourceFreshness, UseCaseHealth } from "../components/ui";
import { isMeasurement } from "../lib/availability";
import { goDuration, integer, money, relative, utc } from "../lib/format";
import { scoped, useScope } from "../lib/scope";

type Resp = { meta: Meta; use_cases: UseCasesDTO };

export function UseCases() {
  const { tenant, params, set } = useScope();
  const res = useApi<Resp>(api("/use-cases"), { tenant });
  const q = params.get("q") ?? "";
  const health = (params.get("health") ?? "") as Health | "";
  const [draft, setDraft] = useState(q);
  const uc = res.data?.use_cases;
  const rows = useMemo(() => {
    const all = uc?.rows ?? [];
    return all.filter((r) => (!q || r.name.toLowerCase().includes(q.toLowerCase())) && (!health || r.health === health));
  }, [uc, q, health]);
  return (
    <>
      <PageHead
        title="AI Use Cases"
        lede="Every configured AI use case: one agent.talon.yaml, one traffic identity. Health and order are Talon's."
        actions={<button type="button" onClick={res.reload} disabled={res.loading}>Refresh</button>}
      />
      {res.error ? <ErrorState error={res.error} what="AI use cases" onRetry={res.reload} /> : null}
      {!res.data && res.loading ? <Loading what="AI use cases" /> : null}
      {uc ? (
        <section className="card">
          <div className="card-head">
            <form
              className="filter-bar"
              role="search"
              onSubmit={(e) => {
                e.preventDefault();
                set("q", draft.trim());
              }}
            >
              <label>
                Name
                <input value={draft} onChange={(e) => setDraft(e.target.value)} onBlur={() => set("q", draft.trim())} placeholder="filter by name" />
              </label>
              <label>
                Health
                <select value={health} onChange={(e) => set("health", e.target.value)}>
                  <option value="">Any</option>
                  <option value="needs-attention">Needs attention</option>
                  <option value="blocked">Blocked</option>
                  <option value="stopped">Stopped</option>
                  <option value="healthy">Healthy</option>
                </select>
              </label>
            </form>
            <SourceFreshness a={uc.availability} />
          </div>
          <div className="card-body">
            <AvailabilityNotice a={uc.availability} what="AI use cases" />
            <p className="small muted">
              Health basis: {uc.health_basis === "projected_from_store" ? "projected from persisted evidence and configuration (not a liveness check)" : "live runtime"}.
              Request, denial and fallback counts cover the last {goDuration(uc.counter_windows?.requests_denied)}, failed sessions the last {goDuration(uc.counter_windows?.failed_sessions)} (the windows Talon's health uses); month spend uses the UTC calendar month.
            </p>
          </div>
          {isMeasurement(uc.availability) && (uc.rows ?? []).length === 0 ? <EmptyState title="No AI use case is configured" /> : null}
          {rows.length === 0 && (uc.rows ?? []).length > 0 ? <EmptyState title="No AI use case matches these filters" /> : null}
          {rows.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>AI use case</th>
                    <th>State</th>
                    <th>Health</th>
                    <th>Why</th>
                    <th className="num">Month spend</th>
                    <th className="num">Monthly cap</th>
                    <th className="num">Requests ({goDuration(uc.counter_windows?.requests_denied)})</th>
                    <th className="num">Denied ({goDuration(uc.counter_windows?.requests_denied)})</th>
                    <th className="num">Fallbacks ({goDuration(uc.counter_windows?.fallbacks)})</th>
                    <th className="num">Failed sessions ({goDuration(uc.counter_windows?.failed_sessions)})</th>
                    <th className="num">Last request</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={`${r.tenant_id}/${r.name}`}>
                      <td>
                        <Link to={scoped(`/use-cases/${encodeURIComponent(r.name)}`, tenant || r.tenant_id)}>{r.name}</Link>
                        <div className="small muted">{r.tenant_id}{r.use_case?.department ? ` · ${r.use_case.department}` : ""}</div>
                      </td>
                      <td>{r.state === "enabled" ? "Enabled" : <Badge tone="neutral">Disabled</Badge>}</td>
                      <td><UseCaseHealth health={r.health} /></td>
                      <td className="small">{r.why}</td>
                      <td className="num">{money(r.spend_month, r.currency)}</td>
                      <td className="num">{r.monthly_cap > 0 ? money(r.monthly_cap, r.currency) : <span className="muted">none</span>}</td>
                      <td className="num">{integer(r.requests)}</td>
                      <td className="num">{integer(r.denied)}</td>
                      <td className="num">{integer(r.fallbacks)}</td>
                      <td className="num">{integer(r.failed_sessions)}</td>
                      <td className="num" title={utc(r.last_run)}>{relative(r.last_run)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </section>
      ) : null}
    </>
  );
}
