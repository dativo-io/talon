import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { Configuration as ConfigDTO, UseCaseConfig } from "../api/types";
import { PageHead } from "../components/Layout";
import { AvailabilityNotice, Badge, Chips, DetailSection, EmptyState, ErrorState, Loading, SourceFreshness } from "../components/ui";
import { utc } from "../lib/format";
import type { ActiveFile } from "../api/types";
import { ActiveBadge, roleLabel, RuntimeStateBadge } from "../components/RuntimeStatus";
import { scoped, useScope } from "../lib/scope";
import { Link } from "react-router-dom";

// Configuration as the files read NOW, summarised server-side from an
// allowlist of fields (no secret values, no raw file contents). This is not
// proof of what a running process enforces: each file states whether a
// running process proves it loaded (#538); the effective policy with rule
// provenance is on each AI use case's page (#305).
export function Configuration() {
  const { tenant, params, set } = useScope();
  const focus = params.get("use_case") ?? "";
  const res = useApi<ConfigDTO>(api("/configuration"), { tenant });
  const c = res.data;
  const items = (c?.use_cases.items ?? []).filter((u) => !focus || u.name === focus);
  return (
    <>
      <PageHead
        title="Configuration"
        lede="How Talon is configured: what the installation shares, what each AI use case declares, and what a running process proves it loaded."
        actions={<button type="button" onClick={res.reload} disabled={res.loading}>Refresh</button>}
      />
      {res.error ? <ErrorState error={res.error} what="configuration" onRetry={res.reload} /> : null}
      {!c && res.loading ? <Loading what="configuration" /> : null}
      {c ? (
        <div className="grid">
          <div className="notice info" role="note">
            <div>
              <strong>Current file contents, read {utc(c.read_at)}.</strong> Below each file: whether a running process proves it loaded these bytes.{" "}
              The effective policy with rule provenance is on each AI use case's page.
            </div>
          </div>
          <section className="stack" aria-labelledby="cfg-installation">
            <div className="section-head">
              <h2 id="cfg-installation">Installation configuration</h2>
              <Badge tone="neutral">Shared by every tenant</Badge>
            </div>
            <p className="small muted">
              The organization baseline, the gateway and providers, and the MCP proxy are installation-wide{tenant ? `; they apply to tenant ${tenant} as to every other` : ""}.
            </p>
            <Active c={c} />
            {c.issues && c.issues.length > 0 ? (
              <div className="notice warn" role="status">
                <div>
                  <strong>Configuration files that could not be used:</strong>
                  <ul className="small">{c.issues.map((i) => <li key={i.path}><code>{i.path}</code> — {i.status}: {i.reason}</li>)}</ul>
                </div>
              </div>
            ) : null}
            <Organization c={c} />
            <Proxy c={c} />
          </section>
          <section className="stack" aria-labelledby="cfg-tenant">
            <div className="section-head">
              <h2 id="cfg-tenant">{tenant ? `Tenant ${tenant}: AI use cases` : "AI use cases in every tenant"}</h2>
              <Badge tone="info">{tenant ? "Tenant scope" : "All tenants"}</Badge>
            </div>
            <p className="small muted">
              Talon has no tenant-wide policy layer. Each AI use case's effective policy is the shared organization baseline, its own agent file's
              override and the hard constraints, enforced separately at the LLM gateway and the MCP proxy. Open a use case's effective policy for the
              winning rule of each field.
            </p>
            <section className="card" aria-labelledby="cfg-usecases">
              <div className="card-head">
                <h2 id="cfg-usecases">AI use cases</h2>
                <div className="row">
                  {focus ? <button type="button" onClick={() => set("use_case", "")}>Show all</button> : null}
                  <SourceFreshness a={c.use_cases.availability} />
                </div>
              </div>
              <AvailabilityNotice a={c.use_cases.availability} what="Agent configuration" />
              {c.use_cases.availability.state === "empty" ? <EmptyState title={tenant ? `No agent file declares tenant ${tenant}` : "No agent file in this scope"} /> : null}
              <div className="card-body stack">
                {items.map((u) => <UseCaseCard key={`${u.tenant_id}/${u.name}`} u={u} />)}
              </div>
            </section>
          </section>
        </div>
      ) : null}
    </>
  );
}

function Organization({ c }: { c: ConfigDTO }) {
  const o = c.organization;
  return (
    <DetailSection title="Organization baseline (shared)" id="cfg-org" actions={<SourceFreshness a={o.availability} />}>
      <AvailabilityNotice a={o.availability} what="Organization configuration" />
      {o.availability.state === "empty" ? <p className="muted">{o.availability.note}</p> : null}
      {o.availability.state === "ok" ? (
        <div className="stack">
          <p className="small muted">Source: <code>{o.source_path}</code></p>
          <div className="grid two">
            <dl className="facts">
              <dt>PII action</dt><dd>{o.pii_action || "—"}{o.response_pii_action ? ` (responses: ${o.response_pii_action})` : ""}</dd>
              <dt>Default daily cap</dt><dd>{o.daily_cost || "—"}</dd>
              <dt>Default monthly cap</dt><dd>{o.monthly_cost || "—"}</dd>
              <dt>Session cost cap</dt><dd>{o.session_cost || "—"}</dd>
              <dt>Ceiling (daily / monthly / session)</dt><dd>{o.max_daily_cost || "—"} / {o.max_monthly_cost || "—"} / {o.max_session_cost || "—"}</dd>
              <dt>Retry</dt><dd>{o.retry ? `${o.retry.max_attempts} attempts${o.retry.initial_backoff ? `, backoff ${o.retry.initial_backoff}–${o.retry.max_backoff ?? ""}` : ""}` : "—"}</dd>
            </dl>
            <dl className="facts">
              <dt>Allowed providers</dt><dd><Chips items={o.allowed_providers} empty="no restriction" /></dd>
              <dt>Allowed models</dt><dd><Chips items={o.allowed_models} empty="no restriction" /></dd>
              <dt>Blocked models</dt><dd><Chips items={o.blocked_models} /></dd>
              <dt>Forbidden tools</dt><dd><Chips items={o.forbidden_tools} /></dd>
              <dt>Tool policy action</dt><dd>{o.tool_policy_action || "—"}</dd>
              <dt>Prompt / response logging</dt><dd>{o.log_prompts ? "prompts" : "no prompts"} · {o.log_responses ? "responses" : "no responses"}</dd>
              <dt>Cost webhook</dt><dd>{o.cost_webhook_configured ? "configured (URL not shown)" : "not configured"}</dd>
            </dl>
          </div>
          <p className="small muted">Amounts are in the pricing table's currency.</p>
          {o.providers && o.providers.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Provider</th><th>Enabled</th><th>Endpoint</th><th>Region</th><th>Credential</th><th>Models</th><th>Fallback</th></tr></thead>
                <tbody>
                  {o.providers.map((p) => (
                    <tr key={p.name}>
                      <td><code>{p.name}</code></td>
                      <td>{p.enabled ? "yes" : "no"}</td>
                      <td><code>{p.endpoint ?? "—"}</code></td>
                      <td>{p.region ?? "—"}</td>
                      <td className="small">{p.secret_name ? <>vault secret <code>{p.secret_name}</code></> : p.upstream_auth_mode ?? "—"}</td>
                      <td><Chips items={p.allowed_models} empty="any" /></td>
                      <td><Chips items={p.fallback} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      ) : null}
    </DetailSection>
  );
}

function UseCaseCard({ u }: { u: UseCaseConfig }) {
  return (
    <article className="card" aria-label={`Configuration of ${u.name}`}>
      <div className="card-head">
        <h2>{u.name}</h2>
        <div className="row">
          {u.enabled ? <Badge tone="ok" plain>enabled</Badge> : <Badge tone="neutral">disabled</Badge>}
          <span className="small muted">tenant {u.tenant_id}</span>
        </div>
      </div>
      <div className="card-body grid two">
        <dl className="facts">
          <dt>Source</dt><dd><code>{u.source_path}</code></dd>
          {u.description ? (<><dt>Description</dt><dd>{u.description}</dd></>) : null}
          <dt>Traffic key</dt><dd>{u.key_secret_name ? <>vault secret <code>{u.key_secret_name}</code></> : <span className="muted">none (not a gateway identity)</span>}</dd>
          <dt>Model tier</dt><dd>{u.model_tier}</dd>
          <dt>Allowed providers</dt><dd><Chips items={u.allowed_providers} empty="organization default" /></dd>
          <dt>Allowed models</dt><dd><Chips items={u.allowed_models} empty="organization default" /></dd>
          <dt>Routing</dt>
          <dd>{u.model_routing && u.model_routing.length > 0 ? u.model_routing.map((t) => <div key={t.tier} className="small">tier {t.tier}: {t.primary}{t.fallback_chain?.length ? ` → ${t.fallback_chain.join(" → ")}` : t.fallback ? ` → ${t.fallback}` : ""}</div>) : <span className="muted">—</span>}</dd>
          <dt>Retry</dt><dd>{u.retry ? `${u.retry.max_attempts} attempts` : "—"}</dd>
        </dl>
        <dl className="facts">
          <dt>Cost caps (request / day / month)</dt><dd>{u.cost_per_request || "—"} / {u.cost_daily || "—"} / {u.cost_monthly || "—"}</dd>
          <dt>Session max cost</dt><dd>{u.session_max_cost || "—"}</dd>
          <dt>Rate limit</dt><dd>{u.requests_per_minute ? `${u.requests_per_minute}/min` : "—"}</dd>
          <dt>Allowed tools</dt><dd><Chips items={u.allowed_tools} /></dd>
          <dt>Forbidden tools</dt><dd><Chips items={u.forbidden_tools} /></dd>
          <dt>Data</dt><dd>{[u.input_scan && "input scan", u.output_scan && "output scan", u.redact_pii && "redact PII", u.block_on_pii && "block on PII"].filter(Boolean).join(", ") || "no scanning configured"}</dd>
          <dt>Audit</dt><dd>{u.audit_log_level ?? "default"}{u.audit_retention_days ? `, ${u.audit_retention_days} days` : ""}{u.audit_include_prompts ? ", prompts" : ""}</dd>
          <dt>Policy digest</dt><dd>{u.policy_digest ? <code className="small">{u.policy_digest.slice(0, 16)}…</code> : "—"}</dd>
          <dt>Loaded by a running process</dt><dd><ActiveBadge a={u.active} /></dd>
          <dt>Effective policy</dt><dd><Link to={`${scoped(`/use-cases/${encodeURIComponent(u.name)}`, u.tenant_id)}#uc-effective`}>Effective policy and provenance</Link></dd>
        </dl>
      </div>
    </article>
  );
}

function Proxy({ c }: { c: ConfigDTO }) {
  const p = c.mcp_proxy;
  return (
    <DetailSection title="MCP proxy (shared)" id="cfg-proxy" actions={<SourceFreshness a={p.availability} />}>
      <AvailabilityNotice a={p.availability} what="MCP proxy configuration" />
      {p.availability.state === "ok" ? (
        <dl className="facts">
          <dt>Source</dt><dd><code>{p.source_path}</code></dd>
          <dt>Proxy</dt><dd>{p.name}</dd>
          <dt>Upstream</dt><dd>{p.vendor} · <code>{p.endpoint}</code>{p.region ? ` · ${p.region}` : ""}</dd>
          <dt>Upstream credential</dt><dd>{p.auth_secret_name ? <>vault secret <code>{p.auth_secret_name}</code></> : "none"}</dd>
          <dt>Allowed tools</dt><dd><Chips items={p.allowed_tools} /></dd>
          <dt>Forbidden tools</dt><dd><Chips items={p.forbidden_tools} /></dd>
          <dt>Rate limit</dt><dd>{p.requests_per_minute ? `${p.requests_per_minute}/min` : "—"}</dd>
        </dl>
      ) : null}
    </DetailSection>
  );
}

function FileMatch({ label, f }: { label: string; f: ActiveFile | undefined }) {
  if (!f) return null;
  return (
    <>
      <dt>{label}</dt>
      <dd>
        {f.matches === null ? <span className="muted">loaded <code className="small">{f.loaded_digest.slice(0, 12)}</code>; not comparable from this console</span>
          : f.matches ? <Badge tone="ok" plain>current file is loaded</Badge> : <Badge tone="warn" plain>file changed since it was loaded</Badge>}
        <div className="small muted">loaded {utc(f.loaded_at)} from <code>{f.loaded_path}</code></div>
      </dd>
    </>
  );
}

// Active: what each current data-plane process reports it loaded (#538).
function Active({ c }: { c: ConfigDTO }) {
  return (
    <DetailSection title="Active configuration" id="cfg-active" actions={<SourceFreshness a={c.active_generation} />}>
      {c.active_generation.state !== "ok" ? (
        <div className="notice info" role="status"><div><strong>Active configuration not proven.</strong> {c.active_generation.note ?? c.active_generation.error}</div></div>
      ) : null}
      {c.active.length === 0 ? <p className="muted">No data-plane process of this installation has reported.</p> : null}
      <div className="stack">
        {c.active.map((a) => (
          <article key={a.instance_id} className="card card-body" aria-label={`Process ${a.instance_id}`}>
            <div className="row"><strong>{a.roles.map(roleLabel).join(" + ")}</strong> <RuntimeStateBadge state={a.state} /> <code className="small">{a.instance_id}</code></div>
            <dl className="facts">
              <dt>Active generation</dt><dd>{a.active_generation ? <code className="small">{a.active_generation.slice(0, 16)}</code> : <span className="muted">not reported</span>}{a.activated_at ? <span className="small muted"> · activated {utc(a.activated_at)}</span> : null}</dd>
              <dt>Agent files</dt><dd>{a.agent_files_match === null ? <span className="muted">not comparable</span> : a.agent_files_match ? <Badge tone="ok" plain>match the active generation</Badge> : <Badge tone="warn" plain>differ from the active generation</Badge>}</dd>
              <dt>Last reload</dt><dd>{!a.reload_enabled ? "reload off" : a.reload_rejected ? <><Badge tone="warn">Rejected</Badge> <span className="small">last-known-good keeps serving{a.rejected_at ? ` since ${utc(a.rejected_at)}` : ""}</span>{(a.rejected_causes ?? []).map((x) => <div key={x} className="small muted">{x}</div>)}</> : "accepted"}</dd>
              <FileMatch label="MCP proxy config" f={a.proxy_config} />
              <FileMatch label="Gateway config" f={a.gateway_config} />
            </dl>
          </article>
        ))}
      </div>
    </DetailSection>
  );
}
