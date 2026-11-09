import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { EffectiveFile, EffectivePolicyDTO, EffectiveReport } from "../api/types";
import { AvailabilityNotice, Badge, CopyableIdentifier, DecisionOutcome, ErrorState, Loading } from "./ui";
import { ActiveBadge } from "./RuntimeStatus";
import { humanize, utc } from "../lib/format";
import { scoped } from "../lib/scope";

// EffectivePolicySection renders effective.Report (#305) as four layers that
// are never merged: the current files, whether a running process loaded
// them, the policy compiled from them with rule provenance, and the last
// recorded decision. Every value comes from the server; nothing is inferred
// here.
export function EffectivePolicySection({ name, tenant }: { name: string; tenant: string }) {
  const res = useApi<EffectivePolicyDTO>(api(`/use-cases/${encodeURIComponent(name)}/effective-policy`), { tenant });
  const d = res.data;
  return (
    <div className="stack" data-testid="effective-policy">
      {res.error ? <ErrorState error={res.error} what="effective policy" onRetry={res.reload} /> : null}
      {!d && res.loading ? <Loading what="effective policy" /> : null}
      {d ? <AvailabilityNotice a={d.availability} what="Effective policy" /> : null}
      {d?.report ? <Layers r={d.report} tenant={tenant || d.report.tenant_id} /> : null}
      <p className="small muted">CLI: <code>talon agents show {name} --effective</code></p>
    </div>
  );
}

function Layers({ r, tenant }: { r: EffectiveReport; tenant: string }) {
  const e = r.effective;
  return (
    <div className="stack">
      <section aria-labelledby="eff-files">
        <h3 id="eff-files">1. Current files</h3>
        <dl className="facts">
          <dt>Agent file</dt><dd><code>{r.current_files.agent_file}</code></dd>
          <dt>Policy digest</dt><dd>{r.current_files.policy_digest ? <CopyableIdentifier value={r.current_files.policy_digest} label="policy digest" /> : "—"}</dd>
          <FileRow label="Gateway config" f={r.current_files.gateway_config} />
          <FileRow label="MCP proxy config" f={r.current_files.proxy_config} />
        </dl>
      </section>

      <section aria-labelledby="eff-loaded">
        <h3 id="eff-loaded">2. Loaded by a running process</h3>
        <ActiveBadge a={r.loaded} />
        {r.loaded.instance_ids?.length ? <p className="small muted">Reported by {r.loaded.instance_ids.join(", ")}</p> : null}
      </section>

      <section aria-labelledby="eff-compiled">
        <h3 id="eff-compiled">3. Effective policy</h3>
        <p>
          {e.proven_active ? <Badge tone="ok">Proven active</Badge> : <Badge tone="info">Compiled from current files, not proven active</Badge>}{" "}
          <span className="small muted">{e.basis}</span>
        </p>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Rule</th><th>Effective</th><th>From</th><th>Every layer</th></tr></thead>
            <tbody>
              {e.rules.map((rule) => (
                <tr key={rule.rule}>
                  <td><code>{rule.rule}</code><div className="small muted">{rule.precedence}</div></td>
                  <td>{rule.effective || <span className="muted">none</span>}</td>
                  <td>{humanize(rule.winner)}</td>
                  <td>
                    <ul className="small plain">
                      {rule.candidates.map((c) => (
                        <li key={c.source + c.field}>
                          {c.applied ? <strong>{c.source}</strong> : <span className="muted">{c.source}</span>} <code>{c.field}</code>: {c.value || <span className="muted">unset</span>}
                        </li>
                      ))}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {e.providers?.length ? (
          <p className="small muted">
            Effective policy digest per provider (signed into gateway evidence):{" "}
            {e.providers.map((p) => <span key={p.name}>{p.name} <code>{p.effective_digest.slice(0, 12)}</code>{p.enabled ? "" : " (disabled)"} </span>)}
          </p>
        ) : null}
        {r.mcp_boundary ? (
          <div className="stack">
            <h4>MCP proxy {r.mcp_boundary.proxy} <span className="small muted">({r.mcp_boundary.scope})</span></h4>
            {r.mcp_boundary.error ? <div className="notice warn" role="status"><div>MCP proxy config unusable: {r.mcp_boundary.error}</div></div> : null}
            {r.mcp_boundary.tools.length ? (
              <table>
                <thead><tr><th>Tool</th><th>Decision before dispatch</th></tr></thead>
                <tbody>
                  {r.mcp_boundary.tools.map((t) => (
                    <tr key={t.tool}>
                      <td><code>{t.tool}</code></td>
                      <td>
                        {t.allowed ? <Badge tone="ok" plain>allowed</Badge> : <Badge tone="error">denied at {humanize(t.stage)}{t.matched ? ` (${t.matched})` : ""}</Badge>}
                        {t.reasons?.length ? <div className="small muted">{t.reasons.join("; ")}</div> : null}
                        {t.note ? <div className="small muted">{t.note}</div> : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : null}
          </div>
        ) : null}
      </section>

      <section aria-labelledby="eff-last">
        <h3 id="eff-last">4. Last recorded decision</h3>
        {r.last_decision ? (
          <dl className="facts">
            <dt>Evidence</dt><dd><Link to={scoped(`/evidence/${encodeURIComponent(r.last_decision.evidence_id)}`, tenant)}>{r.last_decision.evidence_id}</Link> <span className="small muted">{utc(r.last_decision.timestamp)} · {r.last_decision.invocation_type}</span></dd>
            <dt>Outcome</dt><dd><DecisionOutcome o={r.last_decision.outcome} /></dd>
            {r.last_decision.primary_explanation_code ? (<><dt>Why</dt><dd><code>{r.last_decision.primary_explanation_code}</code> {r.last_decision.primary_explanation_reason}</dd></>) : null}
            <dt>Recorded agent policy vs current file</dt><dd>{humanize(r.last_decision.agent_file)}</dd>
            <dt>Recorded effective policy</dt><dd>{humanize(r.last_decision.effective_policy)}</dd>
          </dl>
        ) : <p className="muted">No decision recorded for this AI use case.</p>}
        {r.last_decision?.note ? <p className="small muted">{r.last_decision.note}</p> : null}
      </section>
      {r.notes?.length ? <ul className="small muted">{r.notes.map((n) => <li key={n}>{n}</li>)}</ul> : null}
    </div>
  );
}

function FileRow({ label, f }: { label: string; f: EffectiveFile | undefined }) {
  let v;
  if (!f) v = <span className="muted">not given</span>;
  else if (f.error) v = <><code>{f.path}</code> <Badge tone="warn" plain>unusable</Badge> <span className="small">{f.error}</span></>;
  else if (!f.present) v = <><code>{f.path}</code> <span className="muted">absent</span></>;
  else v = <><code>{f.path}</code> <span className="small muted">sha256 {f.digest?.slice(0, 12)}</span></>;
  return <><dt>{label}</dt><dd>{v}</dd></>;
}
