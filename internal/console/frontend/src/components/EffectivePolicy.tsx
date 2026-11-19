import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { ActionArgumentRule, ActionBoundary, ActionDecision, EffectiveFile, EffectivePolicyDTO, EffectiveReport } from "../api/types";
import { AvailabilityNotice, Badge, CopyableIdentifier, DecisionOutcome, ErrorState, Loading } from "./ui";
import { ActiveBadge } from "./RuntimeStatus";
import { humanize, utc } from "../lib/format";
import { scoped } from "../lib/scope";

// EffectivePolicySection renders effective.Report (#305) as four layers that
// are never merged: the current files, whether a running process loaded
// them, the policy compiled from them with rule provenance (each enforcement
// boundary proved on its own), and the last recorded decision with its
// signature check. Every value comes from the server; nothing is inferred
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
          <strong className="small">LLM gateway: </strong>
          {e.proven_active ? <Badge tone="ok">Proven active</Badge> : <Badge tone="info">Compiled from current files, not proven active</Badge>}{" "}
          <span className="small muted">{e.proof.reason}</span>
        </p>
        <p className="small muted">{e.basis}</p>
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
            <p>
              <strong className="small">MCP proxy: </strong>
              {r.mcp_boundary.proven_active ? <Badge tone="ok">Proven active</Badge> : <Badge tone="info">Computed from the current proxy config, not proven active</Badge>}{" "}
              <span className="small muted">{r.mcp_boundary.proof.reason}</span>
            </p>
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
        {r.action_boundary ? <ActionBoundarySection b={r.action_boundary} /> : null}
      </section>

      <section aria-labelledby="eff-last">
        <h3 id="eff-last">4. Last recorded decision</h3>
        {r.last_decision ? (
          <dl className="facts">
            <dt>Evidence</dt><dd><Link to={scoped(`/evidence/${encodeURIComponent(r.last_decision.evidence_id)}`, tenant)}>{r.last_decision.evidence_id}</Link> <span className="small muted">{utc(r.last_decision.timestamp)} · {r.last_decision.invocation_type}</span></dd>
            <dt>Signature</dt><dd>{r.last_decision.verification === "valid" ? <Badge tone="ok">Signature valid</Badge> : <Badge tone="error">Signature invalid: record changed after signing</Badge>}</dd>
            <dt>Outcome</dt><dd><DecisionOutcome o={r.last_decision.outcome} />{r.last_decision.verification === "valid" ? null : <div className="small">Not authenticated: shown only to point at the record.</div>}</dd>
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

// The Action Gateway's effective policy: the company policy composed with
// the use case's own. A baseline ALLOW with argument rules is shown as
// "by arguments", never as an unconditional allow.
function ActionBoundarySection({ b }: { b: ActionBoundary }) {
  const rules = b.argument_rules ?? [];
  const nameRules = b.approval_rules ?? [];
  return (
    <div className="stack" data-testid="action-boundary">
      <h4>Action Gateway</h4>
      <p>
        <strong className="small">Action Gateway: </strong>
        {b.proven_active ? <Badge tone="ok">Proven active</Badge> : <Badge tone="info">Compiled from current files, not proven active</Badge>}{" "}
        <span className="small muted">{b.proof.reason}</span>
      </p>
      <p className="small muted">{b.basis}</p>
      {b.error ? <div className="notice warn" role="status"><div>Effective action policy unavailable: {b.error}</div></div> : null}
      {b.actions.length ? (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Action</th><th>Decision</th><th>Rules that apply</th></tr></thead>
            <tbody>
              {b.actions.map((a) => (
                <tr key={a.action}>
                  <td><code>{a.action}</code></td>
                  <td><ActionVerdict a={a} /></td>
                  <td className="small">
                    {(a.approval_rules ?? []).map((x) => (
                      <div key={x.id}><code>{x.id}</code> ({humanize(x.source)}): approval by {x.approver_groups.join(", ")}</div>
                    ))}
                    {(a.argument_rules ?? []).map((x) => <div key={x.id}><RuleLine r={x} /></div>)}
                    {!a.approval_rules?.length && !a.argument_rules?.length ? <span className="muted">none</span> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {rules.length || nameRules.length ? (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Rule</th><th>Declared by</th><th>Actions</th><th>Condition</th><th>Effect</th></tr></thead>
            <tbody>
              {nameRules.map((x) => (
                <tr key={x.id}>
                  <td><code>{x.id}</code></td>
                  <td>{humanize(x.source)}</td>
                  <td><code>{(x.actions ?? []).join(", ")}</code></td>
                  <td className="muted">every call</td>
                  <td>Require approval by {x.approver_groups.join(", ")}</td>
                </tr>
              ))}
              {rules.map((x) => (
                <tr key={x.id}>
                  <td><code>{x.id}</code></td>
                  <td>{humanize(x.source)}</td>
                  <td><code>{(x.actions ?? []).join(", ")}</code></td>
                  <td><code>{x.condition}</code> <span className="small muted">({x.type})</span></td>
                  <td>{x.effect === "deny" ? "Deny" : `Require approval by ${(x.approver_groups ?? []).join(", ")}`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <dl className="facts">
        {b.forbidden_actions?.length ? (<><dt>Forbidden actions</dt><dd><code>{b.forbidden_actions.join(", ")}</code></dd></>) : null}
        {b.approval_expires_after ? (<><dt>Approvals expire after</dt><dd>{b.approval_expires_after}</dd></>) : null}
        {b.policy_digest ? (<><dt>Approval policy digest</dt><dd><CopyableIdentifier value={b.policy_digest} label="approval policy digest" /></dd></>) : null}
      </dl>
      {rules.length ? (
        <p className="small muted">
          An argument rule only restricts: when its condition holds the call needs approval or is denied; a call whose argument is missing or of another type is denied. A use case can add rules, never lift a company rule.
        </p>
      ) : null}
      {(b.notes ?? []).map((n) => <p key={n} className="small muted">{n}</p>)}
    </div>
  );
}

function ActionVerdict({ a }: { a: ActionDecision }) {
  const from = a.verdict_source ? ` (${humanize(a.verdict_source)})` : "";
  if (a.decision_basis === "arguments") {
    return (
      <>
        <Badge tone="info">Depends on arguments</Badge>
        <div className="small muted">{a.verdict === "ALLOW" ? "allowed" : "approval required"} by name{from}; the rules can make a call stricter</div>
      </>
    );
  }
  if (a.verdict === "DENY") return <Badge tone="error">Denied{from}</Badge>;
  if (a.verdict === "REQUIRE_APPROVAL") return <Badge tone="warn">Approval required{from}</Badge>;
  return <Badge tone="ok" plain>Allowed by policy</Badge>;
}

function RuleLine({ r }: { r: ActionArgumentRule }) {
  return (
    <>
      <code>{r.id}</code> ({humanize(r.source)}): when <code>{r.condition}</code> → {r.effect === "deny" ? "deny" : `approval by ${(r.approver_groups ?? []).join(", ")}`}
    </>
  );
}
