import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { ActionArgumentRule, ActionBoundary, ActionDecision, EffectiveFile, EffectivePolicyDTO, EffectiveReport, UseCaseCredential, UseCaseNextStep } from "../api/types";
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
        <p className="small muted">The newest request decision recorded for this use case at any boundary. Registration, enable/disable and reload records are operator events, not decisions; how the caller was identified is section 5.</p>
        {r.last_decision ? (
          <dl className="facts">
            <dt>Evidence</dt><dd><Link to={scoped(`/evidence/${encodeURIComponent(r.last_decision.evidence_id)}`, tenant)}>{r.last_decision.evidence_id}</Link> <span className="small muted">{utc(r.last_decision.timestamp)} · {r.last_decision.invocation_type}</span></dd>
            {r.last_decision.session_id ? (<><dt>Session</dt><dd><Link to={scoped(`/sessions/${encodeURIComponent(r.last_decision.session_id)}`, tenant, { agent: r.use_case })}>{r.last_decision.session_id}</Link></dd></>) : null}
            <dt>Signature</dt><dd>{r.last_decision.verification === "valid" ? <Badge tone="ok">Signature valid</Badge> : <Badge tone="error">Signature invalid: record changed after signing</Badge>}</dd>
            <dt>Outcome</dt><dd><DecisionOutcome o={r.last_decision.outcome} />{r.last_decision.verification === "valid" ? null : <div className="small">Not authenticated: shown only to point at the record.</div>}</dd>
            {r.last_decision.primary_explanation_code ? (<><dt>Why</dt><dd><code>{r.last_decision.primary_explanation_code}</code> {r.last_decision.primary_explanation_reason}</dd></>) : null}
            <dt>Recorded agent policy vs current file</dt><dd>{humanize(r.last_decision.agent_file)}</dd>
            <dt>Recorded effective policy</dt><dd>{humanize(r.last_decision.effective_policy)}</dd>
          </dl>
        ) : <p className="muted">No authenticated request of this AI use case is recorded.</p>}
        {r.last_decision?.note ? <p className="small muted">{r.last_decision.note}</p> : null}
      </section>

      <VerificationSection v={r.verification} tenant={tenant} useCase={r.use_case} />
      {r.notes?.length ? <ul className="small muted">{r.notes.map((n) => <li key={n}>{n}</li>)}</ul> : null}
    </div>
  );
}

const BOUNDARY: Record<string, string> = { llm_gateway: "LLM gateway", mcp_proxy: "MCP proxy", action_gateway: "Action Gateway" };

const POLICY: Record<string, { label: string; tone: "ok" | "warn" | "error" | "info" }> = {
  matches_current: { label: "Policy matches the current files", tone: "ok" },
  differs_from_current: { label: "Policy differs from the current files", tone: "warn" },
  not_recorded: { label: "Policy not proven", tone: "info" },
  unverified: { label: "Not verified", tone: "error" },
  bound_at_establishment: { label: "Policy bound at establishment, not evaluated for this event", tone: "info" },
};

// Labels for the Go codes; the notes next to them are Go's text.
const CREDENTIAL: Record<string, { label: string; tone: "ok" | "warn" | "error" | "info" }> = {
  current: { label: "Credential stored now", tone: "ok" },
  previous: { label: "Earlier credential: history", tone: "warn" },
  not_established: { label: "Current credential not established", tone: "warn" },
  unknown: { label: "Credential not known", tone: "info" },
  not_applicable: { label: "Workload identity, not the key", tone: "info" },
};

const RUNTIME_CREDENTIAL: Record<string, { label: string; tone: "ok" | "warn" | "error" | "info" }> = {
  holds_current: { label: "Holds the credential stored now", tone: "ok" },
  predates_current: { label: "Holds an earlier credential", tone: "warn" },
  not_established: { label: "Not established", tone: "warn" },
  not_running: { label: "No process running", tone: "info" },
  unknown: { label: "Not known", tone: "info" },
};

// readingTone colours the one-line reading; the text and the code are Go's.
export function readingTone(code: string): "ok" | "warn" | "error" | "info" | "neutral" {
  if (code === "traffic_observed_policy_matches") return "ok";
  if (code === "traffic_record_unverified") return "error";
  if (code === "traffic_observed_policy_differs" || code === "evidence_unavailable") return "warn";
  if (code === "traffic_predates_current_credential" || code === "traffic_observed_current_credential_not_established") return "warn";
  if (code === "traffic_observed_identity_not_established") return "info";
  if (code === "disabled") return "neutral";
  return "info";
}

// VerificationSection renders effective.Verification (#472): independent
// observations, each with its source. Configured, loaded, observed traffic
// and policy match are separate facts; none implies another, and nothing
// here says the application is "governed".
export function VerificationSection({ v, tenant, useCase }: { v: EffectiveReport["verification"]; tenant: string; useCase: string }) {
  if (!v) return null;
  return (
    <section aria-labelledby="eff-verification" data-testid="verification">
      <h3 id="eff-verification">5. Connection and verification</h3>
      <div className={`notice ${readingTone(v.reading.code) === "ok" ? "info" : readingTone(v.reading.code) === "error" ? "error" : readingTone(v.reading.code) === "warn" ? "warn" : "info"}`} role="status" data-testid="verification-reading" data-code={v.reading.code}>
        <div>{v.reading.text}</div>
      </div>
      <NextStep next={v.next} />
      <CredentialFacts c={v.credential} tenant={tenant} />
      <div className="table-wrap">
        <table>
          <thead><tr><th>Boundary</th><th>Traffic of this use case</th><th>Record</th><th>Policy it was evaluated under</th></tr></thead>
          <tbody>
            {v.traffic.map((o) => (
              <tr key={o.boundary} data-boundary={o.boundary} data-state={o.state}>
                <td>{BOUNDARY[o.boundary] ?? o.boundary}<div className="small muted">{o.establishes}</div></td>
                <td>
                  {o.state === "observed" ? (
                    <>
                      {o.identity_proven ? <Badge tone="ok" plain>Observed, authenticated</Badge> : <Badge tone="info" plain>Observed, caller's identity not established</Badge>}{" "}
                      <span className="small" title={utc(o.timestamp)}>{utc(o.timestamp)}</span>
                      {o.outcome ? <div><DecisionOutcome o={o.outcome} compact /></div> : null}
                      {o.identity ? <div className="small muted">Identity: {o.identity}</div> : null}
                      {o.credential ? (
                        <div className="small" data-testid="observation-credential" data-credential={o.credential}>
                          <Badge tone={CREDENTIAL[o.credential]?.tone ?? "info"} plain>{CREDENTIAL[o.credential]?.label ?? humanize(o.credential)}</Badge>
                          <div className="muted">{o.credential_note}</div>
                        </div>
                      ) : null}
                      {o.last_dispatch ? (
                        <div className="small">Last dispatch: <Link to={scoped(`/evidence/${encodeURIComponent(o.last_dispatch.evidence_id)}`, tenant)}>{o.last_dispatch.evidence_id}</Link> <DecisionOutcome o={o.last_dispatch.outcome} compact /></div>
                      ) : null}
                    </>
                  ) : o.state === "unavailable" ? (
                    <><Badge tone="warn">Unavailable</Badge> <span className="small">{o.error}</span></>
                  ) : (
                    <span className="muted">None recorded</span>
                  )}
                </td>
                <td>
                  {o.evidence_id ? (
                    <>
                      <Link to={scoped(`/evidence/${encodeURIComponent(o.evidence_id)}`, tenant)}>{o.evidence_id}</Link>
                      <div>{o.verification === "valid" ? <Badge tone="ok" plain>Signature valid</Badge> : <Badge tone="error">Signature invalid</Badge>}</div>
                      {o.event ? <div className="small muted">{humanize(o.event)}</div> : null}
                      {o.session_id ? <div className="small">Session <Link to={scoped(`/sessions/${encodeURIComponent(o.session_id)}`, tenant, { agent: useCase })}>{o.session_id}</Link></div> : null}
                    </>
                  ) : <span className="muted">—</span>}
                </td>
                <td>
                  {o.policy ? <><Badge tone={POLICY[o.policy]?.tone ?? "info"} plain>{POLICY[o.policy]?.label ?? humanize(o.policy)}</Badge><div className="small muted">{o.policy_note}</div></> : <span className="muted">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <details>
        <summary className="small">What these observations do not establish</summary>
        <ul className="small muted">{v.not_established.map((n) => <li key={n}>{n}</li>)}</ul>
      </details>
      <p className="small muted">Configured: {v.configured}. Whether a running process has loaded this file is section 2; whether a request arrived and under which policy is this section. Each is established separately.</p>
    </section>
  );
}

// NextStep: the one thing to do next (or that nothing needs doing), as the
// CLI's `talon agents show` prints it. The console is read-only: the
// commands are shown to be run in a terminal, never run from here.
export function NextStep({ next }: { next: UseCaseNextStep | undefined }) {
  if (!next) return null;
  return (
    <div className="small" data-testid="verification-next" data-code={next.code}>
      <strong>Next: </strong>{next.text}
      {next.commands?.length ? (
        <ul className="plain">{next.commands.map((c) => <li key={c}><code>{c}</code></li>)}</ul>
      ) : null}
    </div>
  );
}

// CredentialFacts: what is known about the credential the use case presents
// now. Traffic recorded with an earlier credential of the same name (an
// earlier registration, a replaced key) is history; these facts are what
// the per-record attribution below rests on. Every sentence is Go's.
function CredentialFacts({ c, tenant }: { c: UseCaseCredential | null | undefined; tenant: string }) {
  if (!c) return null;
  return (
    <dl className="facts" data-testid="verification-credential" data-state={c.state} data-runtime={c.runtime}>
      <dt>Credential stored now</dt>
      <dd>
        {c.state === "known" ? <><code>{c.secret_name}</code> <span className="small muted">stored {utc(c.since)}</span></> : <Badge tone="info" plain>{humanize(c.state)}</Badge>}
        {c.note ? <div className="small muted">{c.note}</div> : null}
      </dd>
      <dt>Registration record</dt>
      <dd>
        {c.registration ? (
          <><Link to={scoped(`/evidence/${encodeURIComponent(c.registration.evidence_id)}`, tenant)}>{c.registration.evidence_id}</Link> <span className="small muted">{utc(c.registration.at)}</span> {c.registration.verification === "valid" ? <Badge tone="ok" plain>Signature valid</Badge> : <Badge tone="error">Signature invalid</Badge>}</>
        ) : <span className="muted">None: this use case was configured by hand</span>}
      </dd>
      <dt>Running process</dt>
      <dd><Badge tone={RUNTIME_CREDENTIAL[c.runtime]?.tone ?? "info"} plain>{RUNTIME_CREDENTIAL[c.runtime]?.label ?? humanize(c.runtime)}</Badge><div className="small muted">{c.runtime_note}</div></dd>
    </dl>
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
