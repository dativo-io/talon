import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import type { EvidenceDetail } from "../api/types";
import { PageHead } from "../components/Layout";
import { Breadcrumbs, scopeCrumb } from "../components/Breadcrumbs";
import { ProofBoundary } from "../components/ProofBoundary";
import { outcomeStory } from "../lib/outcome";
import { evidenceProof } from "../lib/proof";
import { AvailabilityNotice, CopyableIdentifier, DecisionOutcome, DetailSection, ErrorState, EvidenceVerification, Loading, Chips } from "../components/ui";
import { duration, humanize, utc } from "../lib/format";
import { scoped, useScope } from "../lib/scope";

// One signed evidence record: Talon's decision, the separately recorded
// dispatch and downstream outcome, the explanations, and the result of
// verifying the signature for this read. Standalone records (no session)
// are shown as such; no session is created for them.
export function EvidencePage() {
  const { id = "" } = useParams();
  const { tenant } = useScope();
  const res = useApi<EvidenceDetail>(api(`/evidence/${encodeURIComponent(id)}`), { tenant });
  const det = res.data?.detail;
  const r = det?.record;
  const crumbs = [scopeCrumb(tenant)];
  if (r) {
    crumbs.push({ label: r.agent_id, to: scoped(`/use-cases/${encodeURIComponent(r.agent_id)}`, r.tenant_id) });
    if (r.session_id) crumbs.push({ label: `Session ${r.session_id}`, to: scoped(`/sessions/${encodeURIComponent(r.session_id)}`, r.tenant_id, { agent: r.agent_id }) });
  }
  crumbs.push({ label: `Evidence ${id}` });
  // A record whose signature fails tells no story: its outcome is a claim
  // from an altered record (#558 review).
  const tampered = det?.verification?.state === "invalid";
  const story = !det
    ? null
    : tampered
      ? { headline: "Signature invalid — this record's outcome cannot be relied on", detail: "The record changed after it was signed. Its decision, dispatch and destination facts are shown below only as claims; do not act on them.", tone: "error" as const }
      : outcomeStory(det.outcome);
  return (
    <>
      <Breadcrumbs items={crumbs} />
      <PageHead title="Evidence record" lede={<CopyableIdentifier value={id} label="evidence id" />} actions={<button type="button" onClick={res.reload}>Refresh</button>} />
      {res.error ? <ErrorState error={res.error} what={`evidence ${id}`} onRetry={res.reload} /> : null}
      {!res.data && res.loading ? <Loading what="evidence" /> : null}
      {res.data ? <AvailabilityNotice a={res.data.availability} what="Evidence" /> : null}
      {det && r && story ? (
        <div className="grid">
          <section className={`card story-card tone-border-${story.tone}`} aria-labelledby="ev-story" data-testid="outcome-story">
            <div className="card-body story">
              <h2 id="ev-story">{story.headline}</h2>
              <p>{story.detail}</p>
              {tampered ? null : <span className="small muted">The separate facts behind this sentence are under Decision and outcome.</span>}
            </div>
          </section>
          <ProofBoundary facts={evidenceProof(r, det.outcome, det.verification)} />
          <DetailSection title="Verification" id="ev-verify">
            <div className="row">
              <EvidenceVerification v={det.verification} />
              <span className="small muted">HMAC signature checked by the console at {utc(det.verification.checked_at)}.</span>
            </div>
            <p className="small muted">
              Evidence is tamper-evident: a changed record fails this check. It is not immutable storage, and a valid signature proves the record is unchanged, not that every event was recorded.
            </p>
          </DetailSection>

          <div className="grid two">
            <DetailSection title={tampered ? "Decision and outcome — claimed, not verified" : "Decision and outcome"} id="ev-outcome">
              {tampered ? <div className="notice error" role="note"><div>From an altered record: these values are what the record now says, not facts Talon vouches for.</div></div> : null}
              <DecisionOutcome o={det.outcome} />
              <p className="small">Why this outcome: {det.outcome.basis}</p>
              <dl className="facts">
                <dt>Policy action</dt><dd>{r.policy_decision.action}</dd>
                <dt>Reasons</dt><dd><Chips items={r.policy_decision.reasons} /></dd>
                <dt>Policy version</dt><dd>{r.policy_decision.policy_version ? <code>{r.policy_decision.policy_version}</code> : <span className="muted">not recorded</span>}</dd>
                {r.status ? (<><dt>Execution status</dt><dd>{humanize(r.status)}{r.failure_reason ? ` (${r.failure_reason})` : ""}</dd></>) : null}
                {r.execution.error ? (<><dt>Recorded error</dt><dd><code>{r.execution.error}</code></dd></>) : null}
                {r.enforcement ? (<><dt>Enforcement</dt><dd>{humanize(r.enforcement.mechanism)} at {humanize(r.enforcement.boundary)} · authority {humanize(r.enforcement.decision_authority)} · provenance {humanize(r.enforcement.provenance)}</dd></>) : null}
              </dl>
            </DetailSection>

            <DetailSection title="Identity" id="ev-identity">
              <dl className="facts">
                <dt>Recorded at</dt><dd>{utc(r.timestamp)}</dd>
                <dt>AI use case</dt><dd><Link to={scoped(`/use-cases/${encodeURIComponent(r.agent_id)}`, r.tenant_id)}>{r.agent_id}</Link></dd>
                <dt>Tenant</dt><dd>{r.tenant_id}</dd>
                <dt>Record type</dt><dd><code>{r.invocation_type}</code></dd>
                <dt>Session</dt>
                <dd>
                  {r.session_id ? (
                    <Link to={scoped(`/sessions/${encodeURIComponent(r.session_id)}`, r.tenant_id, { agent: r.agent_id })}>{r.session_id}</Link>
                  ) : (
                    <span className="muted">none: a standalone record, not part of a session</span>
                  )}
                </dd>
                <dt>Correlation id</dt><dd><CopyableIdentifier value={r.correlation_id} label="correlation id" /></dd>
                {r.request_source_id ? (<><dt>Request source</dt><dd>{r.request_source_id} <span className="small muted">(attribution)</span></dd></>) : null}
                <dt>Model</dt><dd>{r.execution.model_used || <span className="muted">none</span>}</dd>
                <dt>Tools</dt><dd><Chips items={r.execution.tools_called} /></dd>
                <dt>Duration</dt><dd>{duration(r.execution.duration_ms)}</dd>
                <dt>Recorded cost</dt>
                <dd>{r.execution.cost.toFixed(6)} {r.execution.currency || "(no currency recorded)"} {r.execution.cost > 0 && !r.execution.pricing_known ? <span className="small muted">— no pricing-table price</span> : null}</dd>
                {r.failover ? (<><dt>Failover</dt><dd>{humanize(r.failover.role)} · {r.failover.provider}{r.failover.model ? `/${r.failover.model}` : ""} · position {r.failover.chain_position}{r.failover.error_class ? ` · ${r.failover.error_class}` : ""}</dd></>) : null}
              </dl>
            </DetailSection>
          </div>

          <DetailSection title="Explanations" id="ev-explanations">
            {r.explanations && r.explanations.length > 0 ? (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Code</th><th>Decision</th><th>Stage</th><th>Reason</th><th>Trigger</th><th>Fix</th><th>Policy reference</th></tr></thead>
                  <tbody>
                    {r.explanations.map((x, i) => (
                      <tr key={`${x.code}-${i}`}>
                        <td><code>{x.code}</code>{i === 0 ? <div className="small muted">primary</div> : null}</td>
                        <td>{x.decision}</td>
                        <td>{humanize(x.stage)}</td>
                        <td>{x.reason}</td>
                        <td className="small">{x.trigger ?? "—"}</td>
                        <td className="small">{x.fix ?? "—"}</td>
                        <td className="small">{x.policy_ref ? <code>{x.policy_ref}</code> : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="muted">No explanation items on this record.</p>
            )}
          </DetailSection>

          <DetailSection title="Stored record" id="ev-raw" actions={<CopyRaw value={JSON.stringify(r, null, 2)} />}>
            <p className="small muted">The signed record as stored, with the redaction it was written with. Prompts and responses are not part of it.</p>
            <pre className="json">{JSON.stringify(r, null, 2)}</pre>
          </DetailSection>
        </div>
      ) : null}
    </>
  );
}

function CopyRaw({ value }: { value: string }) {
  return (
    <button type="button" onClick={() => void navigator.clipboard?.writeText(value)}>
      Copy JSON
    </button>
  );
}
