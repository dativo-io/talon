import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, getJSON } from "../api/client";
import { useApi } from "../api/useApi";
import type { EvidenceIndex, SessionDetail as DetailDTO, SessionSummary, TimelineCursor } from "../api/types";
import { PageHead } from "../components/Layout";
import { Breadcrumbs, scopeCrumb } from "../components/Breadcrumbs";
import { ProofBoundary } from "../components/ProofBoundary";
import { outcomeStory } from "../lib/outcome";
import { sessionProof } from "../lib/proof";
import { AvailabilityNotice, Badge, Chips, CopyableIdentifier, CurrencyAmount, DecisionOutcome, DetailSection, EmptyState, ErrorState, Loading } from "../components/ui";
import { duration, humanize, integer, utc } from "../lib/format";
import { scoped, useScope } from "../lib/scope";

const PAGE = 50;

export function SessionDetail() {
  const { id = "" } = useParams();
  const { tenant, params } = useScope();
  const agent = params.get("agent") ?? "";
  const res = useApi<DetailDTO>(api(`/sessions/${encodeURIComponent(id)}`), { tenant, agent, timeline_limit: PAGE });
  const d = res.data;
  // One investigation = session id + scope + the first page it was opened
  // with. Extra pages belong to exactly one investigation: a late page for a
  // previous one is aborted or discarded, never appended here.
  const investigation = d ? JSON.stringify([id, tenant, agent, d.meta.generated_at]) : null;
  const [paged, setPaged] = useState<{ inv: string | null; extra: EvidenceIndex[]; cursor?: TimelineCursor; err: Error | null }>({ inv: null, extra: [], err: null });
  const [busy, setBusy] = useState(false);
  const inflight = useRef<AbortController | null>(null);
  useEffect(() => {
    inflight.current?.abort();
    inflight.current = null;
    setBusy(false);
    setPaged({ inv: investigation, extra: [], cursor: d?.timeline?.next_cursor, err: null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigation]);
  useEffect(() => () => inflight.current?.abort(), []);
  const own = paged.inv === investigation;
  const extra = own ? paged.extra : [];
  const cursor = own ? paged.cursor : d?.timeline?.next_cursor;
  const moreErr = own ? paged.err : null;
  const summary = d?.detail?.summary;
  const records = [...(d?.timeline?.records ?? []), ...extra];
  const loadMore = () => {
    if (!cursor || investigation === null) return;
    const inv = investigation;
    inflight.current?.abort();
    const ctrl = new AbortController();
    inflight.current = ctrl;
    setBusy(true);
    // Further pages come from /timeline, which does not recompute the summary.
    getJSON<DetailDTO>(
      api(`/sessions/${encodeURIComponent(id)}/timeline`),
      { tenant, agent, timeline_limit: PAGE, timeline_after: cursor.timestamp, timeline_after_id: cursor.id },
      ctrl.signal,
    )
      .then((page) => {
        if (ctrl.signal.aborted) return;
        setPaged((p) => (p.inv !== inv ? p : { inv, extra: [...p.extra, ...(page.timeline?.records ?? [])], cursor: page.timeline?.next_cursor, err: null }));
      })
      .catch((e: unknown) => {
        if (ctrl.signal.aborted) return;
        setPaged((p) => (p.inv !== inv ? p : { ...p, err: e instanceof Error ? e : new Error(String(e)) }));
      })
      .finally(() => {
        if (inflight.current === ctrl) {
          inflight.current = null;
          setBusy(false);
        }
      });
  };
  const scopeTenant = d?.meta.tenant_id ?? tenant;
  // The use case of the path: the one the URL scopes to, else the only one
  // the session's records name. Never guessed between several.
  const agents = summary?.agents ?? [];
  const pathAgent = agent || (agents.length === 1 ? agents[0] : "");
  const crumbs = [scopeCrumb(tenant)];
  if (pathAgent) crumbs.push({ label: pathAgent, to: scoped(`/use-cases/${encodeURIComponent(pathAgent)}`, scopeTenant) });
  else crumbs.push({ label: "Sessions", to: scoped("/sessions", tenant) });
  crumbs.push({ label: `Session ${id}` });
  return (
    <>
      <Breadcrumbs items={crumbs} />
      <PageHead
        title={`Session ${id}`}
        lede={agent ? `Scoped to AI use case ${agent}.` : undefined}
        actions={<button type="button" onClick={res.reload} disabled={res.loading}>Refresh</button>}
      />
      {res.error ? <ErrorState error={res.error} what={`session ${id}`} onRetry={res.reload} /> : null}
      {!d && res.loading ? <Loading what="session" /> : null}
      {d ? <AvailabilityNotice a={d.availability} what="This session" /> : null}
      {d?.detail?.ambiguous_sessions && d.detail.ambiguous_sessions.length > 0 ? (
        <div className="notice warn" role="status">
          <div>
            <strong>More than one AI use case used this session id.</strong> Pick one; each is a separate session.
            <ul>
              {d.detail.ambiguous_sessions.map((s) => (
                <li key={s.id}>
                  <Link to={scoped(`/sessions/${encodeURIComponent(id)}`, s.tenant_id, { agent: s.agent_id })}>{s.agent_id}</Link>
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}
      {d && summary && !agent && !d.detail?.session && (summary.agents ?? []).length > 1 ? (
        <div className="notice warn" role="status">
          <div>
            <strong>{(summary.agents ?? []).length} AI use cases recorded this session id.</strong> Talon did not correlate them: the figures and timeline below combine their records, as <code>talon session show</code> does without <code>--agent</code>. Open one use case's session:
            <ul>
              {(summary.agents ?? []).map((a) => (
                <li key={a}>
                  <Link to={scoped(`/sessions/${encodeURIComponent(id)}`, scopeTenant, { agent: a })}>{a}</Link>
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}
      {d && summary ? (
        <div className="grid">
          <Header d={d} s={summary} tenant={scopeTenant} />
          <Summary s={summary} />
          <ProofBoundary facts={sessionProof(summary, Boolean(d.detail?.session), scopeTenant)} />
          <section className="card" aria-labelledby="timeline-title">
            <div className="card-head">
              <h2 id="timeline-title">Timeline</h2>
              <span className="small muted">
                {records.length} of {d.timeline?.total ?? records.length} records · oldest first · times UTC
              </span>
            </div>
            {records.length === 0 ? <EmptyState title="No evidence records in this session" /> : <Timeline records={records} tenant={scopeTenant} />}
            {moreErr ? <ErrorState error={moreErr} what="more records" onRetry={loadMore} /> : null}
            {cursor ? (
              <div className="table-foot">
                <span className="small muted">More records are recorded for this session.</span>
                <button type="button" onClick={loadMore} disabled={busy}>
                  {busy ? "Loading…" : `Load ${PAGE} more`}
                </button>
              </div>
            ) : null}
          </section>
        </div>
      ) : null}
    </>
  );
}

function Header({ d, s, tenant }: { d: DetailDTO; s: SessionSummary; tenant: string }) {
  const row = d.detail?.session;
  const costReason = d.availability.unavailable?.includes("detail.summary.total_cost") ? d.availability.note : undefined;
  return (
    <DetailSection title="Session" id="session-head">
      <div className="grid two">
        <dl className="facts">
          <dt>Session id</dt><dd><CopyableIdentifier value={s.session_id} label="session id" /></dd>
          <dt>AI use case</dt>
          <dd>{(s.agents ?? []).map((a) => <Link key={a} to={scoped(`/use-cases/${encodeURIComponent(a)}`, tenant)}>{a} </Link>)}</dd>
          <dt>Kind</dt>
          <dd>{row ? "Managed session (session store)" : "Observed in evidence only (no lifecycle tracked)"}</dd>
          {row ? (<><dt>Lifecycle status</dt><dd>{humanize(row.status)}</dd></>) : null}
          <dt>Attribution</dt>
          <dd>{s.session_source ? humanize(s.session_source) : row?.source ? humanize(row.source) : "talon"}{s.client ? ` · client ${s.client}` : ""} <span className="small muted">(attribution, not authentication)</span></dd>
          <dt>First / last record</dt><dd>{utc(s.first_seen)} → {utc(s.last_seen)}</dd>
          <dt>Duration</dt><dd>{s.duration_ms ? duration(s.duration_ms) : "—"}</dd>
        </dl>
        <dl className="facts">
          <dt>Model requests</dt><dd>{integer(s.requests)}</dd>
          <dt>Allowed / denied</dt><dd>{integer(s.allowed)} / {integer(s.denied)}</dd>
          <dt>Records with an error</dt><dd>{integer(s.errors)} <span className="small muted">(denials record their reason in the error field)</span></dd>
          <dt>Recorded cost</dt>
          <dd>
            <CurrencyAmount amount={costReason ? null : s.total_cost} currency={s.currency ?? ""} reason={costReason} />
            {costReason ? <div className="small">{costReason}</div> : null}
          </dd>
          <dt>Tokens in / out</dt><dd>{integer(s.input_tokens)} / {integer(s.output_tokens)}</dd>
          <dt>Records</dt><dd>{integer(s.record_count)}</dd>
        </dl>
      </div>
    </DetailSection>
  );
}

function Summary({ s }: { s: SessionSummary }) {
  return (
    <DetailSection title="What happened" id="session-summary">
      <div className="grid two">
        <dl className="facts">
          <dt>Provider path</dt><dd><Chips items={s.provider_path} empty="not recorded" /></dd>
          <dt>Models</dt><dd><Chips items={s.models} /></dd>
          <dt>Retries</dt><dd>{integer(s.retries ?? 0)}</dd>
          <dt>Failed attempts</dt><dd>{integer(s.failed_attempts ?? 0)}</dd>
          <dt>Fallbacks</dt><dd>{integer(s.fallbacks ?? 0)}</dd>
          <dt>Failed closed</dt><dd>{integer(s.fail_closed ?? 0)}</dd>
        </dl>
        <dl className="facts">
          <dt>Tool calls</dt><dd>{integer(s.tool_calls ?? 0)} ({integer(s.tool_calls_denied ?? 0)} denied, {integer(s.tool_calls_failed ?? 0)} failed)</dd>
          <dt>Tools</dt><dd><Chips items={s.tool_names} /></dd>
          <dt>Tools filtered</dt><dd><Chips items={s.tools_filtered} /></dd>
          <dt>PII redactions</dt><dd>{integer(s.pii_redactions ?? 0)} {s.pii_types?.length ? <Chips items={s.pii_types} /> : null}</dd>
          <dt>Denials by reason</dt>
          <dd>
            {s.denied_by_reason && Object.keys(s.denied_by_reason).length > 0 ? (
              <ul className="small">{Object.entries(s.denied_by_reason).map(([k, v]) => <li key={k}><code>{k}</code> × {v}</li>)}</ul>
            ) : <span className="muted">none</span>}
          </dd>
          <dt>Last failure</dt>
          <dd>{s.last_failure ? <><code>{s.last_failure.code}</code> at {utc(s.last_failure.at)}{s.last_failure.detail ? <div className="small">{s.last_failure.detail}</div> : null}</> : <span className="muted">none</span>}</dd>
        </dl>
      </div>
    </DetailSection>
  );
}

function TimelineStory({ o }: { o: EvidenceIndex["outcome"] }) {
  const s = outcomeStory(o);
  return <div className="story"><strong>{s.headline}</strong><span className="small muted">{s.detail}</span></div>;
}

function Timeline({ records, tenant }: { records: EvidenceIndex[]; tenant: string }) {
  return (
    <ol className="timeline">
      {records.map((r) => (
        <li key={r.id}>
          <div className="when">{utc(r.timestamp).replace(" UTC", "")}</div>
          <div className="what">
            <div className="row">
              <code>{r.invocation_type}</code>
              {r.outcome?.tool ? <span className="chip">{r.outcome.tool}</span> : null}
              {r.model_used ? <span className="chip">{r.model_used}</span> : null}
              {r.agent_id ? <span className="small muted">{r.agent_id}</span> : null}
            </div>
            <TimelineStory o={r.outcome} />
            <DecisionOutcome o={r.outcome} />
            {r.primary_explanation_code ? (
              <div className="small">
                <code>{r.primary_explanation_code}</code> {r.primary_explanation_reason}
              </div>
            ) : null}
            <div className="small muted row">
              <span>Evidence <Link to={scoped(`/evidence/${encodeURIComponent(r.id)}`, tenant)}>{r.id}</Link></span>
              {r.correlation_id ? <span>· correlation <code>{r.correlation_id}</code></span> : null}
              {r.duration_ms ? <span>· {duration(r.duration_ms)}</span> : null}
              {r.cost ? <span>· cost {r.cost.toFixed(4)} {r.currency || "(no currency)"}</span> : null}
              {/* MCP proxy denials store their deny reason in the error field (internal/mcp/proxy.go); the reason is shown above. */}
              {r.has_error && r.allowed ? <Badge tone="warn" plain>error recorded</Badge> : null}
            </div>
            {r.outcome ? <div className="small muted">Why this outcome: {r.outcome.basis}</div> : null}
          </div>
        </li>
      ))}
    </ol>
  );
}
