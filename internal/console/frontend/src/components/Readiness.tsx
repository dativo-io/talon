import { Link } from "react-router-dom";
import type { Finding, OverallReadiness, Readiness, ReadyState, Severity } from "../api/types";
import type { Tone } from "../lib/availability";
import { relative, utc } from "../lib/format";
import { scoped } from "../lib/scope";
import { Badge } from "./ui";

// Readiness is the backend's installation-wide projection: the states, the
// reasons and the findings are Go's; this file only presents them. A tenant
// scope never filters it.

const OVERALL: Record<OverallReadiness, { label: string; tone: Tone | "ok"; lede: string }> = {
  operational: { label: "Operational", tone: "ok", lede: "Verified now from the processes' own records and the stores." },
  degraded: { label: "Degraded", tone: "error", lede: "At least one fact established now is wrong." },
  unverified: { label: "Unverified", tone: "info", lede: "Nothing is known to be wrong, but a running process does not report what would prove readiness." },
  unknown: { label: "Unknown", tone: "info", lede: "Part of the runtime cannot be assessed, so it is not reported healthy." },
  not_configured: { label: "No runtime configured", tone: "neutral", lede: "This console has no gateway or MCP proxy to watch; only recorded history is shown." },
};

const STATE: Record<ReadyState, { label: string; tone: Tone | "ok" }> = {
  ok: { label: "OK", tone: "ok" },
  degraded: { label: "Degraded", tone: "error" },
  unverified: { label: "Unverified", tone: "info" },
  unknown: { label: "Unknown", tone: "info" },
  not_configured: { label: "Not configured", tone: "neutral" },
};

const SEVERITY: Record<Severity, { label: string; tone: Tone }> = {
  critical: { label: "Critical", tone: "error" },
  warning: { label: "Warning", tone: "warn" },
  info: { label: "Info", tone: "info" },
};

export function ReadyBadge({ state }: { state: ReadyState }) {
  const s = STATE[state] ?? STATE.unknown;
  return <Badge tone={s.tone}>{s.label}</Badge>;
}

export function OverallBadge({ overall }: { overall: OverallReadiness }) {
  const s = OVERALL[overall] ?? OVERALL.unknown;
  return <Badge tone={s.tone}>{s.label}</Badge>;
}

// ReadinessPanel: the overall state, the summary and every dimension.
export function ReadinessPanel({ r, compact }: { r: Readiness; compact?: boolean }) {
  const o = OVERALL[r.overall] ?? OVERALL.unknown;
  return (
    <section className={`card readiness readiness-${r.overall}`} aria-labelledby="readiness-title" data-testid="readiness">
      <div className="card-head">
        <div>
          <h2 id="readiness-title">
            Operational readiness <OverallBadge overall={r.overall} />
          </h2>
          <p className="readiness-summary">{r.summary}</p>
        </div>
        <span className="small muted" title={utc(r.assessed_at)}>Installation-wide · assessed {relative(r.assessed_at)}</span>
      </div>
      <div className="card-body stack">
        <p className="small muted">{o.lede} Not filtered by the tenant scope. Canonical fleet health of the AI use cases is reported separately.</p>
        <ul className="dimensions" aria-label="Readiness dimensions">
          {r.dimensions.map((d) => (
            <li key={d.key} className={`dimension state-${d.state}`} data-dimension={d.key}>
              <div className="dimension-head">
                <span className="dimension-label">{d.label}</span>
                <ReadyBadge state={d.state} />
              </div>
              {compact ? null : <div className="small">{d.reason}</div>}
              <div className="small muted" title={d.observed_at ? utc(d.observed_at) : undefined}>
                {d.observed_at ? `established ${relative(d.observed_at)}` : "not established"}
              </div>
            </li>
          ))}
        </ul>
        {compact ? (
          <details>
            <summary className="small">Why each dimension has this state</summary>
            <dl className="facts small">
              {r.dimensions.map((d) => (
                <div key={d.key} className="contents">
                  <dt>{d.label}</dt>
                  <dd>{d.reason} <span className="muted">(source: {d.source})</span></dd>
                </div>
              ))}
            </dl>
          </details>
        ) : null}
      </div>
    </section>
  );
}

// FindingsList: what is wrong, what it affects, why, when, where next.
// Links to a use case keep that use case's own tenant.
export function FindingsList({ findings, tenant, title = "Findings", empty }: { findings: Finding[]; tenant: string; title?: string; empty?: string }) {
  return (
    <section className="card" aria-labelledby="findings-title" data-testid="findings">
      <div className="card-head">
        <h2 id="findings-title">{title}</h2>
        <span className="small muted">most urgent first · installation findings, then AI use cases in this scope</span>
      </div>
      {findings.length === 0 ? (
        <div className="card-body">
          <p>{empty ?? "No finding in this scope."}</p>
        </div>
      ) : (
        <ol className="findings">
          {findings.map((f, i) => {
            const sev = SEVERITY[f.severity] ?? SEVERITY.info;
            const to = f.scope === "use_case" ? f.link : scoped(f.link, tenant);
            return (
              <li key={`${f.code}-${f.affected}-${i}`} className={`finding severity-${f.severity}`} data-code={f.code}>
                <div className="finding-head">
                  <Badge tone={sev.tone}>{sev.label}</Badge>
                  <strong>{f.title}</strong>
                  <span className="small muted">{f.scope === "installation" ? "installation" : `tenant ${f.tenant_id}`}</span>
                </div>
                <dl className="finding-facts small">
                  <dt>Affects</dt><dd>{f.affected}</dd>
                  <dt>Why</dt><dd>{f.why}</dd>
                  <dt>Observed</dt><dd title={f.observed_at ? utc(f.observed_at) : undefined}>{f.observed_at ? `${relative(f.observed_at)} · ${f.source}` : f.source}</dd>
                </dl>
                <Link className="small" to={to}>{nextLabel(f)} →</Link>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

function nextLabel(f: Finding): string {
  if (f.scope === "use_case") return `Open ${f.use_case ?? "the AI use case"}`;
  if (f.link.startsWith("/configuration")) return "Inspect configuration";
  return "Inspect System facts";
}
