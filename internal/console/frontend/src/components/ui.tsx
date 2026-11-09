import { useState, type ReactNode } from "react";
import type { Availability, Health, Outcome, Verification, BudgetUsage } from "../api/types";
import { sourceLabel, viewOf, type Tone } from "../lib/availability";
import { humanize, money, percent, relative, utc } from "../lib/format";
import { ApiError } from "../api/client";

export function Badge({ tone, children, plain, title }: { tone: Tone | "ok" | "accent"; children: ReactNode; plain?: boolean; title?: string }) {
  return (
    <span className={`badge tone-${tone}${plain ? " plain" : ""}`} title={title}>
      {children}
    </span>
  );
}

// AvailabilityState: compact label for a section's availability.
export function AvailabilityBadge({ a }: { a: Availability | undefined }) {
  const v = viewOf(a);
  if (a?.state === "ok") return null;
  return <Badge tone={v.tone}>{v.label}</Badge>;
}

// SourceFreshness: where a section came from and when it was read.
export function SourceFreshness({ a, prefix }: { a: Availability | undefined; prefix?: string }) {
  if (!a) return null;
  return (
    <span className="freshness" title={a.as_of ? utc(a.as_of) : undefined}>
      {prefix ?? "Source"}: {sourceLabel(a.source)}
      {a.as_of ? <> · read {relative(a.as_of)}</> : null}
    </span>
  );
}

// PartialDataNotice / ErrorState: why a section is not a full measurement.
export function AvailabilityNotice({ a, what }: { a: Availability | undefined; what: string }) {
  if (!a || a.state === "ok" || a.state === "empty") return null;
  const cls = a.state === "unavailable" ? "error" : a.state === "partial" ? "warn" : "info";
  const head =
    a.state === "unavailable" ? `${what} unavailable` : a.state === "partial" ? `${what} partially available` : `${what} unknown`;
  return (
    <div className={`notice ${cls}`} role="status">
      <div>
        <strong>{head}.</strong> {a.error ?? a.note ?? ""}
        {a.unavailable && a.unavailable.length > 0 ? (
          <div className="small muted">Not measured: {a.unavailable.join(", ")}</div>
        ) : null}
      </div>
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <h2>{title}</h2>
      {children ? <div className="small">{children}</div> : null}
    </div>
  );
}

export function Loading({ what }: { what: string }) {
  return (
    <div className="empty" role="status" aria-live="polite">
      Loading {what}…
    </div>
  );
}

// ErrorState: an HTTP or network failure, never rendered as "no data".
export function ErrorState({ error, what, onRetry }: { error: Error; what: string; onRetry?: () => void }) {
  if (error instanceof ApiError && error.sessionEnded) return null; // the app returns to pairing
  const notFound = error instanceof ApiError && error.status === 404;
  return (
    <div className={`notice ${notFound ? "info" : "error"}`} role="alert">
      <div>
        <strong>{notFound ? `${what} not found.` : `Could not load ${what}.`}</strong>{" "}
        {error.message}
        {error instanceof ApiError ? <span className="muted small"> ({error.reason})</span> : null}
        {onRetry && !notFound ? (
          <div>
            <button type="button" className="ghost" onClick={onRetry}>
              Retry
            </button>
          </div>
        ) : null}
      </div>
    </div>
  );
}

const HEALTH: Record<Health, { label: string; tone: Tone | "ok" }> = {
  healthy: { label: "Healthy", tone: "ok" },
  "needs-attention": { label: "Needs attention", tone: "warn" },
  blocked: { label: "Blocked", tone: "error" },
  stopped: { label: "Stopped", tone: "neutral" },
};

// UseCaseHealth: the canonical fleet health word, unchanged.
export function UseCaseHealth({ health }: { health: Health }) {
  const h = HEALTH[health] ?? { label: health, tone: "neutral" as const };
  return <Badge tone={h.tone}>{h.label}</Badge>;
}

// CurrencyAmount: an amount in its stated currency, or "unavailable" with
// the reason when the backend says the figure is not a measurement.
export function CurrencyAmount({ amount, currency, unavailable, reason }: { amount: number | null; currency: string; unavailable?: boolean; reason?: string }) {
  if (unavailable || amount === null) {
    return (
      <span className="muted" title={reason}>
        unavailable{reason ? <span className="visually-hidden"> — {reason}</span> : null}
      </span>
    );
  }
  return <span>{money(amount, currency)}</span>;
}

// BudgetUtilization: backend-computed usage and status word; nothing derived here.
export function BudgetUtilization({ b, currency, unavailable, reason }: { b: BudgetUsage | undefined; currency: string; unavailable?: boolean; reason?: string }) {
  if (unavailable) return <span className="muted" title={reason}>not computed{reason ? ` — ${reason}` : ""}</span>;
  if (!b) return <span className="muted">no effective cap reported</span>;
  const tone = b.status === "BLOCKED" || b.status === "CRITICAL" ? "error" : b.status === "WARNING" ? "warn" : "";
  const width = Math.max(0, Math.min(100, b.percent));
  return (
    <div className="stack">
      <div className="row">
        <span>
          {money(b.used_eur, currency)} of {money(b.limit_eur, currency)}
        </span>
        <Badge tone={tone === "error" ? "error" : tone === "warn" ? "warn" : "neutral"} plain>
          {b.status} · {percent(b.percent)}
        </Badge>
      </div>
      <div className={`meter ${tone}`} role="img" aria-label={`${percent(b.percent)} of the cap used, status ${b.status}`}>
        <span className="w" data-w={width} ref={(el) => el && (el.style.width = `${width}%`)} />
      </div>
      <span className="small muted">Cap source: {humanize(b.source)}</span>
    </div>
  );
}

const DISPATCH: Record<string, { label: string; tone: Tone | "ok" }> = {
  not_dispatched: { label: "Not dispatched", tone: "neutral" },
  dispatched: { label: "Dispatched", tone: "info" },
  unknown: { label: "Dispatch unknown", tone: "warn" },
  not_recorded: { label: "Dispatch not recorded", tone: "neutral" },
};
const DOWNSTREAM: Record<string, { label: string; tone: Tone | "ok" }> = {
  none: { label: "", tone: "neutral" },
  completed: { label: "Destination answered", tone: "ok" },
  rejected: { label: "Destination rejected", tone: "warn" },
  failed: { label: "Attempt failed", tone: "error" },
  unknown: { label: "Outcome unknown", tone: "warn" },
  not_recorded: { label: "", tone: "neutral" },
  cache: { label: "Answered from Talon's cache", tone: "info" },
};

// PolicyDecision + DispatchOutcome: Talon's decision, then what happened to
// the request, as two separate facts from evidence.OutcomeOf.
export function DecisionOutcome({ o, compact }: { o: Outcome | undefined; compact?: boolean }) {
  if (!o) return <span className="muted">outcome not recorded</span>;
  const d = DISPATCH[o.dispatch] ?? DISPATCH.not_recorded!;
  const s = DOWNSTREAM[o.downstream] ?? DOWNSTREAM.not_recorded!;
  return (
    <span className="outcome" title={o.basis}>
      <Badge tone={o.decision === "allowed" ? "ok" : "error"}>Talon {o.decision}</Badge>
      <span className="arrow" aria-hidden="true">→</span>
      <Badge tone={d.tone} plain>{d.label}</Badge>
      {s.label ? (
        <>
          <span className="arrow" aria-hidden="true">→</span>
          <Badge tone={s.tone} plain>{s.label}</Badge>
        </>
      ) : null}
      {o.response_withheld ? <Badge tone="warn" plain>answer withheld by Talon</Badge> : null}
      {!compact ? <span className="visually-hidden">Basis: {o.basis}</span> : null}
    </span>
  );
}

// EvidenceVerification: the result of checking the signature for this read.
export function EvidenceVerification({ v }: { v: Verification | undefined }) {
  if (!v) return <Badge tone="info">Verification unavailable</Badge>;
  return v.state === "valid" ? (
    <Badge tone="ok">Signature valid</Badge>
  ) : (
    <Badge tone="error">Signature invalid: record changed after signing</Badge>
  );
}

export function CopyableIdentifier({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="copy">
      <code title={value}>{value}</code>
      <button
        type="button"
        className="ghost"
        aria-label={`Copy ${label ?? "identifier"}`}
        onClick={() => {
          void navigator.clipboard?.writeText(value).then(() => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1200);
          });
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </span>
  );
}

export function DetailSection({ title, actions, children, id }: { title: string; actions?: ReactNode; children: ReactNode; id?: string }) {
  return (
    <section className="card section" aria-labelledby={id}>
      <div className="card-head">
        <h2 id={id}>{title}</h2>
        {actions ? <div className="row">{actions}</div> : null}
      </div>
      <div className="card-body">{children}</div>
    </section>
  );
}

export function Chips({ items, empty }: { items: string[] | undefined | null; empty?: string }) {
  if (!items || items.length === 0) return <span className="muted">{empty ?? "none"}</span>;
  return (
    <span className="chips">
      {items.map((i) => (
        <span className="chip" key={i}>
          {i}
        </span>
      ))}
    </span>
  );
}
