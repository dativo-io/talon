import type { ActiveStatus, RoleStatus, Runtime, RuntimeProcess, RuntimeState } from "../api/types";
import { Badge, CopyableIdentifier } from "./ui";
import type { Tone } from "../lib/availability";
import { relative, utc } from "../lib/format";

const ROLE_LABEL: Record<string, string> = { mcp_proxy: "MCP proxy", gateway: "LLM gateway", native: "Native agent runtime" };
const STATE: Record<RuntimeState, { label: string; tone: Tone | "ok" }> = {
  running: { label: "Running", tone: "ok" },
  stale: { label: "Stale", tone: "warn" },
  offline: { label: "Offline", tone: "error" },
  not_configured: { label: "Not configured", tone: "neutral" },
  unknown: { label: "Unknown", tone: "info" },
};

export function roleLabel(role: string): string {
  return ROLE_LABEL[role] ?? role;
}

// RuntimeStateBadge: the state Go derived from the process's own heartbeat.
export function RuntimeStateBadge({ state }: { state: RuntimeState }) {
  const s = STATE[state] ?? STATE.unknown;
  return <Badge tone={s.tone}>{s.label}</Badge>;
}

export function RoleTable({ roles }: { roles: RoleStatus[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th>Runtime</th><th>State</th><th>Why</th><th className="num">Last verified contact</th></tr>
        </thead>
        <tbody>
          {roles.map((r) => (
            <tr key={r.role}>
              <td>{roleLabel(r.role)}{r.expected ? <div className="small muted">configured for this installation</div> : null}</td>
              <td><RuntimeStateBadge state={r.state} /></td>
              <td className="small">{r.reason}</td>
              <td className="num" title={utc(r.last_seen)}>{r.last_seen ? relative(r.last_seen) : "never"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ProcessTable({ processes }: { processes: RuntimeProcess[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th>Process</th><th>Roles</th><th>State</th><th>Version</th><th>Active generation</th><th>Reload</th><th className="num">Started (UTC)</th></tr>
        </thead>
        <tbody>
          {processes.map((p) => (
            <tr key={p.instance_id}>
              <td>
                <CopyableIdentifier value={p.instance_id} label="instance id" />
                <div className="small muted">{p.current ? "current" : "earlier instance (history)"} · pid {p.pid}{p.host ? ` on ${p.host}` : ""}</div>
              </td>
              <td>{p.roles.map(roleLabel).join(", ")}</td>
              <td><RuntimeStateBadge state={p.assessed_state} /><div className="small muted">{p.reason}</div></td>
              <td>{p.version}</td>
              <td>{p.catalog ? <code className="small" title={p.catalog.active_generation}>{p.catalog.active_generation.slice(0, 12)}</code> : <span className="muted">not reported</span>}
                {p.catalog ? <div className="small muted">activated {utc(p.catalog.activated_at)}</div> : null}
              </td>
              <td className="small">
                {!p.catalog ? "—" : !p.catalog.reload_enabled ? "reload off" : p.catalog.reload_rejected ? (
                  <><Badge tone="warn">Rejected</Badge><div>last-known-good keeps serving{p.catalog.rejected_at ? ` since ${utc(p.catalog.rejected_at)}` : ""}</div>{(p.catalog.rejected_causes ?? []).map((c) => <div key={c} className="muted">{c}</div>)}</>
                ) : "accepted"}
              </td>
              <td className="num">{utc(p.started_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// runtimeSummary is one sentence for headers: the role states as Go derived them.
export function runtimeSummary(rt: Runtime): string {
  if (rt.availability.state !== "ok") return `Runtime ${rt.availability.state}${rt.availability.error ? `: ${rt.availability.error}` : rt.availability.note ? ` — ${rt.availability.note}` : ""}`;
  const roles = (rt.roles ?? []).filter((r) => r.state !== "not_configured" || r.expected);
  if (roles.length === 0) return "No data-plane process is configured or reporting.";
  return roles.map((r) => `${roleLabel(r.role)}: ${(STATE[r.state] ?? STATE.unknown).label.toLowerCase()}`).join(" · ");
}

const ACTIVE: Record<ActiveStatus["state"], { label: string; tone: "ok" | "warn" | "info" | "neutral" }> = {
  loaded_matches_file: { label: "Yes: this file is loaded", tone: "ok" },
  loaded_differs_from_file: { label: "A different version is loaded", tone: "warn" },
  not_in_active_generation: { label: "Not in the active generation", tone: "warn" },
  unknown: { label: "Not proven", tone: "info" },
};

export function ActiveBadge({ a }: { a: ActiveStatus | undefined }) {
  if (!a) return <span className="muted">not reported</span>;
  const s = ACTIVE[a.state] ?? ACTIVE.unknown;
  return (
    <span className="stack">
      <Badge tone={s.tone}>{s.label}</Badge>
      <span className="small muted">{a.reason}</span>
    </span>
  );
}
