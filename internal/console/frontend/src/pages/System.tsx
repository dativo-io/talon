import { useEffect } from "react";
import { api } from "../api/client";
import { ProcessTable, RoleTable, roleLabel, RuntimeStateBadge } from "../components/RuntimeStatus";
import { useApi } from "../api/useApi";
import type { SystemInfo } from "../api/types";
import { PageHead } from "../components/Layout";
import { AvailabilityNotice, Badge, CopyableIdentifier, DetailSection, ErrorState, Loading } from "../components/ui";
import { bytes, integer, relative, utc } from "../lib/format";

const COMMANDS = [
  ["Health checks", "talon doctor"],
  ["AI use cases (fleet)", "talon agents --json"],
  ["Costs", "talon costs --json"],
  ["Sessions", "talon session list --json"],
  ["One session", "talon session show <session-id> --json"],
  ["Audit trail", "talon audit list --json"],
  ["Verify a record", "talon audit verify <evidence-id>"],
  ["New pairing code", "talon ui pair"],
];

// What the console can vouch for: that it answers, and what it read from the
// store file. Gateway and MCP process liveness is not inferred from the
// store; it stays unknown until the runtime probe (#538).
// Refresh is bounded: every 10 s while the page is open; an older answer
// never replaces a newer one (useApi request keys plus the server's
// per-instance sequence check).
const REFRESH_MS = 10_000;

export function System({ expiresAt, onLogout }: { expiresAt?: string; onLogout: () => void }) {
  const res = useApi<SystemInfo>(api("/system"));
  const s = res.data;
  const { reload } = res;
  useEffect(() => {
    const t = window.setInterval(reload, REFRESH_MS);
    return () => window.clearInterval(t);
  }, [reload]);
  return (
    <>
      <PageHead title="System" lede="Can you trust the sources behind what this console shows?" actions={<button type="button" onClick={res.reload} disabled={res.loading}>Refresh</button>} />
      {res.error ? <ErrorState error={res.error} what="system facts" onRetry={res.reload} /> : null}
      {!s && res.loading ? <Loading what="system facts" /> : null}
      {s ? (
        <div className="grid">
          <div className="grid stats">
            <div className="card stat"><div className="label">Console</div><div className="value"><Badge tone="ok">Responding</Badge></div><div className="sub">answered this request</div></div>
            <div className="card stat"><div className="label">Evidence store</div><div className="value">{s.store.availability.state === "ok" ? <Badge tone="ok">Readable</Badge> : <Badge tone="error">{s.store.availability.state}</Badge>}</div><div className="sub">{s.store.read_only ? "read-only connection" : "connection mode unknown"}</div></div>
            {(s.runtime.roles ?? []).filter((r) => r.role !== "native" || r.state !== "not_configured").map((r) => (
              <div className="card stat" key={r.role}>
                <div className="label">{roleLabel(r.role)}</div>
                <div className="value"><RuntimeStateBadge state={r.state} /></div>
                <div className="sub">{r.state === "not_configured" ? "optional; not part of this installation" : r.last_seen ? `heartbeat ${new Date(r.last_seen).toISOString().slice(11, 19)} UTC` : "no heartbeat recorded"}</div>
              </div>
            ))}
            {s.runtime.availability.state !== "ok" ? (
              <div className="card stat"><div className="label">Data-plane runtime</div><div className="value"><Badge tone="info">Unknown</Badge></div><div className="sub">not inferred from the store</div></div>
            ) : null}
          </div>
          <div className="grid two">
            <DetailSection title="Console" id="sys-console">
              <dl className="facts">
                <dt>Version</dt><dd>{s.console.version}</dd>
                <dt>Commit</dt><dd>{s.console.commit ? <CopyableIdentifier value={s.console.commit} label="commit" /> : "—"}</dd>
                <dt>Started</dt><dd>{utc(s.console.started_at)} ({relative(s.console.started_at)})</dd>
                <dt>Amounts in</dt><dd>{s.console.currency}</dd>
                <dt>Your session expires</dt><dd>{expiresAt ? `${utc(expiresAt)} (or after an hour idle)` : "unknown"}</dd>
              </dl>
              <div className="row">
                <button type="button" onClick={onLogout}>Log out of this browser</button>
              </div>
            </DetailSection>
            <DetailSection title="Evidence store" id="sys-store">
              <AvailabilityNotice a={s.store.availability} what="Evidence store" />
              <dl className="facts">
                <dt>Path</dt><dd><code>{s.store.path}</code></dd>
                <dt>Connection</dt><dd>{s.store.read_only ? "read-only (mode=ro)" : "unknown"}</dd>
                <dt>Records</dt><dd>{s.store.availability.state === "ok" ? integer(s.store.record_count) : "unavailable"}</dd>
                <dt>Size</dt><dd>{s.store.size_bytes ? bytes(s.store.size_bytes) : "—"}</dd>
                <dt>Newest record</dt><dd>{s.store.newest_record ? `${utc(s.store.newest_record)} (${relative(s.store.newest_record)})` : "—"}</dd>
                <dt>Read at</dt><dd>{utc(s.store.availability.as_of)}</dd>
              </dl>
              <p className="small muted">A recent newest record shows that something wrote to the store; it does not show which process or that it is still running.</p>
            </DetailSection>
          </div>
          <DetailSection title="Runtime" id="sys-runtime">
            <AvailabilityNotice a={s.runtime.availability} what="Runtime" />
            {s.runtime.availability.state === "ok" ? (
              <div className="stack">
                <p className="small muted">
                  Each data-plane process (<code>talon serve</code>) writes its own status record into this installation's data directory every few seconds. A process is running while that heartbeat is fresh, stale after three missed heartbeats, and offline after twelve or a recorded shutdown. Sessions and evidence stay in the store whatever the process state. Read {utc(s.runtime.read_at)}.
                </p>
                <RoleTable roles={s.runtime.roles ?? []} />
                {(s.runtime.processes ?? []).length > 0 ? <ProcessTable processes={s.runtime.processes ?? []} /> : <p className="muted">No process of this installation has reported yet.</p>}
                {(s.runtime.rejected ?? []).length > 0 ? (
                  <div className="notice warn" role="status">
                    <div>
                      <strong>Records not combined:</strong>
                      <ul className="small">{(s.runtime.rejected ?? []).map((r) => <li key={r.file}><code>{r.file}</code> — {r.reason}</li>)}</ul>
                    </div>
                  </div>
                ) : null}
              </div>
            ) : null}
          </DetailSection>
          <DetailSection title="Diagnostics" id="sys-diag">
            <p className="small muted">Run these on the Talon host. The console never runs commands.</p>
            <div className="table-wrap">
              <table>
                <tbody>
                  {COMMANDS.map(([what, cmd]) => (
                    <tr key={cmd}><td>{what}</td><td><CopyableIdentifier value={cmd!} label="command" /></td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </DetailSection>
        </div>
      ) : null}
    </>
  );
}
