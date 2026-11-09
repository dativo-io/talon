import { api } from "../api/client";
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
export function System({ expiresAt, onLogout }: { expiresAt?: string; onLogout: () => void }) {
  const res = useApi<SystemInfo>(api("/system"));
  const s = res.data;
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
            <div className="card stat"><div className="label">Gateway / MCP runtime</div><div className="value"><Badge tone="info">{s.runtime.availability.state === "ok" ? "Verified" : "Unknown"}</Badge></div><div className="sub">not inferred from the store</div></div>
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
            <p className="small">
              Known: the console is responding and the evidence store is readable. Unknown: whether the gateway and MCP proxy processes are running, which configuration generation they loaded, and whether a reload was rejected.
            </p>
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
