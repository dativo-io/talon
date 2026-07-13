# Gateway dashboard reference

The gateway dashboard provides real-time visibility into LLM API gateway traffic. It shows request volumes, cost, PII detections, policy enforcement, tool governance, and budget utilization — all from a single embedded HTML page with no external dependencies.

---

## Enabling the dashboard

The dashboard is available when Talon runs in gateway mode:

```bash
talon serve --gateway --gateway-config talon.config.yaml
```

The dashboard is served on the same port as the API (default `:8080`).

Without `--gateway` (or `--proxy-quickstart`), the gateway routes are **not mounted**: `GET /gateway/dashboard`, `GET /api/v1/metrics`, and `GET /api/v1/metrics/stream` all return `404 page not found` as plain text (a common symptom is `jq` failing with `Cannot index number` on the "404" body). The unified governance dashboard (`/dashboard`) detects this at load time and hides its gateway telemetry links, showing a hint to restart with `--gateway` instead. `--gateway` works even when `talon.config.yaml` has no `gateway:` block — defaults apply.

### Configuration

Set the server admin key so dashboard and metrics endpoints are protected:

```bash
export TALON_ADMIN_KEY="your-secret-admin-key"
talon serve --gateway --gateway-config talon.config.yaml
```

If `TALON_ADMIN_KEY` is unset, admin endpoints are unrestricted (dev only).

---

## Endpoints

All dashboard endpoints are served on the main server port (same as `/health`, `/v1/evidence`, etc.).

### `GET /gateway/dashboard`

Returns the single-file HTML dashboard. The page auto-connects to the SSE stream for live updates, with a polling fallback.

**Authentication:** Requires admin auth. Any of:

- **Header (recommended):** `X-Talon-Admin-Key: <key>`
- **Bearer:** `Authorization: Bearer <key>`
- **Query (GET only, for browser bookmarks):** `?talon_admin_key=<key>` (legacy `?token=<key>` is still accepted)

Use the query parameter when opening either dashboard in a browser (browsers cannot send custom headers on navigation). Same pattern for both:

- **Governance dashboard:** `http://localhost:8080/dashboard?talon_admin_key=YOUR_TALON_ADMIN_KEY`
- **Gateway dashboard:** `http://localhost:8080/gateway/dashboard?talon_admin_key=YOUR_TALON_ADMIN_KEY`

Each page reads `talon_admin_key` (or legacy `token`), sets `window.TALON_ADMIN_KEY`, and removes the query from the URL so the key is not left in the address bar. API calls then use the header. Ensure the server was started with `TALON_ADMIN_KEY` set to the same value.

```bash
curl -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" http://localhost:8080/gateway/dashboard
```

### `GET /api/v1/metrics`

Returns the current metrics snapshot as JSON.

**Authentication:** Same as above.

```bash
curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" http://localhost:8080/api/v1/metrics | jq .
```

**Response:**

```json
{
  "generated_at": "2026-03-09T14:32:00Z",
  "enforcement_mode": "enforce",
  "uptime": "2h15m",
  "summary": {
    "total_requests": 1247,
    "blocked_requests": 23,
    "pii_detections": 89,
    "pii_redactions": 67,
    "tools_filtered": 12,
    "total_cost_eur": 4.82,
    "avg_latency_ms": 340,
    "p99_latency_ms": 1200,
    "error_rate": 0.018,
    "active_runs": 2,
    "pending_plans": 4,
    "approved_plans": 11,
    "rejected_plans": 2,
    "modified_plans": 1,
    "dispatched_plans": 8,
    "plan_dispatch_errors": 1
  },
  "requests_timeline": [
    {"time": "14:25", "count": 42},
    {"time": "14:30", "count": 38}
  ],
  "pii_timeline": [
    {"time": "14:25", "count": 3},
    {"time": "14:30", "count": 1}
  ],
  "cost_timeline": [
    {"time": "14:25", "cost_eur": 0.15},
    {"time": "14:30", "cost_eur": 0.12}
  ],
  "agent_stats": [
    {
      "agent": "openclaw-main",
      "requests": 820,
      "pii_detected": 45,
      "blocked": 8,
      "cost_eur": 3.10,
      "avg_latency_ms": 320
    }
  ],
  "pii_breakdown": [
    {"type": "email", "count": 42},
    {"type": "iban", "count": 18}
  ],
  "model_breakdown": [
    {"model": "gpt-4o-mini", "requests": 900, "cost_eur": 2.1}
  ],
  "provider_breakdown": [
    {"provider": "openai", "requests": 900, "cost_eur": 2.1}
  ],
  "tool_governance": {
    "total_requested": 150,
    "total_filtered": 12,
    "top_filtered": [
      {"tool": "file_write", "count": 8}
    ],
    "by_risk_level": [
      {"level": "high", "count": 5}
    ],
    "bulk_operations": 2,
    "irreversible_blocked": 3,
    "anomalous_agents": []
  },
  "shadow_summary": {
    "total_violations": 15,
    "by_type": [
      {"type": "pii_would_block", "count": 10}
    ]
  },
  "budget_status": {
    "daily_used": 4.82,
    "daily_limit": 50.0,
    "daily_percent": 9.64,
    "monthly_used": 142.50,
    "monthly_limit": 500.0,
    "monthly_percent": 28.5
  },
  "cache_stats": {
    "hits": 312,
    "hit_rate": 0.25,
    "cost_saved": 1.20
  },
  "plan_stats": {
    "pending": 4,
    "approved": 11,
    "rejected": 2,
    "modified": 1,
    "dispatched": 8,
    "dispatch_failures": 1
  },
  "sessions": [
    {
      "session_id": "sess-a41f",
      "tenant_id": "default",
      "session_source": "client_asserted",
      "client": "claude-code",
      "agents": ["claude-code"],
      "providers": ["anthropic", "openai"],
      "models": ["claude-opus-4-8", "gpt-5.3-codex"],
      "record_count": 14,
      "allowed": 13,
      "denied": 1,
      "errors": 0,
      "total_cost": 0.8412,
      "input_tokens": 48210,
      "output_tokens": 9120,
      "cache_read_tokens": 31000,
      "first_seen": "2026-07-05T13:01:11Z",
      "last_seen": "2026-07-05T13:24:53Z",
      "subagents": [
        {"agent_id": "generator", "record_count": 9, "total_cost": 0.71, "input_tokens": 40100, "output_tokens": 8000},
        {"agent_id": "judge", "parent_agent_id": "generator", "record_count": 5, "total_cost": 0.13, "input_tokens": 8110, "output_tokens": 1120}
      ]
    }
  ],
  "denials_by_reason": [
    {"reason": "session_budget_exceeded", "count": 3},
    {"reason": "policy_deny", "count": 1}
  ]
}
```

### `GET /api/v1/metrics/stream`

Server-Sent Events stream. Pushes one JSON snapshot every 5 seconds.

**Authentication:** Same as above.

```bash
curl -N -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" http://localhost:8080/api/v1/metrics/stream
```

Each event has the format:

```
data: {"generated_at":"2026-03-09T14:32:05Z","enforcement_mode":"enforce",...}

data: {"generated_at":"2026-03-09T14:32:10Z","enforcement_mode":"enforce",...}
```

The HTML dashboard connects to this endpoint automatically for live updates. If SSE fails, it falls back to polling `/api/v1/metrics` every 10 seconds.

---

## Snapshot fields reference

### Quickstart evidence attributes (optional)

When traffic comes from `--proxy-quickstart`, evidence records may include:

- `upstream_auth_mode`
- `upstream_key_source`
- `upstream_key_fingerprint`
- `gateway_annotations`

These are additive attributes and do not change existing dashboard snapshot keys.

### `summary` (top-level KPIs)

| Field | Type | Description |
|-------|------|-------------|
| `total_requests` | int | Total gateway requests since start. |
| `blocked_requests` | int | Requests denied by policy. |
| `pii_detections` | int | PII entities detected (email, IBAN, phone, SSN, etc.). |
| `pii_redactions` | int | PII entities redacted before forwarding to provider. |
| `tools_filtered` | int | Tool calls blocked or filtered by governance. |
| `total_cost_eur` | float | Cumulative LLM cost in EUR. |
| `avg_latency_ms` | int | Average end-to-end request latency (milliseconds). |
| `p99_latency_ms` | int | 99th percentile request latency (milliseconds). |
| `error_rate` | float | Fraction of requests that resulted in an error (0.0–1.0). |
| `active_runs` | int | Currently executing agent runs. |
| `pending_plans` | int | Plans currently awaiting human review. |
| `approved_plans` | int | Plans approved by a reviewer. |
| `rejected_plans` | int | Plans rejected by a reviewer. |
| `modified_plans` | int | Plans approved with modifications. |
| `dispatched_plans` | int | Approved plans already dispatched/executed. |
| `plan_dispatch_errors` | int | Dispatched plans that recorded a dispatch error. |

### `requests_timeline`, `pii_timeline`, `cost_timeline`

Time-series arrays with 5-minute buckets. Used by the dashboard to render sparklines.

- `requests_timeline[].time` — bucket label (e.g. `"14:25"`).
- `requests_timeline[].count` — request count in the bucket.
- `pii_timeline[].count` — PII detections in the bucket.
- `cost_timeline[].cost_eur` — cost accrued in the bucket.

### `agent_stats`

Per-agent aggregates. One entry per resolved agent identity (`agent.name` from its `agent.talon.yaml`).

| Field | Type | Description |
|-------|------|-------------|
| `agent` | string | Agent name (the identity the presented key resolved to). |
| `requests` | int | Total requests from this agent. |
| `pii_detected` | int | PII entities detected in this agent's traffic. |
| `blocked` | int | Requests from this agent that were blocked. |
| `cost_eur` | float | Cost attributed to this agent. |
| `avg_latency_ms` | int | Average latency for this agent. |

### `pii_breakdown`

Detection counts per PII type (e.g. `email`, `iban`, `phone`, `ssn`, `passport`).

### `model_breakdown`

Per-model request counts and cost. One entry per distinct model seen.

### `provider_breakdown`

Per-provider request counts and cost. One entry per selected provider in evidence routing decisions.

### `tool_governance`

| Field | Type | Description |
|-------|------|-------------|
| `total_requested` | int | Total tool calls attempted. |
| `total_filtered` | int | Tool calls filtered (blocked or modified). |
| `top_filtered` | array | Most-filtered tools with counts. |
| `by_risk_level` | array | Tool calls grouped by risk level (low/medium/high). |
| `bulk_operations` | int | Bulk operations detected. |
| `irreversible_blocked` | int | Irreversible operations blocked. |
| `anomalous_agents` | array | Agent IDs with unusual tool usage patterns. |

### `shadow_summary` (shadow mode only)

| Field | Type | Description |
|-------|------|-------------|
| `total_violations` | int | Violations that would have been blocked in enforce mode. |
| `by_type` | array | Violations grouped by type. |

### `budget_status`

| Field | Type | Description |
|-------|------|-------------|
| `daily_used` | float | EUR spent today. |
| `daily_limit` | float | Daily cost cap (see note below). |
| `daily_percent` | float | Daily utilization percentage. |
| `monthly_used` | float | EUR spent this month. |
| `monthly_limit` | float | Monthly cost cap (see note below). |
| `monthly_percent` | float | Monthly utilization percentage. |

The global budget widget denominates against what enforcement actually gates on (#288): in gateway mode, the **sum of per-agent binding effective caps** over the identity registry — registry + `ResolveEffectivePolicy`, the same path enforcement uses, where the binding cap is the tightest of the agent's resolved cap and the organization ceiling (`constraints.max_daily_cost`/`max_monthly_cost`, #287). With #266's single loaded agent this is exactly that agent's cap; per-agent drill-down is the fleet view's job (#270/#143). Native mode (no gateway) uses the agent policy's own `cost_limits` — what the runner enforces.

#### `GET /v1/costs/budget` (per-agent budget endpoint)

Query params: `tenant_id` (or derived from the presenting agent key), `agent_id`. Returns `daily_used` / `monthly_used`, the applicable `daily_limit` / `monthly_limit`, and `budget_source`:

- `"agent_effective_cap"` — the limits are the agent's **binding effective** caps, resolved for `agent_id` by the same shared computation enforcement uses (organization defaults → the agent's one override, bounded by the organization ceilings, #287/#288). With no `agent_id`, the tenant's **single** registered agent resolves this way when exactly one exists.
- `"unknown_agent"` — a running gateway did not find `agent_id` in the identity registry: no limits are reported (never the default agent file's caps), and `note` says so explicitly — until `agents_dir` (#267) exactly one agent policy is loaded per gateway (#290).
- `"unresolved_multi_agent"` — no `agent_id` was given and the tenant has several registered agents; query a specific `agent_id`.
- `"policy_cost_limits"` — native mode (no gateway): the limits come from the loaded agent policy file's `policies.cost_limits`, which is what the native runner enforces.

`talon costs` consumes this endpoint when the server is reachable (`--url`, default `http://localhost:8080`; `TALON_ADMIN_KEY` authenticates) and labels the source `server_*` in both the JSON payload and the human-readable budget lines. A server ANSWER is final — including `unknown_agent` / `unresolved_multi_agent` (the CLI then reports no denominator; it never "falls back" past an authoritative no). Only an **unreachable** server permits offline local resolution, which reports **no** denominator for an agent other than the loaded default (#288/#290). A server that is up but rejects the query (auth, wrong deployment) is a hard error when `--url` was set explicitly, and a loud warning + local fallback for the default probe (something unrelated on `:8080` must not break offline use).

### `cache_stats`

| Field | Type | Description |
|-------|------|-------------|
| `hits` | int | Cache hits (served from semantic cache). |
| `hit_rate` | float | Cache hit ratio (0.0–1.0). |
| `cost_saved` | float | Estimated cost saved by cache hits (EUR). |

### `plan_stats`

Plan lifecycle counters (same values surfaced in `summary.*_plans` fields).

| Field | Type | Description |
|-------|------|-------------|
| `pending` | int | Plans in pending review state. |
| `approved` | int | Plans approved by reviewer. |
| `rejected` | int | Plans rejected by reviewer. |
| `modified` | int | Plans approved with modifications. |
| `dispatched` | int | Approved plans marked as dispatched. |
| `dispatch_failures` | int | Dispatched plans with non-empty `dispatch_error`. |

### `sessions`

Orchestration session drill-down (#199): the most recently active client- or
vendor-asserted coding sessions (bounded to the 20 most recent), re-derived
from signed evidence on every snapshot by the **same pure function** behind
`talon audit list --session <id>` (`evidence.BuildSessionSummary`) — the
dashboard and the CLI cannot disagree, and a metrics-collector rebuild
(`ReconcileFromStore`) cannot change these numbers. Omitted when no
orchestration data exists (synthetic per-request session ids never appear).
Each entry is a session summary:

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | Client-asserted session id (hostile input — escape before rendering). |
| `tenant_id` | string | Owning tenant. |
| `session_source` | string | `client_asserted` \| `vendor_asserted`. |
| `client` | string | Adapter that asserted it (`claude-code`, `codex`, `generic`). |
| `agents` | array | Every gateway agent identity (traffic identity) observed on this session id — a cross-agent collision is visible, never merged. |
| `providers` / `models` | array | Distinct providers/models used — a mixed-provider session is ONE session. |
| `record_count` / `allowed` / `denied` / `errors` | int | Request outcome counts. |
| `total_cost` | float | Accumulated signed spend (EUR). |
| `input_tokens` / `output_tokens` / `cache_read_tokens` / `cache_write_tokens` | int | Token totals. |
| `first_seen` / `last_seen` | timestamp | Session activity window. |
| `subagents` | array | Per-subagent rollup (client-asserted `agent_id`, optional `parent_agent_id`), sorted by descending cost. |

### `denials_by_reason`

Denied requests bucketed by the machine-code prefix of their first policy
reason (`session_budget_exceeded`, `budget_exceeded`, `egress_*`, …) so
session denials do not lump under a generic `policy_deny` (#199). Sorted by
descending count; omitted when there are no denials.

---

## CLI ↔ dashboard parity

The dashboard metrics and CLI commands (`talon costs`, `talon audit list`, `talon report`) share the same underlying `MetricsQuerier` interface against the evidence store. This ensures:

- `talon costs --tenant default` reports the same daily/monthly totals as `budget_status` in the dashboard.
- `talon costs --by-provider` aligns with `provider_breakdown` in `/api/v1/metrics`.
- `talon report` counts match `summary.total_requests` and `summary.pii_detections`.
- Evidence records shown by `talon audit list` are the same records that feed the dashboard timelines.

Cost export surfaces:

- CLI: `talon costs export --format csv|json --tenant <id> [--agent <id>]`
- API: `POST /v1/costs/export` with `{tenant_id, agent_id, from, to, format}`

Both export surfaces include evidence ID, tenant/agent, timestamp, model/provider, cost, token counts, and policy decision/reason so rows can be joined to signed evidence exports by evidence ID.

The in-memory collector adds real-time aggregation (5-minute buckets, latency percentiles) on top of the querier, so the dashboard may reflect very recent events slightly sooner than CLI queries that read directly from SQLite.

## Evidence-first runtime

Invariants:

- Metrics emission requires a successful evidence write. No evidence → no event → no metric.
- Backpressure drops surface as `dropped_events` in `/api/v1/metrics` and `metrics_events_dropped` in `/v1/status`.

Scope (locked in v1.5.0):

- `/api/v1/metrics` is the runtime SSOT snapshot for all evidence-backed Talon activity visible to the collector, not gateway-only request counters.
- Event feeds (`/api/v1/events/recent`, `/api/v1/events/stream`) emit terminal outcomes plus evidence-backed lifecycle events. No lifecycle row is emitted without a persisted evidence record.

## Validation

| Check | Command | Pass condition |
|-------|---------|----------------|
| Gates | `make test && make lint && make check` | exit 0 |
| Status fields | `curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" http://localhost:8080/v1/status` | includes `metrics_events_dropped`, `events_stream_gaps`, `events_replay_misses`, `events_backlog_drops` |
| Recent events | `curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" "http://localhost:8080/api/v1/events/recent?limit=10"` | each row has `event_id`, `evidence_id`, `decision`, `reason_code`, optional `reasons[]`, `cost_eur`, `correlation_id` |
| SSE resume | `curl -N -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" -H "Last-Event-ID: <id>" http://localhost:8080/api/v1/events/stream` | stream resumes after `<id>`; emits `event: gap` on cursor miss |
| Dashboard parity | open `http://localhost:8080/dashboard?talon_admin_key=$TALON_ADMIN_KEY` | "Session timeline" rows match `/api/v1/events/recent` |

---

## Security

| Concern | Approach |
|---------|----------|
| Authentication | `TALON_ADMIN_KEY` on the server. Clients send `X-Talon-Admin-Key` (preferred) or bearer fallback. Token comparison uses `crypto/subtle.ConstantTimeCompare`. |
| Network binding | Dashboard is served on the main listen address. Bind to `127.0.0.1:8080` (default) to prevent external access. Use a reverse proxy with TLS for production. |
| No secrets in responses | The metrics snapshot never contains API keys, secrets, or raw prompt/response content. |
| CORS | Not enabled by default. Add CORS middleware if the dashboard is accessed from a different origin. |

---

## Relationship to OTel metrics

The dashboard and OTel metrics are complementary:

| | Gateway dashboard | OTel metrics |
|---|---|---|
| **Purpose** | Real-time operational view | Long-term storage, alerting, Grafana |
| **Data source** | In-memory collector + evidence backfill | OTel SDK instruments |
| **Retention** | In-process (resets on restart) | Depends on backend (Prometheus, etc.) |
| **Access** | Browser / curl | Prometheus, Grafana, OTLP backends |
| **Granularity** | 5-minute buckets, per-agent | Per-request via attributes |

Use the dashboard for at-a-glance monitoring. Use OTel + Grafana for historical analysis, alerting, and SLA tracking. See [Observability](../OBSERVABILITY.md) for the full OTel metrics catalogue and [`examples/observability/`](../../examples/observability/) for the local Grafana stack.

---

## Related governance dashboard endpoints

When using the main governance dashboard (`/dashboard`), Talon also exposes:

- `GET /v1/dashboard/agent-health` - per-agent risk-oriented health summary
- `GET /v1/dashboard/drift-signals` - drift z-scores (cost anomaly, denial-rate spike, PII-rate change)
- `GET /v1/dashboard/denials-by-reason` - store-wide denied total with a per-reason breakdown (`pii_block`, `policy_deny`, `attachment_block`, `tool_filtered`)

These endpoints are used by the embedded UI and can also be queried directly for custom dashboards.

### Unified dashboard semantics

A few `/dashboard` behaviors worth knowing when reading the page:

- The **Blocked (all evidence)** card shows the store-wide denied total from `/v1/dashboard/denials-by-reason` — the same number as the "All evidence: N denied" line. It does not change when the evidence table is filtered; clicking the card applies the Denied filter to drill into those records.
- **Visible requests** and **Visible cost** are computed from the currently visible evidence rows, so they *do* change with filters.
- The **Detail** button is read-only: it shows the signed fields, trust/spend attribution, and step trace without verifying the record. Signature verification only happens via the explicit **Verify** / **Verify visible records** buttons, which update the Integrity column.
