# Gateway dashboard reference

The gateway dashboard provides real-time visibility into LLM API gateway traffic. It shows request volumes, cost, PII detections, policy enforcement, tool governance, and budget utilization — all from a single embedded HTML page with no external dependencies.

---

## Enabling the dashboard

The dashboard is available when Talon runs in gateway mode. No extra flags are needed:

```bash
talon serve --gateway --gateway-config talon.config.yaml
```

The dashboard is served on the same port as the API (default `:8080`).

### Configuration

Add the following to the `gateway:` block in `talon.config.yaml`:

```yaml
gateway:
  # ... providers, callers, etc.
  dashboard_token: "your-secret-token"   # optional; when set, all dashboard endpoints require this token
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `gateway.dashboard_token` | string | `""` (no auth) | Bearer token for dashboard access. When empty, dashboard is open. |

---

## Endpoints

All dashboard endpoints are served on the main server port (same as `/health`, `/v1/evidence`, etc.).

### `GET /gateway/dashboard`

Returns the single-file HTML dashboard. The page auto-connects to the SSE stream for live updates, with a polling fallback.

**Authentication:** Requires `Authorization: Bearer <dashboard_token>` when `dashboard_token` is configured.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/gateway/dashboard
```

### `GET /api/v1/metrics`

Returns the current metrics snapshot as JSON.

**Authentication:** Same as above.

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/metrics | jq .
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
    "active_runs": 2
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
  "caller_stats": [
    {
      "caller": "openclaw-main",
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
    "daily_pct": 9.64,
    "monthly_used": 142.50,
    "monthly_limit": 500.0,
    "monthly_pct": 28.5
  },
  "cache_stats": {
    "hits": 312,
    "misses": 935,
    "hit_rate": 0.25,
    "cost_saved_eur": 1.20
  }
}
```

### `GET /api/v1/metrics/stream`

Server-Sent Events stream. Pushes one JSON snapshot every 5 seconds.

**Authentication:** Same as above.

```bash
curl -N -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/metrics/stream
```

Each event has the format:

```
data: {"generated_at":"2026-03-09T14:32:05Z","enforcement_mode":"enforce",...}

data: {"generated_at":"2026-03-09T14:32:10Z","enforcement_mode":"enforce",...}
```

The HTML dashboard connects to this endpoint automatically for live updates. If SSE fails, it falls back to polling `/api/v1/metrics` every 10 seconds.

---

## Snapshot fields reference

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

### `requests_timeline`, `pii_timeline`, `cost_timeline`

Time-series arrays with 5-minute buckets. Used by the dashboard to render sparklines.

- `requests_timeline[].time` — bucket label (e.g. `"14:25"`).
- `requests_timeline[].count` — request count in the bucket.
- `pii_timeline[].count` — PII detections in the bucket.
- `cost_timeline[].cost_eur` — cost accrued in the bucket.

### `caller_stats`

Per-caller (application identity) aggregates. One entry per `gateway.callers[].name`.

| Field | Type | Description |
|-------|------|-------------|
| `caller` | string | Caller name from gateway config. |
| `requests` | int | Total requests from this caller. |
| `pii_detected` | int | PII entities detected in this caller's traffic. |
| `blocked` | int | Requests from this caller that were blocked. |
| `cost_eur` | float | Cost attributed to this caller. |
| `avg_latency_ms` | int | Average latency for this caller. |

### `pii_breakdown`

Detection counts per PII type (e.g. `email`, `iban`, `phone`, `ssn`, `passport`).

### `model_breakdown`

Per-model request counts and cost. One entry per distinct model seen.

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
| `daily_limit` | float | Daily cost cap from policy. |
| `daily_pct` | float | Daily utilization percentage. |
| `monthly_used` | float | EUR spent this month. |
| `monthly_limit` | float | Monthly cost cap from policy. |
| `monthly_pct` | float | Monthly utilization percentage. |

### `cache_stats`

| Field | Type | Description |
|-------|------|-------------|
| `hits` | int | Cache hits (served from semantic cache). |
| `misses` | int | Cache misses (forwarded to LLM provider). |
| `hit_rate` | float | Cache hit ratio (0.0–1.0). |
| `cost_saved_eur` | float | Estimated cost saved by cache hits. |

---

## CLI ↔ dashboard parity

The dashboard metrics and CLI commands (`talon costs`, `talon audit list`, `talon report`) share the same underlying `MetricsQuerier` interface against the evidence store. This ensures:

- `talon costs --tenant default` reports the same daily/monthly totals as `budget_status` in the dashboard.
- `talon report` counts match `summary.total_requests` and `summary.pii_detections`.
- Evidence records shown by `talon audit list` are the same records that feed the dashboard timelines.

The in-memory collector adds real-time aggregation (5-minute buckets, latency percentiles) on top of the querier, so the dashboard may reflect very recent events slightly sooner than CLI queries that read directly from SQLite.

---

## Security

| Concern | Approach |
|---------|----------|
| Authentication | `dashboard_token` in gateway config. When set, all dashboard endpoints require `Authorization: Bearer <token>`. Token comparison uses `crypto/subtle.ConstantTimeCompare`. |
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
| **Granularity** | 5-minute buckets, per-caller | Per-request via attributes |

Use the dashboard for at-a-glance monitoring. Use OTel + Grafana for historical analysis, alerting, and SLA tracking. See [Observability](../OBSERVABILITY.md) for the full OTel metrics catalogue and [`examples/observability/`](../../examples/observability/) for the local Grafana stack.
