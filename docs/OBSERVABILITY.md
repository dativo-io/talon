# Observability in Talon

Talon uses **OpenTelemetry** for traces and metrics, and **zerolog** for structured logs. Evidence records are stored in SQLite for compliance; traces and metrics are for operational observability.

## Enabling OpenTelemetry

OTel is off by default. Enable it in one of these ways:

- **Flag:** `talon --otel run "query"` or `talon --otel serve`
- **Environment:** `TALON_OTEL_ENABLED=true`
- **Verbose:** `talon -v ...` also enables OTel (for development)

Example (production-style, without turning on verbose logs):

```bash
export TALON_OTEL_ENABLED=true
talon serve
```

Or:

```bash
talon --otel serve
```

## What is exported

- **Traces:** Span hierarchy for agent runs, policy evaluation, LLM calls, evidence store, secrets, memory, and HTTP requests (when using `talon serve`). Spans include `correlation_id`, `tenant_id`, `agent_id`, and GenAI attributes where applicable.
- **Metrics:** 25+ OTel instruments across all subsystems (see [Metrics reference](#metrics-reference) below). Exported via OTLP or stdout depending on configuration.
- **Logs:** Structured JSON or console via zerolog. Key log lines include `trace_id` and `span_id` when OTel is enabled so logs can be correlated with traces in a backend.

Export destination is **stdout** by default. Use the OTLP exporter to send traces and metrics to a collector (e.g. Jaeger, Prometheus, Grafana). See [examples/observability](../examples/observability/) for a ready-made local stack.

---

## Metrics reference

All metrics are registered via the OpenTelemetry Go SDK. The tables below group them by subsystem. Every metric follows the naming convention `talon.<subsystem>.<metric>` for custom metrics or [GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) for standard LLM telemetry.

### LLM / GenAI

Registered by `internal/llm`. Emitted on every LLM call.

| Metric | Type | Unit | Attributes | Description |
|--------|------|------|------------|-------------|
| `talon.cost.request` | Float64Histogram | `eur` | `agent`, `model`, `degraded` | Cost in EUR per LLM request. |
| `gen_ai.client.token.usage` | Int64Histogram | `{token}` | `gen_ai.system`, `gen_ai.request.model`, `gen_ai.token.type` | Token usage per LLM request (input/output). GenAI SemConv. |
| `gen_ai.client.operation.duration` | Float64Histogram | `s` | `gen_ai.system`, `gen_ai.request.model` | End-to-end LLM operation duration. GenAI SemConv. |
| `talon.provider.availability` | Float64Gauge | `1` | `provider` | Provider availability (1 = up, 0 = down). |
| `talon.provider.failover.total` | Int64Counter | `{failover}` | `original_model`, `fallback_model`, `reason` | Provider failover events (cost degradation or unavailability). |

### Gateway

Registered by `internal/gateway`. Emitted for every request through the LLM API gateway.

| Metric | Type | Unit | Attributes | Description |
|--------|------|------|------------|-------------|
| `talon.gateway.requests.total` | Int64Counter | `{request}` | `caller`, `model`, `gen_ai.system`, `status` | Total gateway proxy requests. |
| `talon.gateway.errors.total` | Int64Counter | `{error}` | `error_type` | Gateway errors by type (auth, policy, provider, timeout). |
| `talon.data_tier.requests` | Int64Counter | `{request}` | `tier`, `caller` | Requests by data classification tier (0/1/2). |
| `talon.tools.governance.total` | Int64Counter | `{decision}` | `tool`, `action` | Tool governance decisions (allow, block, filter). |
| `talon.cache.hits` | Int64Counter | `{hit}` | `tenant_id` | Semantic cache hits (request served from cache). |
| `talon.cache.misses` | Int64Counter | `{miss}` | `tenant_id` | Semantic cache misses (forwarded to LLM). |
| `talon.shadow.violations.total` | Int64Counter | `{violation}` | `violation_type` | Shadow mode violations (would-have-blocked in enforce mode). |
| `talon.budget.utilization` | Float64Gauge | `%` | `tenant_id`, `period` | Current budget utilization as a percentage. |
| `talon.budget.alerts.total` | Int64Counter | `{alert}` | `tenant_id`, `threshold` | Budget threshold breach alerts. |

### Policy engine

Registered by `internal/policy`. Emitted on every policy evaluation (OPA).

| Metric | Type | Unit | Attributes | Description |
|--------|------|------|------------|-------------|
| `talon.policy.evaluations.total` | Int64Counter | `{evaluation}` | `decision`, `tenant_id`, `agent_id` | Policy evaluation count by decision (allow/deny). |
| `talon.policy.evaluation.duration` | Float64Histogram | `ms` | `tenant_id` | Policy evaluation latency in milliseconds. |

### PII classifier

Registered by `internal/classifier`. Emitted when PII is detected or redacted.

| Metric | Type | Unit | Attributes | Description |
|--------|------|------|------------|-------------|
| `talon.pii.detections.total` | Int64Counter | `{detection}` | `pii_type`, `direction`, `action` | PII entities detected (email, IBAN, phone, etc.). |
| `talon.pii.redactions.total` | Int64Counter | `{redaction}` | `pii_type`, `direction` | PII entities redacted before forwarding. |

### Evidence store

Registered by `internal/evidence`. Emitted on every evidence write or verification.

| Metric | Type | Unit | Attributes | Description |
|--------|------|------|------------|-------------|
| `talon.evidence.records.total` | Int64Counter | `{record}` | `type` | Evidence records stored (LLM, tool, secret, memory). |
| `talon.evidence.signature_verifications` | Int64Counter | `{verification}` | `result` | HMAC signature verification attempts (success/failure). |

### Secrets vault

Registered by `internal/secrets`. Emitted on every secret access attempt.

| Metric | Type | Unit | Attributes | Description |
|--------|------|------|------------|-------------|
| `talon.secrets.access.total` | Int64Counter | `{access}` | `secret_name`, `agent_id`, `outcome` | Secret access attempts (granted/denied). |

### Attachment scanner

Registered by `internal/attachment`. Emitted when prompt injection patterns are detected.

| Metric | Type | Unit | Attributes | Description |
|--------|------|------|------------|-------------|
| `talon.injection.attempts.total` | Int64Counter | `{attempt}` | `detection_type`, `action` | Prompt injection attempts detected in attachments. |

### Agent memory

Registered by `internal/memory`. Emitted on memory operations.

| Metric | Type | Unit | Attributes | Description |
|--------|------|------|------------|-------------|
| `memory.writes.total` | Int64Counter | `{write}` | `category`, `tenant_id` | Memory entries written. |
| `memory.writes.denied` | Int64Counter | `{write}` | `reason` | Memory writes denied (PII, forbidden category). |
| `memory.conflicts.detected` | Int64Counter | `{conflict}` | `resolution` | Memory conflicts detected during consolidation. |
| `memory.reads.total` | Int64Counter | `{read}` | `source`, `tenant_id` | Memory entries read (for prompt injection). |
| `memory.entries.count` | Int64Gauge | `{entry}` | `tenant_id`, `agent_id` | Current memory entry count per agent. |
| `memory.dedup.skips` | Int64Counter | `{skip}` | `tenant_id` | Duplicate memory writes suppressed by dedup window. |
| `memory.consolidation.noops` | Int64Counter | `{noop}` | — | Consolidation runs that found nothing to merge. |
| `memory.consolidation.invalidations` | Int64Counter | `{invalidation}` | — | Entries invalidated during consolidation. |
| `memory.consolidation.updates` | Int64Counter | `{update}` | — | Entries updated during consolidation. |
| `talon.memory.poisoning.blocked` | Int64Counter | `{block}` | `reason`, `agent_id` | Memory poisoning attempts blocked by governance. |

---

## Gateway dashboard metrics

In addition to OTel metrics, Talon provides a **real-time gateway dashboard** with an in-memory metrics collector. The dashboard aggregates evidence records into a live snapshot available at:

- **HTML dashboard:** `GET /gateway/dashboard` — single-page HTML with auto-refreshing charts.
- **JSON API:** `GET /api/v1/metrics` — full snapshot for programmatic access.
- **SSE stream:** `GET /api/v1/metrics/stream` — Server-Sent Events, one snapshot every 5 seconds.

The dashboard snapshot includes:

| Field | Type | Description |
|-------|------|-------------|
| `summary.total_requests` | int | Total requests processed. |
| `summary.blocked_requests` | int | Requests denied by policy. |
| `summary.pii_detections` | int | PII entities found across all requests. |
| `summary.pii_redactions` | int | PII entities redacted. |
| `summary.tools_filtered` | int | Tool calls filtered by governance. |
| `summary.total_cost_eur` | float | Cumulative cost in EUR. |
| `summary.avg_latency_ms` | int | Average request latency. |
| `summary.p99_latency_ms` | int | P99 request latency. |
| `summary.error_rate` | float | Error rate (0.0–1.0). |
| `summary.active_runs` | int | Currently executing agent runs. |
| `requests_timeline` | array | 5-minute bucketed request counts. |
| `pii_timeline` | array | 5-minute bucketed PII detection counts. |
| `cost_timeline` | array | 5-minute bucketed cost in EUR. |
| `caller_stats` | array | Per-caller aggregates (requests, PII, blocked, cost, latency). |
| `pii_breakdown` | array | Detections broken down by PII type (email, IBAN, phone, etc.). |
| `model_breakdown` | array | Requests and cost broken down by LLM model. |
| `tool_governance` | object | Tool filtering stats (total, filtered, by risk level, anomalous agents). |
| `shadow_summary` | object | Shadow mode violation summary (only present in shadow mode). |
| `budget_status` | object | Budget utilization (daily/monthly used, limit, percentage). |
| `cache_stats` | object | Semantic cache performance (hits, hit rate, cost saved). |

See [Gateway dashboard reference](reference/gateway-dashboard.md) for full configuration, authentication, and API details.

---

## Log–trace correlation

When OTel is enabled, critical log events (e.g. `agent_run_started`, `agent_run_completed`, `failed_to_generate_evidence`) include `trace_id` and `span_id`. In an observability backend that ingests both logs and traces, you can jump from a log line to the corresponding trace.

## Structured log fields

Logs consistently include:

- `correlation_id` – unique per agent run
- `tenant_id` – tenant scope
- `agent_id` – agent name
- `trace_id` / `span_id` – when OTel is enabled

Use these for filtering and correlation in your log aggregation (e.g. Elasticsearch, Loki).

## HTTP server tracing

When running `talon serve`, the chi router uses OTel middleware. Each HTTP request (health, status, webhooks) gets a root span; agent runs triggered by webhooks appear as child spans, so you can see the full request → run → LLM/tool chain in one trace.

## Local observability stack

A ready-made Docker Compose stack is provided in [`examples/observability/`](../examples/observability/). It includes:

- **OpenTelemetry Collector** — receives OTLP from Talon, exports to Prometheus
- **Prometheus** — scrapes metrics from the Collector
- **Grafana** — pre-built dashboard for all `talon.*` and `gen_ai.*` metrics

Start the stack:

```bash
cd examples/observability
docker compose up -d
```

Then configure Talon to export to the Collector:

```bash
export TALON_OTEL_ENABLED=true
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
talon serve --gateway
```

Open Grafana at `http://localhost:3000` (admin/admin) to see the pre-built Talon Gateway dashboard.

See [examples/observability/README.md](../examples/observability/README.md) for details.
