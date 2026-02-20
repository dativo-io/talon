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

## What is exported (MVP)

- **Traces:** Span hierarchy for agent runs, policy evaluation, LLM calls, evidence store, secrets, memory, and HTTP requests (when using `talon serve`). Spans include `correlation_id`, `tenant_id`, `agent_id`, and GenAI attributes where applicable.
- **Metrics:** Cost per LLM request (`talon.cost.request`), memory write/read counters and gauge. Exported to stdout on a periodic interval (default 60s).
- **Logs:** Structured JSON or console via zerolog. Key log lines include `trace_id` and `span_id` when OTel is enabled so logs can be correlated with traces in a backend.

Export destination is **stdout** (pretty-printed in development). Phase 2 will add an OTLP exporter option so you can send traces and metrics to a collector (e.g. Jaeger, Prometheus, Grafana) or a hosted backend.

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

## Phase 2 (planned)

- **OTLP exporter:** Configurable endpoint to send traces and metrics to an OTLP collector or backend (no code change required for existing instrumentation).
- **Log bridge:** Optional OTel log bridge so logs are emitted as OTel log records with trace context attached automatically.
