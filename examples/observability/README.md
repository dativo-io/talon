# Observability stack (local)

A Docker Compose stack for visualising Talon's OpenTelemetry metrics locally. Includes:

- **OpenTelemetry Collector** — receives OTLP from Talon, exports to Prometheus
- **Prometheus** — scrapes the Collector's Prometheus exporter
- **Grafana** — pre-built dashboard for all `talon.*` and `gen_ai.*` metrics

## Quick start

```bash
# 1. Start the stack
cd examples/observability
docker compose up -d

# 2. Run Talon with OTel export enabled
export TALON_OTEL_ENABLED=true
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
talon serve --gateway --gateway-config talon.config.yaml

# 3. Send some traffic through the gateway, then open Grafana
open http://localhost:3000
```

Grafana starts with anonymous admin access (`admin` / `talon`). The pre-provisioned "Talon Gateway" dashboard is available immediately.

## Ports

| Service | Port | URL |
|---------|------|-----|
| OTel Collector (OTLP gRPC) | 4317 | — |
| OTel Collector (OTLP HTTP) | 4318 | — |
| Prometheus | 9090 | http://localhost:9090 |
| Grafana | 3000 | http://localhost:3000 |

## Architecture

```
┌──────────┐  OTLP   ┌────────────────────┐  scrape  ┌────────────┐
│  Talon   │────────▶│  OTel Collector    │◀────────│ Prometheus │
│  serve   │         │  :4317 (gRPC)      │ :8889   │  :9090     │
└──────────┘         │  :4318 (HTTP)      │         └─────┬──────┘
                     └────────────────────┘               │
                                                          ▼
                                                   ┌────────────┐
                                                   │  Grafana   │
                                                   │  :3000     │
                                                   └────────────┘
```

## Metrics available

Once traffic flows through Talon with OTel enabled, the following metric families appear in Prometheus/Grafana:

### LLM / GenAI

| Metric | Type | Description |
|--------|------|-------------|
| `talon_cost_request` | histogram | Cost per LLM request (EUR). |
| `gen_ai_client_token_usage` | histogram | Token usage per request (input/output). |
| `gen_ai_client_operation_duration` | histogram | LLM call duration (seconds). |
| `talon_provider_availability` | gauge | Provider up/down status. |
| `talon_provider_failover_total` | counter | Provider failover events. |

### Gateway

| Metric | Type | Description |
|--------|------|-------------|
| `talon_gateway_requests_total` | counter | Total gateway requests by caller, model, status. |
| `talon_gateway_errors_total` | counter | Errors by type. |
| `talon_data_tier_requests` | counter | Requests by data classification tier. |
| `talon_tools_governance_total` | counter | Tool governance decisions. |
| `talon_cache_hits` | counter | Semantic cache hits. |
| `talon_cache_misses` | counter | Semantic cache misses. |
| `talon_shadow_violations_total` | counter | Shadow mode violations. |
| `talon_budget_utilization` | gauge | Budget utilization (%). |
| `talon_budget_alerts_total` | counter | Budget threshold breaches. |

### Policy & compliance

| Metric | Type | Description |
|--------|------|-------------|
| `talon_policy_evaluations_total` | counter | Policy evaluations by decision. |
| `talon_policy_evaluation_duration` | histogram | Policy evaluation latency (ms). |
| `talon_pii_detections_total` | counter | PII detections by type. |
| `talon_pii_redactions_total` | counter | PII redactions by type. |
| `talon_evidence_records_total` | counter | Evidence records stored. |
| `talon_evidence_signature_verifications` | counter | HMAC verifications. |
| `talon_secrets_access_total` | counter | Secret access attempts. |
| `talon_injection_attempts_total` | counter | Prompt injection attempts. |
| `talon_memory_poisoning_blocked` | counter | Memory poisoning blocks. |

> **Note:** Prometheus converts dots to underscores (`talon.cost.request` → `talon_cost_request`). The Grafana dashboard uses the Prometheus names.

### Memory

| Metric | Type | Description |
|--------|------|-------------|
| `memory_writes_total` | counter | Memory entries written. |
| `memory_writes_denied` | counter | Memory writes denied. |
| `memory_reads_total` | counter | Memory entries read. |
| `memory_entries_count` | gauge | Current entry count per agent. |
| `memory_dedup_skips` | counter | Duplicate writes suppressed. |

## Pre-built Grafana dashboard

The provisioned dashboard (`grafana/dashboards/talon-gateway.json`) includes panels for:

- Request rate and error rate over time
- Cost per model and cumulative spend
- PII detections by type
- Policy allow/deny ratio
- Token usage histograms
- Provider availability and failover events
- Budget utilization gauges
- Cache hit/miss ratio

## Customisation

- **Retention:** Edit `prometheus.yml` to adjust `scrape_interval` or add remote write.
- **Alerting:** Add Prometheus alerting rules for `talon_budget_utilization > 80`, `talon_gateway_errors_total` rate spikes, etc.
- **Production:** Replace this stack with your existing Prometheus/Grafana/LGTM deployment; just point Talon's OTLP exporter at your collector.

## Stopping

```bash
docker compose down
```

## See also

- [Observability in Talon](../../docs/OBSERVABILITY.md) — full metrics reference.
- [Gateway dashboard reference](../../docs/reference/gateway-dashboard.md) — built-in dashboard API.
