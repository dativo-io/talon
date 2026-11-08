# Legacy dashboard migration map

**Status:** reference for the OSS operations console epic (#533). It records what the two removed browser dashboards showed, which Go projection or endpoint was the source of each number, and what operator surface carries that fact today. It is the inventory output of #534 and the input to the console's data layer (#535). It describes shipped behaviour as of the removal; it promises nothing about the console.

The dashboards were removed, not deprecated: `GET|HEAD /`, `GET|HEAD /dashboard`, `GET /gateway/dashboard` and `GET /v1/dashboard/*` return a plain `404` with or without the admin key (`TestRoutes_NoLegacyDashboardRoutes`, smoke section 12). See [LIMITATIONS §11](../../LIMITATIONS.md#11-operator-ui-boundary-legacy-dashboards-removed-replacement-console-tracked-in-533).

## Rules this map encodes

1. **One projection per fact.** Every row names the Go function or HTTP route that owns the number. The console renders projections; it does not re-derive them in the browser. The removed pages computed several figures in JavaScript (FinOps mapping of the metrics snapshot, compliance tab wrappers, evidence verify/detail flow); none of that JavaScript held a calculation missing from Go, so nothing was ported.
2. **Gaps are recorded, not rebuilt here.** A row marked *gap* has a store-level projection but no CLI or HTTP surface. The console epic decides whether to expose it as a typed, bounded DTO. Nothing in this document is a commitment to do so.
3. **Credentials never travel in a URL or a cookie.** The removed pages carried the admin key in `?talon_admin_key=` and copied it into a `talon_admin_session` cookie. Those carriers are gone from every admin middleware (`TestAdminKey_QueryAndCookieNoLongerAuthenticate`). The only carriers are the `X-Talon-Admin-Key` header and `Authorization: Bearer <admin key>`. Console pairing (#536, #537) must not reintroduce a browser carrier and must not relax the backend's admin middleware; it secures the console process, not the Talon API behind it.

## Removed routes and their disposition

| Removed route | Served | Disposition |
|---|---|---|
| `GET\|HEAD /`, `GET\|HEAD /dashboard` | `web/dashboard.html`, unauthenticated page, admin key in the query string | Deleted. No redirect; `404`. |
| `GET /gateway/dashboard` | `web/gateway_dashboard.html` over the metrics API | Deleted. `GET /api/v1/metrics` and `/api/v1/metrics/stream` stay, mounted whenever the gateway is on. |
| `GET /v1/dashboard/tenants-summary` | per-tenant volume, spend today/month, denials, pending plans; per-agent month summary | Deleted. Projections kept, see below. |
| `GET /v1/dashboard/agent-health` | 24-hour per-agent health rows | Deleted. Documented for direct use, but not fetched by the final page. |
| `GET /v1/dashboard/drift-signals` | drift z-scores per agent | Deleted. `talon monitor` is the surface. |
| `GET /v1/dashboard/denials-by-reason` | store-wide denied total and per-reason breakdown | Deleted. Projection kept. |
| `GET /v1/dashboard/governance-alerts` | last N `tool_filtered` / `attachment_injection` records | Deleted. Projection kept. |
| `GET /v1/dashboard/audit-pack` | a JSON file combining four counts | Deleted. Each count remains available separately. |
| `GET /v1/dashboard/review-history` | last N reviewed plans | Deleted. Projection kept. |
| `talon serve --dashboard`, `gateway.dashboard_listen` | flag and never-wired config key | Removed. The key now fails config loading with a migration error naming #533. |

## Widget to source of truth

| Former widget | What it showed | Authoritative projection | Operator surface today | For the console |
|---|---|---|---|---|
| FinOps cards: requests, daily, monthly, budget | gateway request and outcome counters, spend, budget utilisation | `metrics.Collector.Snapshot` (`GET /api/v1/metrics`, SSE at `/api/v1/metrics/stream`); effective caps from `ResolveEffectivePolicy` via `GET /v1/costs/budget` | `talon metrics [--json] [--agent]`, `talon costs [--by-provider\|--by-model\|--session]` | Parity. Reuse the snapshot; do not recompute totals client-side. |
| Blocked (all evidence) card | store-wide denied total with `pii_block` / `policy_deny` / `attachment_block` / `tool_filtered` breakdown, optional `from`/`to` | `evidence.Store.DenialsByReason(ctx, tenantID, from, to)` | None for the store-wide figure. The metrics snapshot carries `denials_by_reason` for the gateway window only, which is a different number. | Gap. Expose as a bounded DTO with an explicit time range. |
| Tenants panel | per tenant: request volume, spend today and month, denials, pending plans | `evidence.Store.TenantsSummary(ctx, dayStart, dayEnd, monthStart, monthEnd, tenantID)` plus `agent.PlanReviewStore.GetPending` counted per tenant | None per tenant. Per-agent month rows: `GET /v1/agents/fleet`, `talon agents` (the fleet projection calls `evidence.Store.AgentsSummary`). | Gap for the per-tenant rows. Per-agent rows: reuse the fleet projection. |
| Agent health (documented endpoint) | 24-hour per-agent rows | `evidence.Store.AgentHealthSummary(ctx, from, to, tenantID)`; no caller remains | `talon agents show <agent>` reports state, health, cost versus caps and signals from the fleet projection | Decide once: either the fleet projection is the health surface and `AgentHealthSummary` is retired, or it is exposed. Do not keep both. |
| Drift signals | cost anomaly, denial-rate spike, PII-rate change per agent | `drift.Analyzer.ComputeSignals(ctx, tenantID, now)` | `talon monitor [--tenant]` | Parity on the CLI; no HTTP route. The console would need one. |
| Governance alerts feed | last N `tool_filtered` / `attachment_injection` evidence records | `evidence.Store.ListGovernanceAlerts(ctx, tenantID, limit)` | None as a feed. The records are ordinary evidence (`talon audit list`, `GET /v1/evidence`). | Gap. |
| Plans panel | pending plans, approve and reject | `agent.PlanReviewStore.GetPending`; `GET /v1/plans/pending`, `POST /v1/plans/{id}/approve\|reject\|modify` (admin key) | `talon plan pending\|approve\|reject` | Parity. Routes unchanged. |
| Review history | last N reviewed plans with decision | `agent.PlanReviewStore.ListReviewed(ctx, tenantID, limit)` | None | Gap. |
| Memory panel | pending memory reviews, approve | `/v1/memory*` routes, unchanged; `memory.Store.CountPendingReviewForTenant` for the count | `/v1/memory*` (admin key) | Parity on the routes. |
| Audit pack download | `evidence_count`, `cost_eur`, `pending_plans`, `pending_memory_reviews` for a range | composition of `evidence.Store.CountInRange`, `evidence.Store.CostTotal`, `agent.PlanReviewStore.GetPending`, `memory.Store.CountPendingReviewForTenant` | `talon report --tenant`, `talon audit export`, `talon costs`, `talon plan pending` | The composition is gone. If the console wants it, compose typed projections; do not add a route that re-bundles them. |
| Evidence table, detail, verify, export | records, HMAC verification, CSV/JSON export | `GET /v1/evidence`, `GET /v1/evidence/{id}`, `GET /v1/evidence/{id}/verify`, `GET /v1/evidence/export`, unchanged | `talon audit list\|show\|verify\|export` | Parity. |
| Compliance tab | coverage, RoPA, Annex IV, framework report | `GET /v1/compliance/{coverage,ropa,annex-iv,report}`, unchanged | `talon compliance ...` | Parity. |
| Live events strip | recent and streamed events | `GET /api/v1/events/recent`, `GET /api/v1/events/stream`, unchanged | none (API only) | Parity on the API. |
| Gateway dashboard page | the metrics snapshot rendered live | `GET /api/v1/metrics`, `GET /api/v1/metrics/stream` | `talon metrics` | Parity. See [Gateway metrics API](gateway-metrics-api.md). |

## Gaps, in one list

Store-level projections with no CLI or HTTP surface after the removal: per-tenant summary (`TenantsSummary`), store-wide denials by reason (`DenialsByReason`), governance-alert feed (`ListGovernanceAlerts`), plan review history (`ListReviewed`), and the undecided `AgentHealthSummary`. Drift signals have a CLI surface but no HTTP route. The audit-pack composition exists only as its four parts.

## Authentication facts the console must respect

- `TALON_ADMIN_KEY` semantics are unchanged: header or bearer token, and the server is open when the key is unset (development default). The example Compose stack publishes the API on `8080:8080` and does not set the key. Securing the console process does not secure that API; #536 and #537 must define the boundary between the read-only console and privileged backend operations before a default Docker UI ships.
- `RequireAdminKeyMiddleware` fails closed when the gateway is served; nothing in the removal changed which endpoints sit behind which middleware.

Related: [Authentication and key scopes](authentication-and-key-scopes.md), [Operational control plane](operational-control-plane.md), [Gateway metrics API](gateway-metrics-api.md).
