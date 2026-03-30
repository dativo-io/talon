# Authentication and key scopes

This reference describes Talon's current auth model across gateway traffic, tenant APIs, and admin/control-plane endpoints.

---

## Key types

| Key type | Source | Primary use | Header |
|---|---|---|---|
| **Tenant key** | `talon.config.yaml` -> `gateway.callers[].tenant_key` | Authenticate gateway callers and tenant-scoped API access | `Authorization: Bearer <tenant_key>` |
| **Admin key** | `TALON_ADMIN_KEY` env var | Authenticate admin/control-plane + dashboard/metrics | `X-Talon-Admin-Key: <key>` (preferred), `Authorization: Bearer <key>` (fallback) |

Notes:

- `tenant_key` is configured per caller and maps to a `tenant_id`.
- `TALON_ADMIN_KEY` is server-wide.

---

## Endpoint-to-key matrix

| Endpoint family | Accepted auth | Scope |
|---|---|---|
| `/v1/proxy/...` | Tenant key (bearer) | Gateway data plane (caller-specific policy) |
| Tenant-only write paths (`/v1/agents/run`, `/v1/chat/completions`, `/mcp`, `/mcp/proxy`) | Tenant key (bearer) | Tenant-scoped execution |
| Tenant-or-admin read paths (`/v1/evidence*`, `/v1/status`, `/v1/costs*`, `/v1/memory*`, `/v1/triggers*`, `/v1/plans/pending`, `/v1/plans/{id}`) | Tenant key (bearer) **or** admin key | Tenant visibility for tenant keys; cross-tenant admin visibility for admin key |
| Admin-only paths (`/v1/plans/{id}/approve`, `/v1/plans/{id}/reject`, `/v1/plans/{id}/modify`, `/v1/memory/{agent_id}/approve`, `/v1/secrets*`, `/v1/policies*`, `/v1/dashboard/*`, `/v1/copaw/*`) | Admin key | Control-plane actions |
| Operational control plane (`/v1/runs*`, `/v1/overrides*`, `/v1/tool-approvals*`) | Admin key | Run management, tenant overrides, tool approval gates |
| Gateway dashboard + metrics (`/gateway/dashboard`, `/api/v1/metrics`, `/api/v1/metrics/stream`) | Admin key | Operational dashboards and telemetry streams |

---

## Practical rules

- Use a **tenant key** for normal tenant workloads, including `POST /v1/agents/run`.
- Use **`TALON_ADMIN_KEY`** for admin/reviewer/operator actions and all dashboard/metrics endpoints.
- Prefer `X-Talon-Admin-Key` for admin calls; bearer fallback is accepted.

---

## Common confusion

### "Tenant key returns 401 on `/v1/evidence` or other tenant-or-admin paths"

When `talon serve` is run **without** `--gateway` (and without a `gateway:` block in config), no tenant keys are loaded. Tenant-or-admin read paths (`/v1/evidence`, `/v1/status`, etc.) then accept only the **admin key** (`X-Talon-Admin-Key` or Bearer). Use the admin key for evidence and status when running a minimal server without the gateway.

### "My caller key works on `/v1/proxy` but fails on admin endpoints"

Expected behavior. Caller/tenant keys are not admin keys.

Quick checks:

```bash
# Tenant-key path
curl -i -H "Authorization: Bearer <tenant_key>" http://localhost:8080/v1/status

# Admin-only path
curl -i -H "X-Talon-Admin-Key: <admin_key>" http://localhost:8080/v1/secrets
```

---

## Production guidance

- Issue distinct tenant keys per tenant/integration.
- Keep tenant keys and admin keys separate.
- Rotate tenant keys in `gateway.callers` entries (`tenant_key`) and rotate `TALON_ADMIN_KEY` through your secret manager/deploy workflow.

---

## Related docs

- [Configuration and environment](configuration.md)
- [Gateway dashboard](gateway-dashboard.md)
- [Operational control plane](operational-control-plane.md)
- [How to offer Talon to multiple customers (multi-tenant/MSP)](../guides/multi-tenant-msp.md)
- [Plan review example](../../examples/plan-review/README.md)
