# Authentication and key scopes

This reference clarifies how Talon authenticates requests across API surfaces. It is intentionally explicit because users often assume one API key works for all endpoints.

---

## Why this matters

Talon has two main HTTP surfaces:

- **Gateway data plane** (`/v1/proxy/...`) for runtime LLM traffic.
- **Control plane** (`/v1/agents/...`, `/v1/plans/...`, `/v1/evidence/...`, `/v1/status`, etc.) for operations, governance, and review workflows.

These surfaces are related but use different key sources by design.

---

## Key types

| Key type | Config source | Primary use | Typical endpoints |
|---|---|---|---|
| **Gateway caller key** | `talon.config.yaml` -> `gateway.callers[].api_key` | Authenticate application/agent traffic routed through Talon gateway | `/v1/proxy/{provider}/...` |
| **Talon API key** | `TALON_API_KEYS` env var | Authenticate Talon control-plane API calls | `/v1/agents/run`, `/v1/plans/pending`, `/v1/plans/{id}/approve`, `/v1/evidence`, `/v1/status` |
| **Dashboard token** | `talon.config.yaml` -> `gateway.dashboard_token` | Protect gateway dashboard telemetry pages/API | `/gateway/dashboard`, `/api/v1/metrics`, `/api/v1/metrics/stream` |

---

## Endpoint-to-key matrix

| Endpoint family | Accepted auth | Notes |
|---|---|---|
| `/v1/proxy/...` | Gateway caller key (`Authorization: Bearer <gateway-caller-key>`) | Enforces caller-specific gateway policy overrides. |
| `/v1/*` (control plane) | Talon API key (`X-Talon-Key` or `Authorization: Bearer`) | Tenant context is derived from `TALON_API_KEYS` mapping. |
| `/gateway/dashboard` | Dashboard token OR Talon API key | Uses dashboard-or-API-key middleware when gateway dashboard is enabled. |
| `/api/v1/metrics*` | Dashboard token OR Talon API key | Same as above. |

Practical rule:

- If you call **proxy endpoints**, use a **gateway caller key**.
- If you call **core Talon endpoints** (plans/evidence/run/status), use a **Talon API key**.

---

## `TALON_API_KEYS` format

`TALON_API_KEYS` is a comma-separated list. Each entry is one of:

- `key` (implicitly tenant `default`), or
- `key:tenant_id`

Example:

```bash
export TALON_API_KEYS="admin-key:admin,tenant-a-key:acme,tenant-b-key:globex"
```

This supports key rotation and multiple clients per tenant.

---

## Common confusion and how to resolve it

### "My gateway key works on `/v1/proxy` but fails on `/v1/plans/pending`"

Expected behavior unless that same key is also present in `TALON_API_KEYS`.

Quick check:

```bash
curl -i -H "Authorization: Bearer <key>" http://localhost:8080/v1/status
```

- `200` -> key is valid as Talon API key.
- `401` -> key is not a Talon API key (likely gateway-only).

---

## Recommended production pattern

- Keep **gateway caller keys** for application traffic only.
- Keep **Talon API keys** for operator/control-plane actions.
- Use distinct keys per tenant and per integration where possible.
- Rotate keys by running old+new concurrently in `TALON_API_KEYS`, then removing old keys.

---

## Naming guidance and future ergonomics

Today, `TALON_API_KEYS` is the canonical control-plane key variable. A single-key alias (for example `TALON_API_KEY`) can be added later for convenience, but plural should remain canonical for safe rotation and phased rollout.

---

## Related docs

- [Configuration and environment](configuration.md)
- [Gateway dashboard](gateway-dashboard.md)
- [How to offer Talon to multiple customers (multi-tenant/MSP)](../guides/multi-tenant-msp.md)
- [Plan review example](../../examples/plan-review/README.md)
