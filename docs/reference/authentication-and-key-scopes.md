# Authentication and key scopes

This reference describes Talon's auth model across gateway traffic, tenant-scoped APIs, and admin/control-plane endpoints. There are exactly **two key families**: agent keys (workload identity) and the admin key (operator authority).

---

## Key types

| Key type | Source | Primary use | Header |
|---|---|---|---|
| **Agent key** | Talon vault, bound via `agent.key.secret_name` in `agent.talon.yaml` — mint with `talon secrets set <name> "$(openssl rand -hex 24)"` | Workload identity: authenticates `/v1/proxy` traffic **and** tenant-scoped API access, scoped to the agent's derived tenant | `Authorization: Bearer <agent_key>` (the gateway also accepts `x-api-key: <agent_key>`) |
| **Admin key** | `TALON_ADMIN_KEY` env var | Operator authority: cross-tenant dashboards, secrets, policy admin, approvals | `X-Talon-Admin-Key: <key>` (preferred), `Authorization: Bearer <key>` (fallback) |

Notes:

- One `agent.talon.yaml` = one AI use case = one traffic identity = one active vault-bound key. A presented agent key resolves to exactly one agent (constant-time registry match), and the tenant is always derived `key → agent → tenant_id` — the only tenant derivation.
- Breaking change (#266): the per-application `gateway.callers[].tenant_key` list was removed; agent keys replace it and legacy config keys fail validation.
- `TALON_ADMIN_KEY` is server-wide and never tenant-scoped.

---

## Endpoint-to-key matrix

| Endpoint family | Accepted auth | Scope |
|---|---|---|
| `/v1/proxy/...` | Agent key (bearer or `x-api-key`) | Gateway data plane — the key selects the agent and its effective policy; unknown or missing key gets `401 Invalid or missing agent key` |
| Native execution paths (`/v1/agents/run`, `/v1/chat/completions`, `/mcp`, `/mcp/proxy`, `/v1/graph/events`) | Native-only serve: agent key (bearer). Gateway serve: **admin key required — strictly** | Native execution runs the agent's own policy WITHOUT `gateway.organization_policy` / provider constraints, so when a gateway is served these routes need operator authority. Fail-closed: with a gateway and **no** `TALON_ADMIN_KEY` configured they return 401 for everyone (the dev-open rule never applies here) — agent traffic goes through `/v1/proxy` |
| Tenant-or-admin read paths (`/v1/evidence*`, `/v1/status`, `/v1/costs*`, `/v1/memory*`, `/v1/triggers*`, `/v1/plans/pending`, `/v1/plans/{id}`) | Agent key (bearer) **or** admin key | Agent keys see only their OWN agent's records (evidence, costs, memory); cross-tenant admin visibility for the admin key. `/v1/status` also reports coarse installation-level operational counters (event-stream totals, metrics summary, active-run count) — operator telemetry, not record contents, and not agent-private state |
| Admin-only paths (`/v1/plans/{id}/approve`, `/v1/plans/{id}/reject`, `/v1/plans/{id}/modify`, `/v1/memory/{agent_id}/approve`, `/v1/secrets*`, `/v1/policies*`, `/v1/dashboard/*`, `/v1/compliance/*`, `/v1/copaw/*`) | Admin key | Control-plane actions |
| Operational control plane (`/v1/runs*`, `/v1/overrides*`, `/v1/tool-approvals*`) | Admin key | Run management, tenant overrides, tool approval gates |
| Gateway dashboard + metrics (`/gateway/dashboard`, `/api/v1/metrics`, `/api/v1/metrics/stream`) | Admin key | Operational dashboards and telemetry streams |

---

## Practical rules

- Use the workload's **agent key** for normal tenant traffic: the same key authenticates `/v1/proxy` and the tenant-scoped read APIs, always scoped to the derived tenant. In a **native-only** serve it also authenticates `POST /v1/agents/run`.
- Use **`TALON_ADMIN_KEY`** for admin/reviewer/operator actions and all dashboard/metrics endpoints — and for the native execution routes whenever a gateway is served. Agent keys never grant admin authority, and the admin key never impersonates an agent.
- Prefer `X-Talon-Admin-Key` for admin calls; bearer fallback is accepted.
- Auth openness is governed only by the admin-key dev rule (running with no `TALON_ADMIN_KEY` configured is dev mode) — never by how many agents happen to be configured. **Exception (fail-closed):** the native execution routes in gateway mode never dev-open — no admin key means they deny.

### Quickstart exception and BYOK (dev-only)

`talon serve --proxy-quickstart` is the **only non-key identity path**: requests to the host-root facade run as an explicit synthetic quickstart identity injected in-process. It cannot be reached through normal key resolution, so it is impossible to confuse with production authentication. Upstream authentication in this mode:

- Host-root requests (`/v1/chat/completions`, `/v1/responses`) forward the presented bearer token to the upstream provider.
- If no bearer token is presented, Talon falls back to `OPENAI_API_KEY`.
- This does not replace agent-key/admin-key authentication for Talon control-plane and tenant APIs.

Evidence distinction:

- `upstream_key_fingerprint` identifies forwarded upstream key material safely.
- `secrets_accessed` remains reserved for Talon vault reads.

---

## Key rotation

- **Agent key:** write a new value to the same vault secret (`talon secrets set <secret_name> "$(openssl rand -hex 24)"`) and restart `talon serve` (a secret-only change is not digest-detected, so rotation still needs a restart or a file-touch even with periodic reload running). One active key per agent — there is never a window with two concurrently-active keys.
- **Admin key:** rotate `TALON_ADMIN_KEY` through your secret manager/deploy workflow.

---

## Common confusion

### "My agent key returns 401 on `/v1/evidence` or other tenant-or-admin paths"

When `talon serve` is run **without** `--gateway` (and without a `gateway:` block in config), no agent identity registry is built, so no agent keys are loaded. Tenant-or-admin read paths (`/v1/evidence`, `/v1/status`, etc.) then accept only the **admin key** (`X-Talon-Admin-Key` or Bearer). Use the admin key for evidence and status when running a minimal server without the gateway.

### "My agent key works on `/v1/proxy` but fails on admin endpoints"

Expected behavior. Agent keys are workload identities, not admin keys.

Quick checks:

```bash
# Agent-key path
curl -i -H "Authorization: Bearer <agent_key>" http://localhost:8080/v1/status

# Admin-only path
curl -i -H "X-Talon-Admin-Key: <admin_key>" http://localhost:8080/v1/secrets
```

---

## Production guidance

- One agent per AI use case, each with its own vault-bound key — never share one key between use cases (the registry rejects two agents resolving to the same key).
- Multi-tenant/MSP: one agent per customer tenant gives each customer a distinct key and a hard tenant isolation boundary.
- Keep agent keys and the admin key separate; never hand the admin key to a workload.

---

## Related docs

- [Configuration and environment](configuration.md)
- [Gateway dashboard](gateway-dashboard.md)
- [Operational control plane](operational-control-plane.md)
- [How to offer Talon to multiple customers (multi-tenant/MSP)](../guides/multi-tenant-msp.md)
- [Plan review example](../../examples/plan-review/README.md)
