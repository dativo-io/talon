# How to offer Talon to multiple customers (multi-tenant / MSP)

If you are an MSP or ISV and want to offer Talon (or a compliance layer) to multiple customers, use tenant isolation, per-tenant API keys, and (optionally) gateway callers per customer. This guide gives the steps; for architecture and adoption narrative see [Adoption scenarios](../ADOPTION_SCENARIOS.md).

---

## 1. Tenant isolation

Talon scopes evidence and costs by **tenant**. Each customer is a tenant. You map API keys to tenants so that:

- Evidence and cost queries are scoped to the tenant.
- One tenant cannot see or access another tenant’s data.

**API keys:** Use the format `key:tenant_id` when setting `TALON_API_KEYS` (or your config equivalent). Example:

```bash
# key_acme -> tenant acme, key_globex -> tenant globex
export TALON_API_KEYS="key_acme:acme,key_globex:globex"
```

When a request is made with `X-Talon-Key: key_acme`, Talon treats the tenant as `acme`. All evidence and cost APIs return only that tenant’s data.

---

## 2. Gateway: one caller per customer (or per app per customer)

When using the LLM API gateway, define a caller per customer (or per application per customer). Each caller has its own `tenant_id` and can have per-caller limits.

```yaml
gateway:
  callers:
    - name: "customer-acme-app1"
      api_key: "talon-gw-acme-abc"
      tenant_id: "acme"
      policy_overrides:
        max_daily_cost: 50.00

    - name: "customer-globex-bot"
      api_key: "talon-gw-globex-xyz"
      tenant_id: "globex"
      policy_overrides:
        max_daily_cost: 20.00
```

Customers use their own caller API key; they never see other customers’ keys or data. Costs and evidence are stored under their `tenant_id`.

---

## 3. Operations: data directory and exports

- **Data directory:** `TALON_DATA_DIR` points to the state (vault, evidence DB, etc.). You can run one Talon instance with a shared DB and rely on `tenant_id` in every table, or (if you need hard isolation) run separate instances or separate DBs per tenant. The default single-DB design uses `tenant_id` for isolation.
- **Exports and verification:** To hand off evidence for one customer, export and verify scoped to that tenant. Use `talon audit export` (or the API) with the tenant context, or call the API with that tenant’s key so the export only includes their data. See [How to export evidence for auditors](compliance-export-runbook.md).

---

## 4. Summary

| Step | Action |
|------|--------|
| Map keys to tenants | `TALON_API_KEYS="key1:tenant1,key2:tenant2"` |
| Gateway callers | One or more callers per tenant with `tenant_id` and optional `policy_overrides` |
| Exports | Use tenant-scoped export (API with tenant key or tenant filter) for each customer |

For deeper context on adoption and architecture see [Adoption scenarios](../ADOPTION_SCENARIOS.md) and [Architecture: MCP proxy](../ARCHITECTURE_MCP_PROXY.md).
