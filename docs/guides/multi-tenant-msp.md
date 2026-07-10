# How to offer Talon to multiple customers (multi-tenant / MSP)

If you are an MSP or ISV and want to offer Talon (or a compliance layer) to multiple customers, use tenant isolation with **one agent per customer tenant**, each bound to its own vault-backed agent key. This guide gives the steps.

---

## 1. Tenant isolation

Talon scopes evidence and costs by **tenant**. Each customer is a tenant. The tenant is always derived `key → agent → tenant_id` — the agent file is the only place tenancy is declared — so that:

- Evidence and cost queries are scoped to the tenant.
- One tenant cannot see or access another tenant's data.

**One agent per customer:** each customer's AI use case gets its own `agent.talon.yaml` with a `tenant_id` and a vault-bound key:

```yaml
# agents/customer-acme-api.talon.yaml
agent:
  name: customer-acme-api
  tenant_id: acme
  key:
    secret_name: customer-acme-api-talon-key
```

```yaml
# agents/customer-globex-api.talon.yaml
agent:
  name: customer-globex-api
  tenant_id: globex
  key:
    secret_name: customer-globex-api-talon-key
```

Mint one key per agent (never share keys between customers — the registry rejects two agents resolving to the same key):

```bash
talon secrets set customer-acme-api-talon-key   "$(openssl rand -hex 24)"
talon secrets set customer-globex-api-talon-key "$(openssl rand -hex 24)"
```

When a request presents acme's agent key (`Authorization: Bearer <key>`), Talon resolves the agent and derives tenant `acme`. Tenant-scoped evidence and cost APIs, called with the same key, return only that tenant's data.

> #266 loads the single default `agent.talon.yaml` per gateway process; multi-file `agents_dir` discovery lands with #267. Until then, run one gateway process per customer agent file (or point each at its own file) for a multi-customer fleet.

---

## 2. Per-customer policy: one agent, one override

Each customer agent carries its own policy override on top of your shared organization baseline (`gateway.organization_policy` in `talon.config.yaml`) — per-customer cost caps, model lists, PII posture:

```yaml
# agents/customer-acme-app1.talon.yaml
agent:
  name: customer-acme-app1
  tenant_id: acme
  key:
    secret_name: customer-acme-app1-talon-key

policies:
  cost_limits:
    daily: 50.00
```

```yaml
# agents/customer-globex-bot.talon.yaml
agent:
  name: customer-globex-bot
  tenant_id: globex
  key:
    secret_name: customer-globex-bot-talon-key

policies:
  cost_limits:
    daily: 20.00
```

Customers use their own agent key; they never see other customers' keys or data. Costs and evidence are stored under their derived `tenant_id`. If one customer runs several applications, give each application its own agent file (one AI use case = one agent = one key) under the same `tenant_id`.

### Scope vault secrets per tenant (unchanged)

`talon secrets set` stores an **allow-all** ACL by default — any authenticated tenant's gateway traffic can trigger retrieval of that secret. In a multi-tenant deployment, scope every provider key to the tenants (and optionally agents) that may use it:

```bash
# Only acme's traffic may use this key (repeat --tenant for more; globs allowed)
talon secrets set acme-openai-key "sk-..." --tenant acme

# Tenant- and agent-scoped
talon secrets set acme-sales-key "sk-..." --tenant acme --agent "sales-*"
```

An unscoped `talon secrets set` prints a notice reminding you of the allow-all default. `talon secrets audit` shows per-tenant allow/deny decisions for every retrieval — including the gateway's resolution of each agent's own traffic key.

---

## 3. Operations: data directory and exports

- **Data directory:** `TALON_DATA_DIR` points to the state (vault, evidence DB, etc.). You can run one Talon instance with a shared DB and rely on `tenant_id` in every table, or (if you need hard isolation) run separate instances or separate DBs per tenant. The default single-DB design uses `tenant_id` for isolation.
- **Exports and verification:** To hand off evidence for one customer, export and verify scoped to that tenant. Use `talon audit export` (or the API) with the tenant context, or call the API with that customer's agent key so the export only includes their data. See [How to export evidence for auditors](compliance-export-runbook.md).

---

## 4. Summary

| Step | Action |
|------|--------|
| Map keys to tenants | One `agent.talon.yaml` per customer with `agent.tenant_id` + `agent.key.secret_name`; tenant derives from the key |
| Per-customer policy | Each agent file carries its one override (`policies.cost_limits`, `policies.models`, …) over the organization baseline |
| Exports | Use tenant-scoped export (API with the customer's agent key, or a tenant filter) for each customer |

For deeper context on architecture see [Architecture: MCP proxy](../ARCHITECTURE_MCP_PROXY.md).

---

## You're done

You now have tenant isolation with one keyed agent per customer. Talon derives the tenant from each presented key and scopes evidence and costs by tenant, so each customer sees only their own data.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Cap cost per tenant or agent | [How to cap daily spend per team or application](cost-governance-by-agent.md) |
| Export evidence for one tenant | [How to export evidence for auditors](compliance-export-runbook.md) |
| Wrap a vendor (Zendesk, Intercom) per tenant | [Vendor integration guide](../VENDOR_INTEGRATION_GUIDE.md) |
| Understand the gateway pipeline | [What Talon does to your request](../explanation/what-talon-does-to-your-request.md) |
