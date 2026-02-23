# How to cap daily spend per team or application

Use the LLM API gateway to cap daily (and optionally monthly) spend per caller (team or application). Each caller is identified by API key or source IP and can have its own limits. You can then monitor usage via the costs API or CLI.

---

## 1. Define callers with cost overrides

In your gateway config (e.g. `talon.config.yaml` with a `gateway` block), define one or more callers and set `policy_overrides.max_daily_cost` and optionally `max_monthly_cost`.

Example (excerpt from [examples/gateway/talon.config.gateway.yaml](../../examples/gateway/talon.config.gateway.yaml)):

```yaml
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
    ollama:
      enabled: true
      base_url: "http://localhost:11434"

  callers:
    - name: "slack-bot"
      api_key: "talon-gw-slack-abc"
      tenant_id: "default"
      policy_overrides:
        max_daily_cost: 15.00
        max_monthly_cost: 300.00

    - name: "desktop-engineering"
      api_key: "talon-gw-eng-xyz"
      tenant_id: "default"
      policy_overrides:
        max_daily_cost: 25.00

    - name: "ci-openai"
      api_key: "talon-gw-ci-123"
      tenant_id: "default"
      policy_overrides:
        max_daily_cost: 5.00
```

When a caller exceeds their daily or monthly limit, the gateway returns a policy denial and records evidence. Costs are still attributed to the caller for visibility.

---

## 2. Start the gateway

```bash
talon serve --gateway --gateway-config=path/to/your/talon.config.yaml
```

Ensure the real provider API keys are in the vault (e.g. `talon secrets set openai-api-key "sk-..."`). Callers only use their own gateway API keys; they never see the provider key.

---

## 3. Monitor costs

**Via API (per tenant):**

- `GET /v1/costs` with `X-Talon-Key: <talon-api-key>` returns `daily` and `monthly` totals for the authenticated tenant. Gateway traffic is recorded under that tenant, so the totals include all callers in the tenant.
- `GET /v1/costs/budget` returns usage and optional limits (when set in policy).

**Via CLI:**

```bash
talon audit list --limit 50
```

Evidence records include cost per request. For per-caller breakdown you would filter or aggregate by the caller name stored in evidence (e.g. `agent_id` or request metadata, depending on how gateway evidence is tagged).

---

## Native agents (no gateway)

For agents run via `talon run` or `POST /v1/chat/completions`, cost limits are set in `.talon.yaml`:

```yaml
policies:
  cost_limits:
    per_request: 0.50
    daily: 20.00
    monthly: 400.00
```

See [Policy cookbook](policy-cookbook.md) for more snippets.
