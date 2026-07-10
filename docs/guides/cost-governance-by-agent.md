# Cap AI spend for a Slack/support bot in 10 minutes

If your bot or app's AI spend is growing, Talon gives you a simple promise:

> You can cap AI spend before it runs away, and prove every allow/deny decision with signed evidence.

This guide shows the fastest path to that outcome for a support-bot agent.

---

## What this guide covers

- Hard daily/monthly spend caps for one agent (`support-slack-bot`)
- Deny **before** any upstream provider call when the next request would exceed cap
- Signed evidence for both allowed and denied decisions
- Dashboard + CLI visibility for today/month, by agent/model/provider

---

## 1. Define the agent with hard EUR caps

The bot is one AI use case, so it gets one `agent.talon.yaml` — its Talon traffic identity and its one policy override over the organization baseline:

```yaml
agent:
  name: support-slack-bot
  tenant_id: default            # optional; omitted = "default"
  key:
    secret_name: support-slack-bot-talon-key   # vault reference — never a raw key

policies:
  cost_limits:
    daily: 10.00                # replaces the baseline daily cap
    monthly: 200.00             # replaces the baseline monthly cap
  models:
    allowed: ["gpt-4o-mini"]    # gateway model allowlist for this agent
  data_classification:
    input_scan: true            # scan-only → PII action "warn" for this agent
```

Mint the agent key the bot will present to the gateway (the vault stores it encrypted; keep the value in your secret manager):

```bash
AGENT_KEY="$(openssl rand -hex 24)"
talon secrets set support-slack-bot-talon-key "$AGENT_KEY"
```

The gateway side of `talon.config.yaml` holds only providers and the organization baseline (see [examples/gateway/talon.config.gateway.yaml](../../examples/gateway/talon.config.gateway.yaml)):

```yaml
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "enforce"

  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"

  organization_policy:
    default_pii_action: "warn"
    max_daily_cost: 100.00      # organization baseline; the agent override above wins for this agent
    max_monthly_cost: 2000.00
```

For a demo, temporarily lower the agent's `cost_limits.daily` (for example `0.01`) so you can trigger a denial quickly.

**Effective caps = one calculation path.** The caps enforcement applies are resolved by the same function that feeds `talon costs` and the dashboard budget endpoint: organization baseline → the agent's one override (an agent cap replaces the baseline when > 0). What you see reported is exactly what is enforced.

---

## 2. Start Talon gateway

```bash
talon serve --gateway --gateway-config=path/to/talon.config.yaml
```

Ensure provider keys are in vault (for example `talon secrets set openai-api-key "sk-..."`).

---

## 3. Run the 6-step demo flow

1. Configure a very low `cost_limits.daily` for `support-slack-bot`
2. Send one request that is allowed
3. Send a second request that would exceed budget
4. Verify Talon denies **before** the provider call
5. Verify signed evidence exists for the denial
6. Verify dashboard budget utilization reflects the event

Example calls — the bot authenticates with its **agent key** (`$AGENT_KEY` from step 1):

```bash
# Allowed request (first call)
curl -sS "http://localhost:8080/v1/proxy/openai/v1/chat/completions" \
  -H "Authorization: Bearer $AGENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize ticket #123"}]}'

# Denied request (second call, over cap)
curl -sS "http://localhost:8080/v1/proxy/openai/v1/chat/completions" \
  -H "Authorization: Bearer $AGENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize ticket #124"}]}'
```

Expected deny characteristics:

- HTTP 403
- Machine-readable error code/reason contains `budget_exceeded`
- No upstream provider execution for the denied call
- Signed evidence row recorded with denial reason and estimated pre-call cost

---

## 4. Verify with CLI and dashboard

CLI:

```bash
talon costs --tenant default
talon costs --agent support-slack-bot --json
talon costs --by-provider --tenant default
```

`talon costs --agent` reports the agent's **effective** daily/monthly caps — resolved through the same computation enforcement uses, so the numbers can never drift from runtime behavior.

Export cost rows (joinable to signed evidence by `evidence_id`):

```bash
talon costs export --tenant default --agent support-slack-bot --format csv
talon audit export --tenant default --agent support-slack-bot --format signed-json
```

HTTP/API equivalents:

- `GET /v1/costs`
- `GET /v1/costs/budget?agent_id=support-slack-bot`
- `POST /v1/costs/export`

Dashboard:

- `/gateway/dashboard` for the real-time agent/model/provider operational view
- `/dashboard` for the evidence-backed governance view and drill-down

---

## Cost visibility vs caps vs evidence attribution

- **Cost visibility**: today/month totals and breakdowns by tenant/agent/model/provider
- **Hard budget caps**: deny requests that would exceed the effective daily/monthly cap before the provider call
- **Evidence-backed attribution**: every allow/deny is signed and traceable by evidence ID, including budget-denied rows with zero provider cost and denial reason

This is the launch narrative connection to evidence integrity:

> Verified evidence proves both governance decisions and cost attribution.

---

## Native agents (no gateway)

The same `agent.talon.yaml` governs `talon run` — same file, same caps, same derived tenant:

```yaml
policies:
  cost_limits:
    per_request: 0.50
    daily: 20.00
    monthly: 400.00
```

---

## Next steps

| I want to… | Doc |
|------------|-----|
| Verify signed exports and tamper checks | [How to export evidence for auditors](compliance-export-runbook.md) |
| Understand dashboard metrics schema | [Gateway dashboard](../reference/gateway-dashboard.md) |
| Add more agents/models | [Configuration and environment](../reference/configuration.md) |
| Apply additional governance snippets | [Policy cookbook](policy-cookbook.md) |
