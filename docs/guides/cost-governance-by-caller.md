# Cap AI spend for a Slack/support bot in 10 minutes

If your bot or app's AI spend is growing, Talon gives you a simple promise:

> You can cap AI spend before it runs away, and prove every allow/deny decision with signed evidence.

This guide shows the fastest path to that outcome for a support bot caller.

---

## What this guide covers

- Hard daily/monthly spend caps for one caller (`support-slack-bot`)
- Deny **before** any upstream provider call when the next request would exceed cap
- Signed evidence for both allowed and denied decisions
- Dashboard + CLI visibility for today/month, by caller/model/provider

---

## 1. Add a caller with hard EUR caps

Use a gateway config like this (from [examples/gateway/talon.config.gateway.yaml](../../examples/gateway/talon.config.gateway.yaml)):

```yaml
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "enforce"

  callers:
    - name: "support-slack-bot"
      tenant_key: "talon-gw-support-xyz"
      tenant_id: "default"
      policy_overrides:
        max_daily_cost: 10.00
        max_monthly_cost: 200.00
        pii_action: "warn"
        allowed_models: ["gpt-4o-mini"]
```

For a demo, temporarily lower `max_daily_cost` (for example `0.01`) so you can trigger a denial quickly.

---

## 2. Start Talon gateway

```bash
talon serve --gateway --gateway-config=path/to/talon.config.yaml
```

Ensure provider keys are in vault (for example `talon secrets set openai-api-key "sk-..."`).

---

## 3. Run the 6-step demo flow

1. Configure very low `max_daily_cost` for `support-slack-bot`
2. Send one request that is allowed
3. Send a second request that would exceed budget
4. Verify Talon denies **before** provider call
5. Verify signed evidence exists for the denial
6. Verify dashboard budget utilization reflects the event

Example calls:

```bash
# Allowed request (first call)
curl -sS "http://localhost:8080/v1/proxy/openai/v1/chat/completions" \
  -H "Authorization: Bearer talon-gw-support-xyz" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize ticket #123"}]}'

# Denied request (second call, over cap)
curl -sS "http://localhost:8080/v1/proxy/openai/v1/chat/completions" \
  -H "Authorization: Bearer talon-gw-support-xyz" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize ticket #124"}]}'
```

Expected deny characteristics:

- HTTP 403
- Machine-readable error code/reason contains `budget_exceeded`
- No upstream provider execution for denied call
- Signed evidence row recorded with denial reason and estimated pre-call cost

---

## 4. Verify with CLI and dashboard

CLI:

```bash
talon costs --tenant default
talon costs --caller support-slack-bot --json
talon costs --by-provider --tenant default
```

Export cost rows (joinable to signed evidence by `evidence_id`):

```bash
talon costs export --tenant default --caller support-slack-bot --format csv
talon audit export --tenant default --caller support-slack-bot --format signed-json
```

HTTP/API equivalents:

- `GET /v1/costs`
- `GET /v1/costs/budget`
- `POST /v1/costs/export`

Dashboard:

- `/gateway/dashboard` for real-time caller/model/provider operational view
- `/dashboard` for evidence-backed governance view and drill-down

---

## Cost visibility vs caps vs evidence attribution

- **Cost visibility**: today/month totals and breakdowns by tenant/caller/model/provider
- **Hard budget caps**: deny requests that would exceed daily/monthly cap before provider call
- **Evidence-backed attribution**: every allow/deny is signed and traceable by evidence ID, including budget-denied rows with zero provider cost and denial reason

This is the launch narrative connection to evidence integrity:

> Verified evidence proves both governance decisions and cost attribution.

---

## Native agents (no gateway)

If you run `talon run` directly, use `.talon.yaml`:

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
| Add more callers/models | [Configuration and environment](../reference/configuration.md) |
| Apply additional governance snippets | [Policy cookbook](policy-cookbook.md) |
