# How to run a first-line support agent with Talon

Run a first-line support agent that summarizes tickets and suggests replies, with PII and cost controls. You can implement it as a **native Talon agent** (webhook or cron trigger) or by pointing an **existing support bot** at the LLM API gateway.

---

## Option A: Native Talon agent

Use a Talon agent with a webhook trigger (e.g. from Zendesk, Freshdesk) or a cron job. Policy enforces cost limits and PII handling; every run is recorded as evidence.

### 1. Policy snippet

In `agent.talon.yaml`:

```yaml
agent:
  name: "support-agent"
  description: "First-line support: summarize tickets and suggest replies"

policies:
  cost_limits:
    daily: 20.00
    monthly: 400.00

# PII: block or redact before LLM sees it
# (exact key depends on your policy schema; often default_pii_action or capabilities)
```

Optional: enable plan review for high-risk suggestions (`compliance.human_oversight: "on_demand"`). See [Policy cookbook](policy-cookbook.md) and [Agent planning](../AGENT_PLANNING.md).

### 2. Trigger

**Webhook:** Expose `POST /v1/triggers/support-incoming` and point your ticketing system at it. In `.talon.yaml`:

```yaml
triggers:
  webhooks:
    - name: support-incoming
      source: zendesk
      prompt_template: "Summarize this ticket and suggest a reply: {{.payload.description}}"
      require_approval: false
```

**Cron:** Run on a schedule, e.g. poll a queue and run `talon run "Process next support ticket..."` from a script.

### 3. Serve and run

```bash
talon serve --port 8080
```

Evidence is stored per run. Use `talon audit list` or `GET /v1/evidence` filtered by `agent_id` or time to answer "what did the support agent see on date X?"

---

## Option B: Existing support bot → gateway

If you already have a Python/Node/etc. bot that calls the OpenAI (or other) API:

1. **Add a gateway caller** for the support bot (e.g. `support-bot`) with `policy_overrides.max_daily_cost` and `pii_action: "block"` or `"redact"`.
2. **Point the bot** at the Talon gateway base URL and use the caller API key instead of the real provider key. Same pattern as [How to add compliance to your Slack bot](slack-bot-integration.md).
3. Ticket content (often containing PII) is scanned by Talon; policy can block or redact before the request reaches the LLM.

Evidence is recorded per request; costs appear in `GET /v1/costs` for the tenant. Filter evidence by caller name to see support-bot usage.

---

## Evidence and “what did the agent see?”

- **Native:** `talon audit list`, `talon audit show <evidence-id>`, or API `GET /v1/evidence` with optional filters. Evidence includes correlation_id, tenant_id, agent_id, timestamp, policy decision, cost.
- **Gateway:** Same evidence store; gateway requests are recorded with caller identity. Use tenant and date (and caller if exposed in evidence) to scope exports for auditors. See [How to export evidence for auditors](compliance-export-runbook.md).
