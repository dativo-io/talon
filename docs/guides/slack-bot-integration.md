# Govern your Slack bot with Talon

Route your Slack bot's LLM calls through Talon to cap what the bot can spend, block PII before it leaves your infrastructure, and get a signed audit trail of every request — all with a single config change. The same evidence records support compliance reviews when you need them. Allow about 10 minutes.

## Prerequisites

- Talon installed and running with the gateway enabled
- A Slack bot that uses the OpenAI API (or another supported provider)
- Your real provider API key stored in Talon's vault

## Steps

### 1. Install and start Talon with the gateway

```bash
talon serve --gateway --gateway-config=talon.config.yaml
```

Ensure your config includes a `gateway` block and that the bot's agent file carries a key binding (#266).

### 2. Store the real API key in Talon

```bash
talon secrets set openai-api-key
```

### 3. Point the Slack bot at the gateway

Most Slack bots use an environment variable or config for the API base URL. Set it to Talon's gateway:

**OpenAI:**

```bash
export OPENAI_BASE_URL=http://talon:8080/v1/proxy/openai/v1
```

If the bot runs on the same host as Talon:

```bash
export OPENAI_BASE_URL=http://localhost:8080/v1/proxy/openai/v1
```

**Anthropic:**

```bash
export ANTHROPIC_BASE_URL=http://talon:8080/v1/proxy/anthropic
```

No code changes are required — the bot still uses the same SDK; only the base URL changes.

### 4. Mint the bot's agent key

The Slack bot is one AI use case — one `agent.talon.yaml` with a vault-bound
traffic key (#266). Mint it and configure the bot to send the VALUE as
`Authorization: Bearer <value>` (or `x-api-key` for Anthropic):

```bash
talon secrets set support-slack-bot-talon-key "$(openssl rand -hex 24)"
```

Talon resolves that key to the agent (and its derived tenant), then uses the
vault-stored provider key when calling the real provider.

### 5. Verify

Trigger the bot in Slack, then:

```bash
talon audit list
```

You should see gateway evidence for the bot's requests.

### 6. Add per-bot limits (optional)

In the bot's agent file, add overrides:

```yaml
# support-slack-bot/agent.talon.yaml
agent:
  name: support-slack-bot
  version: 1.0.0
  key:
    secret_name: "support-slack-bot-talon-key"
policies:
  cost_limits:
    daily: 10.00
  models:
    allowed: ["gpt-4o-mini"]
  allowed_providers: ["openai"]
  data_classification:
    input_scan: true
    block_on_pii: true
```

Restart Talon after editing the config.

## Summary

| Item        | Value                                                |
|------------|------------------------------------------------------|
| Gateway URL| `http://<talon>:8080/v1/proxy/openai/v1` (trailing `/v1` for correct paths; or anthropic/v1) |
| Auth       | The bot's agent key (agent.talon.yaml + vault binding, #266)  |
| Audit      | `talon audit list`                                   |

---

## You're done

You now have your Slack bot sending LLM calls through Talon. Talon is logging every request, scanning for PII, and applying per-bot limits you configured.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Cap cost or restrict models for this bot | [How to cap daily spend per team or application](cost-governance-by-agent.md) |
| Add Talon to another app (e.g. script or API) | [Add Talon to your existing app](add-talon-to-existing-app.md) |
| Export evidence for auditors | [How to export evidence for auditors](compliance-export-runbook.md) |
| Understand the request lifecycle | [What Talon does to your request](../explanation/what-talon-does-to-your-request.md) |
