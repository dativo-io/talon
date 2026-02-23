# How to add compliance to your Slack bot

Route your Slack bot's LLM calls through Talon for audit, PII detection, and cost control with a single config change. Allow about 10 minutes.

## Prerequisites

- Talon installed and running with the gateway enabled
- A Slack bot that uses the OpenAI API (or another supported provider)
- Your real provider API key stored in Talon's vault

## Steps

### 1. Install and start Talon with the gateway

```bash
talon serve --gateway --gateway-config=talon.config.yaml
```

Ensure your config includes a `gateway` block and at least one `callers` entry (e.g. for your Slack bot).

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

### 4. Use a Talon-issued API key for the bot

In your gateway config, define a caller for the Slack bot and give it an `api_key` (e.g. `talon-gw-slack-xyz`). Configure the bot to send this key as `Authorization: Bearer <talon-gw-slack-xyz>` (or `x-api-key` for Anthropic). Talon will accept that key, resolve the caller, and use the vault-stored key when calling the real provider.

### 5. Verify

Trigger the bot in Slack, then:

```bash
talon audit list
```

You should see gateway evidence for the bot's requests.

### 6. Add per-bot limits (optional)

In the gateway config, under `callers`, add or edit the Slack bot caller with `policy_overrides`:

```yaml
- name: "support-slack-bot"
  api_key: "talon-gw-support-xyz789"
  tenant_id: "default"
  allowed_providers: ["openai"]
  policy_overrides:
    max_daily_cost: 10.00
    pii_action: "block"
    allowed_models: ["gpt-4o-mini"]
```

Restart Talon after editing the config.

## Summary

| Item        | Value                                                |
|------------|------------------------------------------------------|
| Gateway URL| `http://<talon>:8080/v1/proxy/openai` (or anthropic) |
| Auth       | Talon-issued API key in gateway `callers`            |
| Audit      | `talon audit list`                                   |
