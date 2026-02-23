# Govern OpenClaw with Talon (15 minutes)

This guide shows how to route OpenClaw's LLM traffic through Talon so every request is audited and policy-enforced.

## Prerequisites

- Talon installed (`curl -sL install.talon.dev | sh` or from source)
- OpenClaw installed and configured
- Your real OpenAI (or other provider) API key

## Steps

### 1. Install Talon

```bash
curl -sL install.talon.dev | sh
# or: go install github.com/dativo-io/talon/cmd/talon@latest
```

### 2. Store real API keys in the vault

Talon will use these when forwarding requests from OpenClaw; callers never see the real key.

```bash
talon secrets set openai-api-key
# Enter your OpenAI API key when prompted
```

### 3. Start Talon with the gateway enabled

```bash
talon serve --gateway --gateway-config=talon.config.yaml
```

Use a config file that includes a `gateway` block (see `examples/gateway/talon.config.gateway.yaml`).

### 4. Point OpenClaw at the gateway

Edit `~/.openclaw/openclaw.json` and set the base URL to Talon's gateway:

- **OpenAI:** set `baseUrl` to `http://localhost:8080/v1/proxy/openai`
- If Talon runs on another host, use `http://<talon-host>:8080/v1/proxy/openai`

OpenClaw will send all chat completion requests to Talon; Talon will add auth, forward to OpenAI, and log evidence.

### 5. Verify

Send any message through OpenClaw, then check the audit trail:

```bash
talon audit list
```

You should see evidence records with `invocation_type: gateway` and your caller identity.

### 6. Add policy (optional)

Edit your gateway config and add or adjust `callers` and `policy_overrides`:

- `max_daily_cost_eur` / `max_monthly_cost_eur` — cost caps per caller
- `pii_action` — `block`, `redact`, or `warn` when PII is detected
- `allowed_models` — restrict which models this caller can use

Restart `talon serve --gateway` after config changes.

## Summary

| Before                         | After                          |
|--------------------------------|--------------------------------|
| OpenClaw → OpenAI directly     | OpenClaw → Talon → OpenAI      |
| No central audit               | Every request in `talon audit` |
| No PII or cost controls        | Per-caller policy and limits   |
