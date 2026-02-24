# How to govern OpenClaw with Talon

This guide shows how to route OpenClaw's LLM traffic through Talon so every request is audited and policy-enforced. Allow about 15 minutes.

For a Docker-based cloud setup, see the [OpenClaw + Talon primer](openclaw-talon-primer/docker-openclaw-talon-primer.md).

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

Talon will use these when forwarding requests from OpenClaw; callers never see the real key. The secret name must match the provider's `secret_name` in your gateway config (e.g. `openai-api-key`).

```bash
talon secrets set openai-api-key "sk-your-openai-key"
# Or use an env var to avoid putting the key in shell history:
# talon secrets set openai-api-key "$OPENAI_API_KEY"
```

### 3. Start Talon with the gateway enabled

```bash
talon serve --gateway --gateway-config=talon.config.yaml
```

Use a config file that includes a `gateway` block (see `examples/gateway/talon.config.gateway.yaml`).

### 4. Point OpenClaw at the gateway

Edit `~/.openclaw/openclaw.json` (or use `openclaw config set`):

- **OpenAI:** set the OpenAI provider's `baseUrl` to `http://localhost:8080/v1/proxy/openai`
- If Talon runs on another host, use `http://<talon-host>:8080/v1/proxy/openai`
- Set the OpenAI provider's **API key** to your **caller** gateway API key from the Talon gateway config (e.g. the `api_key` of the caller you defined under `gateway.callers`). Do not use your real OpenAI key here—Talon identifies the caller by this key and injects the real key when forwarding.

OpenClaw will send all chat completion requests to Talon; Talon will authenticate the caller, forward to OpenAI with the real key, and log evidence.

### 5. Verify

Send any message through OpenClaw, then check the audit trail:

```bash
talon audit list
```

You should see new evidence rows; the caller name (e.g. `openclaw-main`) appears as `agent_id`. To list only this caller's traffic: `talon audit list --agent openclaw-main`.

### 6. Add policy (optional)

Edit your gateway config and add or adjust `callers` and `policy_overrides`:

- `max_daily_cost` / `max_monthly_cost` — cost caps per caller
- `pii_action` — `block`, `redact`, `warn`, or `allow` when PII is detected
- `allowed_models` — restrict which models this caller can use

Restart `talon serve --gateway` after config changes.

## Summary

| Before                         | After                          |
|--------------------------------|--------------------------------|
| OpenClaw → OpenAI directly     | OpenClaw → Talon → OpenAI      |
| No central audit               | Every request in `talon audit` |
| No PII or cost controls        | Per-caller policy and limits   |
