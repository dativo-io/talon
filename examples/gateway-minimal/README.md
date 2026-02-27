# Gateway Minimal Example

The smallest working Talon gateway. Proxies OpenAI API calls with PII scanning
and an audit trail. Shadow mode: logs everything, blocks nothing.

## Setup

```bash
# 1. Build Talon
make build

# 2. Store your OpenAI key
export TALON_SECRETS_KEY=$(openssl rand -hex 32)
bin/talon secrets set openai-api-key "sk-your-key"

# 3. Start the gateway
bash examples/gateway-minimal/run.sh
```

## Use

Point any OpenAI-compatible app at Talon:

```bash
export OPENAI_BASE_URL=http://localhost:8080/v1/proxy/openai/v1
export OPENAI_API_KEY=talon-gw-myapp-001
```

Or test directly:

```bash
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer talon-gw-myapp-001" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello world"}]}'
```

Check the audit trail:

```bash
bin/talon audit list
```

## What's in the Config

```yaml
gateway:
  enabled: true
  mode: "shadow"          # Log only, don't block anything
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
  callers:
    - name: "my-app"
      api_key: "talon-gw-myapp-001"
  default_policy:
    log_prompts: true
```

That's it. No cost limits, no model restrictions, no PII blocking. Shadow mode
means everything is logged but nothing is blocked. Start here, then add
enforcement when you've reviewed the evidence.

## Next Steps

- Switch to `mode: "enforce"` to start blocking policy violations
- Add `policy_overrides` to callers for per-team cost limits and model restrictions
- See `examples/gateway/talon.config.gateway.yaml` for a full config example
