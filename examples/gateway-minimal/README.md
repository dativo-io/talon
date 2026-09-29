# Gateway Minimal Example

The smallest working Talon gateway. Proxies OpenAI API calls with PII scanning
and an audit trail. It declares no blocking rule, so nothing is denied — but
the policy that *is* declared is enforced: there is no shadow posture (#442).

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
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
  organization_policy:
    log_prompts: true
```

Identity lives in `agent.talon.yaml` (#266) — the scaffold already binds
`my-app-talon-key`; mint it once:

```bash
talon secrets set my-app-talon-key "$(openssl rand -hex 24)"
```

Your app presents that value as `Authorization: Bearer <value>`.

That's it. No cost limits, no model restrictions, no PII blocking: the
organization default `pii_action: warn` records findings in signed evidence
and lets traffic flow. Whatever you add next is enforced immediately, so check
the files first — `talon doctor` validates `talon.config.yaml`, `talon
validate` the agent file — then tighten one rule at a time after reviewing
the evidence.

## Next Steps

- Set `organization_policy.defaults.pii_action: "redact"` (traffic flows, PII replaced before the provider) or `"block"` (request denied, provider never reached)
- Add overrides in the agent file (`policies.cost_limits`, `policies.models`) for per-use-case cost limits and model restrictions
- See `examples/gateway/talon.config.gateway.yaml` for a full config example
