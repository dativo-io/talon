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

### 7. Monitor and respond

Once traffic is flowing, use these operational controls:

**Kill switch** — immediately halt a misbehaving caller without restarting Talon:

```go
// Go API: cancel the agent's context
activeRunTracker.Kill(correlationID)
```

> CLI and HTTP wrappers for kill switch are planned for a future release.

**Audit queries** — inspect recent activity:

```bash
# Show recent evidence for the caller
talon audit list --agent openclaw-main --limit 20

# Show full evidence detail for a specific event
talon audit show <evidence_id>

# Verify evidence integrity (HMAC signatures)
talon audit verify <evidence_id>

# Cost summary
talon costs --tenant default
```

**PII verification** — confirm redaction is working:

```bash
# List recent evidence and check for PII annotations in the output
talon audit list --agent openclaw-main --limit 10
```

For a complete incident response workflow, see the [Incident Response Playbook](incident-response-playbook.md).

---

## Failure mode → defense mapping

| Failure mode | Talon defense | Config / control |
|---|---|---|
| LLM returns PII in response | Response-path PII scanning | `pii_action: redact` or `block` in gateway config |
| Agent calls destructive tool | Destructive operation detection | `tool_access.rego` blocks `delete`, `drop`, `remove` patterns |
| Runaway cost accumulation | Per-caller cost caps | `max_daily_cost`, `max_monthly_cost` in caller config |
| Repeated policy denials (bug loop) | Circuit breaker with half-open recovery | Automatic after configurable denial threshold |
| Agent stuck / infinite loop | Kill switch | `ActiveRunTracker.Kill(correlationID)` (Go API) |
| Bulk data exfiltration attempt | Contextual volume detection in plan review | Plan review flags high-volume operations |
| Evidence tampering | HMAC-signed evidence chain | `talon audit verify` checks integrity |
| Memory poisoning | Governed memory with PII scan + category restrictions | `memory.governance` in `.talon.yaml` |

---

## Tool-aware governance

Talon applies a **three-category redaction model** that goes beyond blanket PII rules. Each tool call (or gateway request) is classified into one of four actions based on the tool and its arguments:

| Category | Behavior | Example |
|---|---|---|
| **allow** | PII passes through unmodified | Internal analytics tools querying anonymized data |
| **redact** | PII entities are replaced with placeholders before the tool sees them | Customer-facing tools receiving names, emails, IBANs |
| **audit** | PII passes through but every occurrence is logged as evidence | Privileged support tools where redaction would break functionality |
| **block** | Request is rejected entirely when PII is detected | Export or bulk-delete tools that should never receive personal data |

Configure per-tool policies in the agent's `.talon.yaml` (not the gateway config):

```yaml
tool_policies:
  search_tickets:
    argument_default: redact
    result: redact
  export_report:
    argument_default: block
    result: block
  admin_lookup:
    argument_default: audit
    result: audit
  _default:
    argument_default: redact
    result: redact
```

This model ensures that governance is proportional — low-risk tools stay fast while high-risk tools get strict controls.

## Summary

| Before                         | After                          |
|--------------------------------|--------------------------------|
| OpenClaw → OpenAI directly     | OpenClaw → Talon → OpenAI      |
| No central audit               | Every request in `talon audit` |
| No PII or cost controls        | Per-caller policy and limits   |
