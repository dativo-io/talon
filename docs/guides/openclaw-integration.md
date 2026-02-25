# How to govern OpenClaw with Talon

This guide shows how to route OpenClaw's LLM traffic through Talon so every request is audited and policy-enforced. Allow about 15 minutes.

For a Docker-based cloud setup, see the [OpenClaw + Talon primer](openclaw-talon-primer/docker-openclaw-talon-primer.md).

## Prerequisites

- Talon installed (`go install github.com/dativo-io/talon/cmd/talon@latest` or `curl -sL https://install.gettalon.dev | sh`)
- OpenClaw installed and configured
- Your real OpenAI (or other provider) API key

## Steps

### 1. Install Talon and generate OpenClaw config

```bash
go install github.com/dativo-io/talon/cmd/talon@latest
# or: curl -sL https://install.gettalon.dev | sh

# Generate a gateway-ready project pre-configured for OpenClaw:
mkdir talon-openclaw && cd talon-openclaw
talon init --pack openclaw --name openclaw-gateway
```

This creates `agent.talon.yaml` (agent policy with PII scanning, cost limits, circuit breaker) and `talon.config.yaml` (gateway config with OpenAI provider, pre-configured `openclaw-main` caller, shadow mode). You can also create these files manually — see the [Docker-based primer](openclaw-talon-primer/docker-openclaw-talon-primer.md) for a full example config.

### 2. Set the vault key and store the real OpenAI key

Talon encrypts secrets (including your OpenAI key) with `TALON_SECRETS_KEY`. You must use the **same** value when storing the secret and when starting the server, or the gateway will return "Service configuration error" or "cipher: message authentication failed".

**Recommended sequence (run in the same shell, or ensure the same env is active):**

```bash
# 1. Set the vault encryption key once; keep it for steps 2 and 3 (save it somewhere safe)
export TALON_SECRETS_KEY=$(openssl rand -hex 32)

# 2. Store your real OpenAI key in the vault (secret name must match gateway config's secret_name)
talon secrets set openai-api-key "sk-your-openai-key"
# Or: talon secrets set openai-api-key "$OPENAI_API_KEY"

# 3. Start Talon with the gateway — same shell so TALON_SECRETS_KEY is still set
talon serve --gateway
```

If you use a different shell or process to start Talon, set `TALON_SECRETS_KEY` there too (e.g. in `~/.bashrc` or the systemd unit). If the key at serve time differs from the key used when you ran `talon secrets set`, decryption fails and the gateway cannot forward requests.

**Two different keys (do not confuse):**

| Key | Purpose | Where it lives |
|-----|---------|----------------|
| **TALON_SECRETS_KEY** | Encrypts/decrypts the vault. Must be the **same** when running `talon secrets set` and `talon serve`. | Environment. Set before step 2 and 3 above. |
| **Caller api_key** (e.g. `talon-gw-openclaw-001`) | Token OpenClaw sends in `Authorization: Bearer ...`. Not used for encryption. | `talon.config.yaml` → `gateway.callers[].api_key`, and the same value in OpenClaw's `openclaw.json` as `models.providers.openai.apiKey`. |

### 3. Confirm the gateway is running

Leave the terminal where `talon serve --gateway` is running open (or run it in the background). The generated `talon.config.yaml` already includes the gateway block. Optional: test with curl (use the caller key from your config):

```bash
curl -s -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer talon-gw-openclaw-001" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hi"}],"max_tokens":5}'
```

You should get a JSON completion, not "Invalid or missing API key" (wrong caller key), "Service configuration error" (vault key mismatch), or 404 (use `baseUrl` with trailing `/v1` as above).

### 4. Point OpenClaw at the gateway

Edit `~/.openclaw/openclaw.json` and add a **top-level** `models` block (sibling of `agents`, `channels`, etc.) with `providers.openai` that overrides the default OpenAI endpoint. OpenClaw requires each provider to declare which models it serves using an array of objects with both `id` and `name`:

```json
{
  "models": {
    "providers": {
      "openai": {
        "baseUrl": "http://localhost:8080/v1/proxy/openai/v1",
        "apiKey": "talon-gw-openclaw-001",
        "api": "openai-responses",
        "models": [
          { "id": "gpt-5.1-codex", "name": "gpt-5.1-codex" },
          { "id": "gpt-4o", "name": "gpt-4o" },
          { "id": "gpt-4o-mini", "name": "gpt-4o-mini" }
        ]
      }
    }
  }
}
```

If Talon runs on another host, replace `localhost:8080` with `<talon-host>:8080`. The trailing **`/v1`** in `baseUrl` is required so that when the client appends `chat/completions`, the full path is `.../v1/chat/completions` (OpenAI expects that). Without it you get 404 from the upstream. Add or remove model entries to match the models you use (e.g. include any model ID you reference in `agents.defaults.model.primary` such as `openai/gpt-5.1-codex` — use the short name like `gpt-5.1-codex` in the `models` array).

After editing, restart the OpenClaw gateway so it picks up the new config:

```bash
openclaw gateway stop
openclaw gateway start
```

On SSH or headless servers, `openclaw gateway stop` may report "systemctl --user unavailable: Failed to connect to bus". In that case, stop the gateway process directly (e.g. `pkill openclaw-gateway`), then start it again however you normally run OpenClaw.

**Important:**
- The `apiKey` here is the Talon **caller key** from your gateway config (`talon.config.yaml` → `gateway.callers[].api_key`), **not** your real OpenAI key. Talon identifies the caller by this key and injects the real OpenAI key when forwarding.
- The `api: "openai-responses"` field is required for OpenAI-compatible proxy endpoints.
- Each model must be an object with both `id` and `name` (OpenClaw's schema requires both).
- Your real OpenAI key stays only in Talon's encrypted vault — OpenClaw never sees it.

OpenClaw will send all chat completion requests to Talon; Talon will authenticate the caller, forward to OpenAI with the real key, and log evidence.

### 5. Verify

Send any message through OpenClaw, then check the audit trail:

```bash
talon audit list
```

You should see new evidence rows; the caller name (e.g. `openclaw-main`) appears as `agent_id`. To list only this caller's traffic: `talon audit list --agent openclaw-main`.

**Troubleshooting**

- **`talon serve --gateway` fails with "agent is required" / "policies is required"** — Talon loads `agent.talon.yaml` from the current working directory. Run `talon serve --gateway` from the directory that contains a valid `agent.talon.yaml` (with top-level `agent:` and `policies:` keys). Easiest: use `talon init --pack openclaw` in a new directory so both `agent.talon.yaml` and gateway-enabled `talon.config.yaml` are generated.
- **OpenClaw reports "Invalid config … models.providers.openai.models"** — The `models` array must contain objects with both `id` and `name` (e.g. `{ "id": "gpt-4o-mini", "name": "gpt-4o-mini" }`). Plain strings or objects with only `id` or only `name` will fail validation.
- **"systemctl --user unavailable" when running `openclaw gateway stop`** — Your shell (e.g. SSH or `su`) may not have access to the user D-Bus session. Stop the gateway process directly: `pkill openclaw-gateway`, then start OpenClaw again as you normally do.
- **`gateway_secret_get_failed` / "cipher: message authentication failed"** — Talon can't decrypt the stored OpenAI key. Use the **same** `TALON_SECRETS_KEY` when running `talon secrets set` and `talon serve`. If you lost the key, set a new one and run `talon secrets set openai-api-key "sk-..."` again.
- **Gateway returns "Service configuration error"** — Same cause: vault decryption failed (wrong or missing `TALON_SECRETS_KEY` when `talon serve` started). Restart Talon in a shell where `TALON_SECRETS_KEY` is set to the same value you used for `talon secrets set`.
- **OpenClaw shows "404 status code (no body)"** — The client is calling the gateway with a path that becomes `.../chat/completions` instead of `.../v1/chat/completions`. Set `baseUrl` to **`http://localhost:8080/v1/proxy/openai/v1`** (trailing `/v1`) so that appended paths are correct. Restart OpenClaw after changing.
- **OpenClaw shows "404" plus binary/garbage text** — The upstream returned an error (e.g. 404) with a body that was compressed or non-JSON; the gateway now forces error responses to be read and forwarded as plain text so the client gets a readable message. Ensure you're on a recent Talon build. If the prompt contained PII (e.g. an email), the gateway may have redacted it before forwarding; the upstream can still return 404 for other reasons (e.g. model or path). Check `talon audit list` and Talon logs for that request.

**Collect diagnostics (paste output when asking for help)**

Run this and share the output (it does not print secret values):

```bash
echo "=== Talon ===" && talon version 2>/dev/null || echo "talon not in PATH"
echo "TALON_SECRETS_KEY set: $([ -n \"$TALON_SECRETS_KEY\" ] && echo yes || echo no)"
echo "TALON_SIGNING_KEY set: $([ -n \"$TALON_SIGNING_KEY\" ] && echo yes || echo no)"
echo "CWD: $(pwd)" && ls -la agent.talon.yaml talon.config.yaml 2>/dev/null || echo "agent.talon.yaml or talon.config.yaml missing in CWD"
echo "Health:" && curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health 2>/dev/null && echo " (Talon on :8080)" || echo " (no response on :8080)"
echo "Audit (last 5):" && talon audit list --limit 5 2>/dev/null || echo "audit list failed"
echo "=== OpenClaw ===" && (jq -r '.models.providers.openai | "baseUrl: \(.baseUrl), apiKey set: \(.apiKey != null), models: \(.models | length)"' ~/.openclaw/openclaw.json 2>/dev/null || echo "OpenClaw config not found or jq missing")
echo "=== Processes ===" && ps aux | grep -E 'talon|openclaw' | grep -v grep
```

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
