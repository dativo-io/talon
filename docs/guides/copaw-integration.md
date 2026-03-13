# How to govern CoPaw with Talon

This guide shows how to route CoPaw's LLM traffic through Talon so every request is audited and policy-enforced. CoPaw is an open-source personal AI assistant (AgentScope/Alibaba DAMO) with multi-channel support (DingTalk, Feishu, Discord, etc.). Allow about 15 minutes.

For a Docker-based setup, see the [CoPaw + Talon primer](copaw-talon-primer/docker-copaw-talon-primer.md).

## Prerequisites

- Talon installed (`go install github.com/dativo-io/talon/cmd/talon@latest` or `curl -sL https://install.gettalon.dev | sh`)
- CoPaw installed (`pip install copaw` or from source)
- Your real LLM provider API key (OpenAI, DashScope, or other OpenAI-compatible provider)

## Steps

### 1. Install Talon and generate CoPaw config

```bash
# Generate a gateway-ready project pre-configured for CoPaw:
mkdir talon-copaw && cd talon-copaw
talon init --pack copaw --name copaw-gateway
# Or run `talon init` and choose CoPaw from the wizard.
```

This creates `agent.talon.yaml` (gateway policy) and `talon.config.yaml` (gateway config with a `copaw-main` caller and shadow mode by default).

### 2. Set the vault key and store the real provider key

```bash
export TALON_SECRETS_KEY=$(openssl rand -hex 32)
talon secrets set openai-api-key "sk-your-openai-key"
# Or for DashScope: talon secrets set dashscope-api-key "sk-your-dashscope-key"
talon serve --gateway
```

Use the **same** `TALON_SECRETS_KEY` when running `talon secrets set` and `talon serve`. The **caller tenant key** (e.g. `talon-gw-copaw-001`) is the token CoPaw sends to Talon; it is configured in `talon.config.yaml` and set in CoPaw's provider `api_key` field.

### 3. Confirm the gateway is running

```bash
curl -s -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer talon-gw-copaw-001" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hi"}],"max_tokens":5}'
```

You should get a JSON completion. If Talon runs on another host, use `http://<talon-host>:8080`.

### 4. Point CoPaw at the gateway

CoPaw stores provider settings in `~/.copaw.secret/providers.json` and can be configured via the **CoPaw Console** (port 8088) or the CoPaw CLI.

**Option A — CoPaw Console (Settings → Models):**

1. Open the CoPaw web UI (e.g. `http://localhost:8088`).
2. Go to **Settings → Models**.
3. Select the provider you use (e.g. OpenAI or a custom one).
4. Set **Base URL** to `http://localhost:8080/v1/proxy/openai/v1` (or `http://<talon-host>:8080/v1/proxy/openai/v1`).
5. Set **API Key** to `talon-gw-copaw-001` (the caller key from your Talon gateway config).
6. Save. CoPaw will use this endpoint for all LLM calls.

**Option B — Environment variables (when starting CoPaw):**

```bash
export OPENAI_BASE_URL=http://localhost:8080/v1/proxy/openai/v1
export OPENAI_API_KEY=talon-gw-copaw-001
copaw run
```

**Option C — CoPaw CLI / REST API:**

Use `copaw providers` or the REST API to set the provider's `base_url` and `api_key` to the Talon gateway URL and caller tenant key.

**Important:**

- The **API Key** in CoPaw is the Talon **caller key** (`talon-gw-copaw-001`), not your real OpenAI/DashScope key. Talon authenticates the caller by this key and injects the real key when forwarding.
- Base URL must end with `/v1` so that paths like `chat/completions` become `.../v1/chat/completions`.

### 5. Verify

Send a message through CoPaw (Console or any connected channel), then check the audit trail:

```bash
talon audit list
talon audit list --agent copaw-main
```

Evidence rows will show `agent_id: copaw-main`. The Talon dashboard (`/dashboard`) has a **CoPaw Agents** tab with stats and alerts.

### 6. Policy and monitoring

- **Shadow mode:** The generated config uses `gateway.mode: shadow` so violations are logged but not enforced. After 24h run `talon enforce report`, then switch to `enforce` in `talon.config.yaml` if desired.
- **Cost limits:** Adjust `gateway.callers[].policy_overrides.max_daily_cost` and `max_monthly_cost` for the CoPaw caller.
- **PII:** Default is `pii_action: redact`. Use `block` or `warn` as needed.

## Troubleshooting

| Symptom | Cause | Fix |
|--------|--------|-----|
| "Invalid or missing API key" | CoPaw is not sending the caller key, or key mismatch | Set CoPaw's API Key to exactly `talon-gw-copaw-001` (or the value in `talon.config.yaml`). |
| "Service configuration error" | Vault key mismatch | Use the same `TALON_SECRETS_KEY` for `talon secrets set` and `talon serve`. |
| 404 on chat/completions | Base URL missing `/v1` | Use `http://talon-host:8080/v1/proxy/openai/v1` (trailing `/v1`). |
| CoPaw uses DashScope | Provider base URL | Add a `dashscope` provider in Talon gateway config with `base_url: https://dashscope.aliyuncs.com/compatible-mode` (no trailing `/v1`; gateway appends the path) and point CoPaw at `http://talon-host:8080/v1/proxy/dashscope/v1`. |

## See also

- [Choosing an integration path](choosing-integration-path.md)
- [OpenClaw integration](openclaw-integration.md) (same gateway pattern)
- [CoPaw + Talon Docker primer](copaw-talon-primer/docker-copaw-talon-primer.md)

---

## You're done

You now have CoPaw sending all LLM traffic through Talon. Talon is logging every request, scanning for PII, and enforcing per-caller policy and cost limits.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Cap cost or restrict models for CoPaw | [How to cap daily spend per team or application](cost-governance-by-caller.md) |
| Run CoPaw + Talon in Docker | [CoPaw + Talon Docker primer](copaw-talon-primer/docker-copaw-talon-primer.md) |
| Export evidence for auditors | [How to export evidence for auditors](compliance-export-runbook.md) |
| Add another app through the gateway | [Add Talon to your existing app](add-talon-to-existing-app.md) |
