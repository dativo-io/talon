# Docker primer: OpenClaw + Talon (OpenAI only)

Straightforward setup: **only your OpenAI API key** is used. Talon runs as a gateway in front of OpenAI. OpenClaw sends every chat request to Talon; Talon checks policy, then forwards to OpenAI and records evidence.

## What this primer does

- **One key**: You set `OPENAI_API_KEY` in `.env`. Talon stores it and uses it when forwarding. OpenClaw never sees or stores the real key.
- **One provider**: OpenAI only. No Anthropic or Ollama in this primer.
- **Governance**: Every request from OpenClaw goes through Talon. Talon authenticates the caller, scans for PII, enforces cost and model limits, then forwards to OpenAI and writes an audit record.

## What OpenClaw must send (and what you configure)

OpenClaw talks to an “OpenAI-compatible” endpoint. To use Talon as that endpoint, you must configure OpenClaw so that **all** chat requests go to Talon, and Talon can identify the caller.

| What OpenClaw sends | What you set in OpenClaw |
|--------------------|---------------------------|
| **Base URL** (where requests go) | Set the **OpenAI provider base URL** to the Talon gateway URL. Example: `http://localhost:8080/v1/proxy/openai`. So every request goes to Talon, not to `api.openai.com`. |
| **API key** (in `Authorization: Bearer ...`) | Set the **OpenAI provider API key** to the **caller key**: `talon-gw-openclaw-abc123`. Do **not** put your real OpenAI key here. Talon uses this to identify the caller; it then adds the real OpenAI key when forwarding. |

Important:

- If the base URL is wrong, OpenClaw will call OpenAI directly and Talon will not see or govern the traffic.
- If the API key in OpenClaw is your real OpenAI key, Talon will not recognise the caller (401) or you will bypass governance. Use **only** the caller key `talon-gw-openclaw-abc123` in OpenClaw.

## Prerequisites

- Docker and Docker Compose
- Talon repo clone (image is built from repo root)
- Your **real** OpenAI API key (only for `.env`; never put it in OpenClaw)

## Quick start

### 1. Set your OpenAI key

```bash
cd docs/guides/openclaw-talon-primer
cp .env.example .env
# Edit .env and set:
#   OPENAI_API_KEY=sk-your-openai-key
```

Only `OPENAI_API_KEY` is required. Talon stores it in the vault; OpenClaw never sees it.

### 2. Build and run Talon

```bash
chmod +x entrypoint.sh
docker compose build
docker compose up -d
```

Talon listens on port 8080. The gateway URL for OpenAI is:

**`http://localhost:8080/v1/proxy/openai`**

(If Talon runs on another host, use `http://<host>:8080/v1/proxy/openai`.)

### 3. Configure OpenClaw

In OpenClaw (e.g. `~/.openclaw/openclaw.json` or OpenClaw settings):

1. **OpenAI provider — base URL**: `http://localhost:8080/v1/proxy/openai` (or your Talon host).
2. **OpenAI provider — API key**: `talon-gw-openclaw-abc123` (the caller key from this primer; **not** your real OpenAI key).

After this, every chat request from OpenClaw goes to Talon. Talon authenticates with the caller key, applies policy, then forwards to OpenAI with your real key and records evidence.

### 4. Verify (optional)

Send a test request through the gateway:

```bash
docker compose --profile verify up verify
```

List evidence for the caller:

```bash
docker exec talon-gateway talon audit list --agent openclaw-main --limit 5
```

## What Talon does with each request

1. **Authenticate** — Checks `Authorization: Bearer talon-gw-openclaw-abc123`. If missing or wrong, returns 401.
2. **Scan** — Extracts message text and scans for PII. Policy can block or redact (this primer uses `redact`).
3. **Policy** — Checks cost (daily/monthly caps), allowed models. Denies if over limit.
4. **Forward** — Sends the request to `https://api.openai.com` with your real API key. OpenClaw never sees that key.
5. **Evidence** — Writes a signed audit record (caller, model, cost, PII detected, etc.).

## Governance in Action

Beyond basic PII scanning and cost caps, Talon layers several runtime governance controls on every OpenClaw request. All of these are configured in `talon.config.gateway.yaml` and the agent `.talon.yaml` policy.

### Tool-aware PII redaction

Talon applies per-tool, per-argument PII policies. Each tool can declare which arguments contain customer data and what to do when PII is detected:

| Action | Behaviour |
|--------|-----------|
| `allow` | Pass through without scanning |
| `audit` | Log the PII finding to evidence but forward unchanged |
| `redact` | Replace PII with `[REDACTED]` before the tool executes |
| `block` | Reject the tool call entirely |

Example from the agent policy (see `tool_policies` in `agent.talon.yaml`):

```yaml
tool_policies:
  send_email:
    arguments:
      to: allow        # email address is the whole point
      body: redact     # scrub customer PII from body
    result: audit
  _default:
    argument_default: redact
    result: redact
```

### Destructive tool blocking

Talon detects destructive operations via configurable pattern matching in `capabilities.destructive_patterns`. The default patterns catch `delete`, `drop`, `remove`, `bulk_*`, `truncate`, `purge`, `wipe`, and `destroy`. Any tool call whose name matches a destructive pattern is denied by the OPA policy engine, even when the tool is in the `allowed_tools` list. This is a heuristic safety net for wildcard allowlists.

### Per-caller rate limiting

Rate limits are enforced per caller identity. The `per_caller_requests_per_min` field in the gateway config caps how many requests a single caller (e.g. `openclaw-main`) can make per minute. The default is 60 RPM. Global limits (`global_requests_per_min`) apply across all callers.

### Response PII redaction

Talon scans LLM responses **before** returning them to the caller. Configure via `response_pii_action` in `default_policy` or per-caller `policy_overrides`:

| Action | Behaviour |
|--------|-----------|
| `allow` | No scanning (default) |
| `warn` | Log PII detection to evidence, forward unchanged |
| `redact` | Replace PII in the response with `[REDACTED]` |
| `block` | Replace the entire response with a policy violation error |

Test it with a prompt that asks the model to generate a German IBAN:

```bash
curl -s http://localhost:8080/v1/proxy/openai/chat/completions \
  -H "Authorization: Bearer talon-gw-openclaw-abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role":"user","content":"Generate a sample German IBAN for testing."}]
  }' | jq '.choices[0].message.content'
# With response_pii_action: "redact", the IBAN in the response is replaced with [REDACTED]
```

### Circuit breaker

When an agent accumulates repeated policy denials (e.g. hitting cost caps or forbidden tools), the circuit breaker trips and suspends the agent automatically. Configured via `circuit_breaker_threshold` (default 5 denials) and `circuit_breaker_window` (default 60 s). States:

- **Closed** — normal operation, requests flow through.
- **Open** — agent suspended, all requests denied immediately.
- **Half-open** — after the window elapses, one probe request is allowed. If it succeeds, the circuit closes; if it fails, the circuit reopens.

Manual reset (programmatic — CLI wrapper planned for a future release):

```go
// In Go code: circuitBreaker.Reset(tenantID, agentID)
```

### Kill switch

Running agents can be cancelled programmatically by correlation ID via `ActiveRunTracker.Kill(correlationID)`, which cancels the agent's context and stops all in-flight LLM calls and tool executions.

```go
// In Go code:
activeRunTracker.Kill(correlationID)
```

> **Note:** CLI and HTTP API wrappers for the kill switch (`talon agent kill`, `DELETE /v1/agents/runs/<id>`) are planned for a future release. Currently, the kill switch is available via the Go API.

### Incident response

For a full runbook covering detection, triage, containment, and post-mortem, see [Incident Response Playbook](../incident-response-playbook.md).

## Primer layout

```
openclaw-talon-primer/
├── docker-openclaw-talon-primer.md  # This guide
├── docker-compose.yaml              # Talon service + optional verify
├── .env.example                     # OPENAI_API_KEY only (copy to .env)
├── entrypoint.sh                    # Seeds vault with OpenAI key, starts gateway
├── talon.config.gateway.yaml        # OpenAI only; one caller (openclaw-main)
└── agent.talon.yaml                 # Minimal policy for server boot
```

## Summary

| Step | Action |
|------|--------|
| 1 | Copy `.env.example` to `.env`, set `OPENAI_API_KEY` (your real OpenAI key). |
| 2 | `docker compose build && docker compose up -d`. |
| 3 | In OpenClaw: base URL = `http://<talon-host>:8080/v1/proxy/openai`, API key = `talon-gw-openclaw-abc123`. |
| 4 | Use OpenClaw as usual; all requests are governed and audited by Talon. |

Only the OpenAI key is used. Configure OpenClaw so it **sends** every request to Talon and uses the **caller** key; Talon then forwards to AI and keeps an audit trail. For more options (cost, PII, models), edit `talon.config.gateway.yaml` or see [How to govern OpenClaw with Talon](../openclaw-integration.md).
