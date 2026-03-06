# Quick Start: 60-Second Demo (No API Key)

See Talon's controls in action without any API keys or configuration. The mock
provider handles all LLM calls, so evidence generation, PII scanning, and cost
tracking work exactly as they would with a real provider.

## Prerequisites

- Docker and Docker Compose
- That's it.

## Steps

### 1. Clone and Start (30 seconds)

```bash
git clone https://github.com/dativo-io/talon
cd talon/examples/docker-compose
docker compose up
```

Wait for both services to show as healthy (about 15-30 seconds).

### 2. Send a Request with PII (10 seconds)

In another terminal:

```bash
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {
        "role": "user",
        "content": "My email is jan@example.com and my IBAN is DE89370400440532013000. Help me reset my password."
      }
    ]
  }'
```

You'll get back a standard OpenAI-compatible JSON response. The mock provider
returned a canned answer, but Talon's full pipeline ran on the request.

### 3. List the evidence (10 seconds)

```bash
docker compose exec talon /usr/local/bin/talon audit list
```

Expected output:

```text
# Expected output:
✓ [req_a1b2c3d4] | 2026-03-15T10:23:45Z | demo/demo-user | gpt-4o-mini | €0.001 | 45ms
```

### 4. Inspect the evidence

```bash
docker compose exec talon /usr/local/bin/talon audit show req_a1b2c3d4
```

This shows the full evidence record:
- **Policy Decision:** Allowed (shadow mode)
- **Classification:** PII detected (email, IBAN), input tier 3
- **Execution:** Model used, cost, token counts, duration
- **Integrity:** Input/output hashes, HMAC signature status

### 5. Verify Signature Integrity

```bash
docker compose exec talon /usr/local/bin/talon audit verify req_a1b2c3d4
```

```
✓ Evidence req_a1b2c3d4: signature VALID
```

The HMAC-SHA256 signature proves no field has been modified since creation.

### 6. Open the dashboard

Visit [http://localhost:8080/dashboard](http://localhost:8080/dashboard) to see
evidence records, costs, and PII findings in the browser.

## What you just proved

The demo showed three things a PII-only proxy cannot:

1. **Tool calls are visible and blockable.** Talon sees MCP tool calls and LLM requests. A proxy that only inspects HTTP bodies for PII never sees which tools the agent is calling; Talon can block forbidden tools before they run.
2. **Policy runs before the LLM call.** Cost and policy are evaluated before the request is forwarded. You are not notified after you have already spent; the call is denied or allowed up front.
3. **Every record is tamper-proof.** The evidence store is HMAC-signed. You can verify with `talon audit verify`; no one can quietly edit the log.

## Now wire this to your app

Point your existing app at Talon by changing only the base URL and using a Talon caller key. Examples:

**Python (openai package):**

```python
import openai
client = openai.OpenAI(
    base_url="http://localhost:8080/v1/proxy/openai/v1",
    api_key="<your-caller-key-from-talon-config>",
)
# Then use client.chat.completions.create(...) as usual.
```

**Node.js (openai package):**

```javascript
const OpenAI = require("openai");
const client = new OpenAI({
  baseURL: "http://localhost:8080/v1/proxy/openai/v1",
  apiKey: "<your-caller-key-from-talon-config>",
});
// Then use client.chat.completions.create(...) as usual.
```

**curl:**

```bash
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-caller-key-from-talon-config>" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'
```

For a full step-by-step (vault key, gateway config, first real request), see [Add Talon to your existing app](../guides/add-talon-to-existing-app.md).

## You're done

You ran the 60-second demo. Talon intercepted a request, scanned for PII, logged cost, and wrote a signed evidence record. The mock provider stood in for OpenAI; with a real key and gateway config, the same flow applies to your app.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Put Talon in front of my real app | [Add Talon to your existing app](../guides/add-talon-to-existing-app.md) |
| Build a new agent with Talon from scratch | [Your first agent with Talon](first-governed-agent.md) |
| See how the request is processed step-by-step | [What Talon does to your request](../explanation/what-talon-does-to-your-request.md) |
| Run more demo requests | Use `bash demo-client/demo.sh` in the docker-compose example dir |

## What's Happening Under the Hood

When your curl request hits Talon, a 10-step pipeline runs:

1. **Route** — URL path determines provider (OpenAI)
2. **Identify** — Caller lookup (default in demo)
3. **Rate limit** — Token bucket check
4. **Extract** — Parse model name and message text from JSON
5. **PII scan** — Regex recognizers find email + IBAN
6. **Classify** — Data tier set to 3 (confidential, due to IBAN)
7. **Policy** — OPA evaluates: allowed in shadow mode
8. **Tool policy** — No tools in this request
9. **Forward** — Request sent to mock provider
10. **Evidence** — HMAC-signed record written to SQLite

Total overhead: <15ms. See
[What Talon Does to Your Request](../explanation/what-talon-does-to-your-request.md)
for the full technical breakdown.

## Run More Requests

Use the demo client to generate a richer evidence trail:

```bash
bash demo-client/demo.sh
```

This sends 5 requests with varied PII patterns and models.

## Clean up

```bash
docker compose down -v
```
