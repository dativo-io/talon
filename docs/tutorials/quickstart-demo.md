# Quick Start: 60-Second Demo (No API Key)

See Talon's governance in action without any API keys or configuration. The mock
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

### 3. Check the Audit Trail (10 seconds)

```bash
docker compose exec talon /usr/local/bin/talon audit list
```

Expected output:

```
✓ [req_a1b2c3d4] | 2026-03-15T10:23:45Z | demo/demo-user | gpt-4o-mini | €0.001 | 45ms
```

### 4. Inspect the Evidence

```bash
docker compose exec talon /usr/local/bin/talon audit show req_a1b2c3d4
```

This shows the full evidence record:
- **Policy Decision:** Allowed (shadow mode)
- **Classification:** PII detected (email, IBAN), input tier 3
- **Execution:** Model used, cost, token counts, duration
- **Audit Trail:** Input/output hashes, HMAC signature status

### 5. Verify Signature Integrity

```bash
docker compose exec talon /usr/local/bin/talon audit verify req_a1b2c3d4
```

```
✓ Evidence req_a1b2c3d4: signature VALID
```

The HMAC-SHA256 signature proves no field has been modified since creation.

### 6. Open the Dashboard

Visit [http://localhost:8080/dashboard](http://localhost:8080/dashboard) to see
evidence records, costs, and PII findings in the browser.

## What's Happening Under the Hood

When your curl request hits Talon, a 10-step pipeline runs:

1. **Route** — URL path determines provider (OpenAI)
2. **Identify** — Caller lookup (default in demo)
3. **Rate limit** — Token bucket check
4. **Extract** — Parse model name and message text from JSON
5. **PII scan** — Regex recognizers find email + IBAN
6. **Classify** — Data tier set to 3 (confidential, due to IBAN)
7. **Policy** — OPA evaluates: allowed in shadow mode
8. **Tool governance** — No tools in this request
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

## Clean Up

```bash
docker compose down -v
```

## Next Steps

| Goal | Next Tutorial |
|------|--------------|
| Govern a real app (Slack bot, script) | [Gateway Quick Start](quickstart-gateway.md) |
| Audit a vendor AI (Zendesk, Intercom) | [MCP Proxy Quick Start](quickstart-mcp-proxy.md) |
| Enterprise rollout (shadow → enforce) | [Enterprise Quick Start](quickstart-enterprise.md) |
| Understand the request lifecycle | [What Talon Does to Your Request](../explanation/what-talon-does-to-your-request.md) |
