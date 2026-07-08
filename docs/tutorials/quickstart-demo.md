# Quick Start: 60-Second Demo (No API Key)

See Talon's request path and signed evidence without any API keys or configuration. The mock provider handles the LLM call, so PII scanning, policy evaluation, cost tracking, and evidence generation run without spending money.

This page intentionally proves one small path. For tools, enforcement, sovereignty routing, session budgets, tamper detection, and RoPA, continue to [Reproduce the governed session manually](manual-governed-session.md).

## Prerequisites

- Docker and Docker Compose
- That's it.

## Steps

### 1. Clone and start (30 seconds)

```bash
git clone https://github.com/dativo-io/talon
cd talon/examples/docker-compose
docker compose up
```

Wait for both services to show as healthy (about 15-30 seconds).

### 2. Send a request with PII (10 seconds)

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

You'll get back a standard OpenAI-compatible JSON response. The mock provider returned a canned answer, but Talon's request pipeline still inspected and classified the request.

The demo configuration is deliberately in **shadow mode**. Talon records what policy observed without changing the request or response. This is the low-risk adoption path: observe real traffic first, then enable enforcement.

### 3. List the evidence (10 seconds)

```bash
docker compose exec talon /usr/local/bin/talon audit list
```

Expected shape:

```text
✓ [req_a1b2c3d4] | ... | demo/demo-user | gpt-4o-mini | ...
```

### 4. Inspect the evidence

```bash
docker compose exec talon /usr/local/bin/talon audit show req_a1b2c3d4
```

The record shows:

- **Policy decision:** allowed in shadow mode
- **Classification:** email + IBAN detected; input tier 2
- **Execution:** model, cost, token counts, duration
- **Integrity:** hashes and HMAC signature

### 5. Verify signature integrity

```bash
docker compose exec talon /usr/local/bin/talon audit verify req_a1b2c3d4
```

Expected result:

```text
✓ Evidence req_a1b2c3d4: signature VALID
```

The HMAC-SHA256 signature makes later modification detectable during verification.

### 6. Open the dashboard

Visit [http://localhost:8080/dashboard](http://localhost:8080/dashboard) to see evidence records, costs, and PII findings in the browser.

Use the Evidence tab to:

- check the per-row integrity state (`Not checked`, `Verified`, `Invalid`, `Unable to verify`),
- open the persistent signature block from **Detail**,
- verify that the governance decision and spend attribution are visible beside signature status.

## What you just proved

You executed and inspected this exact path:

1. **Talon accepted an OpenAI-compatible request without changing the client protocol.**
2. **PII was detected and classified before forwarding.** The email and IBAN produced a tier-2 finding.
3. **Shadow mode recorded the governance signal without breaking the application.** The request still reached the mock provider.
4. **The resulting evidence is tamper-evident and cryptographically verifiable.** `talon audit verify` checks the HMAC signature.

This page did **not** yet execute tool filtering, PII blocking, model denial, sovereignty routing, a session budget, or tamper failure. Reproduce those manually next:

**[Reproduce the governed session manually →](manual-governed-session.md)**

## Now wire this to your app

Point your existing app at Talon by changing only the base URL and using a Talon caller key.

**Python (`openai` package):**

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8080/v1/proxy/openai/v1",
    api_key="<your-caller-key-from-talon-config>",
)
# Then use client.chat.completions.create(...) as usual.
```

**Node.js (`openai` package):**

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

For a full step-by-step with vault key, gateway config, first real request, and evidence, see [Add Talon to your existing app](../guides/add-talon-to-existing-app.md).

## What's happening under the hood

When your curl request hits Talon, the gateway path runs:

1. **Route** — the URL path determines the provider.
2. **Identify** — Talon resolves the caller.
3. **Rate limit** — the token-bucket check runs.
4. **Extract** — Talon parses model and message text.
5. **PII scan** — recognizers find the email and IBAN.
6. **Classify** — the IBAN raises the input to confidential tier 2.
7. **Policy** — OPA evaluates the request; shadow mode records rather than blocks.
8. **Tool policy** — there are no tools in this request.
9. **Forward** — the request goes to the mock provider.
10. **Evidence** — Talon writes an HMAC-signed record to SQLite.

See [What Talon does to your request](../explanation/what-talon-does-to-your-request.md) for the full technical breakdown.

## You're done

You ran the fastest Talon proof loop: one request, one governance decision, one signed record, one verification.

| I want to… | Next doc |
|------------|----------|
| Reproduce the hero/deep controls manually | [Reproduce the governed session manually](manual-governed-session.md) |
| Attack the evidence integrity directly | [Evidence integrity: 5-minute proof](evidence-integrity-demo.md) |
| Put Talon in front of my real app | [Add Talon to your existing app](../guides/add-talon-to-existing-app.md) |
| Choose the right integration path | [Choose an integration path](../guides/choosing-integration-path.md) |
| Build a new agent with Talon | [Your first governed agent](first-governed-agent.md) |

## Clean up

```bash
docker compose down -v
```
