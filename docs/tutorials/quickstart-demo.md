# Try Talon without an API key

Choose the published-image quickstart for policy decisions and signed evidence without a provider API key. For a synthetic model response, redaction and the Operations Console, continue with the optional Compose walkthrough.

This page intentionally proves one small path. For tools, enforcement, sovereignty routing, session budgets, tamper detection, and RoPA, continue to [Reproduce the governed session manually](manual-governed-session.md).

## First: run the published image

Requires Docker, curl and Bash. This example runs v1.17.0; keep the script and image on the same release.

```bash
curl -fsSL https://raw.githubusercontent.com/dativo-io/talon/v1.17.0/scripts/quickstart.sh -o talon-quickstart.sh
# Inspect the script before running it.
TALON_VERSION=1.17.0 bash talon-quickstart.sh
```

Expected: PII blocked (400), model denied (403), unknown key refused (401), two verified evidence records and final PASS. No provider exists in this fixture. For redaction, a mock response and the Operations Console, use the optional walkthrough below. Use synthetic inputs only.

## Prerequisites

- Docker Compose v2.24+, Git and curl; jq for the optional API inspection.
- Local evaluation only: the fixture uses a public demo key and development-open administrative endpoints.

## Steps

### 1. Clone and start

```bash
git clone --depth 1 --branch v1.17.0 https://github.com/dativo-io/talon
cd talon/examples/docker-compose
export TALON_IMAGE=ghcr.io/dativo-io/talon:1.17.0
docker compose -f docker-compose.yml -f docker-compose.published.yml up
```

Wait for all three services to become ready. Startup depends on the machine and image cache.

### 2. Send a request with PII

In another terminal:

```bash
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer talon-demo-key" \
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

You'll get back a standard OpenAI-compatible JSON response. The mock provider returned a canned answer, but Talon's request pipeline inspected, classified, and **redacted** the request before forwarding it.

The demo configuration sets `organization_policy.defaults.pii_action: "redact"`. Active policy is always enforced (#442) — there is no observe-only posture — so the rule you declare is what happens: the mock provider receives `[EMAIL]` and `[IBAN]` in place of the detected values, and the request still succeeds. If you change that one line to `"block"` and restart the demo service so it loads the policy, the same request is denied before the provider is reached.

### 3. List the evidence

```bash
TALON_IMAGE=ghcr.io/dativo-io/talon:1.17.0 docker compose -f docker-compose.yml -f docker-compose.published.yml exec talon /usr/local/bin/talon audit list
```

Expected shape:

```text
✓ [YOUR_EVIDENCE_ID] | ... | demo/demo-agent | gpt-4o-mini | ...
```

### 4. Inspect the evidence

```bash
TALON_IMAGE=ghcr.io/dativo-io/talon:1.17.0 docker compose -f docker-compose.yml -f docker-compose.published.yml exec talon /usr/local/bin/talon audit show YOUR_EVIDENCE_ID
```

Replace YOUR_EVIDENCE_ID with the actual ID from audit list. The record shows:

- **Policy decision:** allowed, with input PII redacted (`pii_redacted: true`)
- **Classification:** email + IBAN detected; input tier 2
- **Execution:** model, cost, token counts, duration
- **Integrity:** hashes and HMAC signature

### 5. Verify signature integrity

```bash
TALON_IMAGE=ghcr.io/dativo-io/talon:1.17.0 docker compose -f docker-compose.yml -f docker-compose.published.yml exec talon /usr/local/bin/talon audit verify YOUR_EVIDENCE_ID
```

Expected result:

```text
✓ Evidence YOUR_EVIDENCE_ID: signature VALID
```

The HMAC-SHA256 signature makes later modification detectable during verification.

### 6. Read the same facts over the API

With `talon serve` running, the evidence records, costs and PII findings are available as JSON (admin key in the header):

```bash
curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" 'http://localhost:8080/v1/evidence?limit=5' | jq '.entries[] | {id, allowed: .policy_decision.allowed, cost: .execution.cost}'
curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" http://localhost:8080/v1/costs | jq .
```

For this local fixture the admin key is intentionally unset. The read-only [Operations Console](../guides/operations-console.md) is available at http://127.0.0.1:8787/. Obtain the one-time pairing code with `TALON_IMAGE=ghcr.io/dativo-io/talon:1.17.0 docker compose -f docker-compose.yml -f docker-compose.published.yml logs talon-ui`. Never expose this fixture to another host.

## What you just proved

In the optional Compose walkthrough, you executed and inspected this exact path:

1. **Talon accepted an OpenAI-compatible request without changing the client protocol.**
2. **PII was detected and classified before forwarding.** The email and IBAN produced a tier-2 finding.
3. **The declared rule was enforced without breaking the application.** The provider received the redacted text, never the raw email or IBAN, and the signed record says so (`pii_redacted: true`).
4. **The resulting evidence is tamper-evident and cryptographically verifiable.** `talon audit verify` checks the HMAC signature.

The Compose walkthrough does not exercise tool filtering, sovereignty routing, session budgets or tamper failure. The published-image quickstart above separately proves PII blocking and model denial; it does not test redaction or a live model response. To see a native policy decision without any model call, `talon run --dry-run "<prompt>"` prints the decision and exits. Reproduce the rest manually next:

**[Reproduce the governed session manually →](manual-governed-session.md)**

## Now wire this to your app

After configuring a separate authenticated Talon installation and registering the use case, point your existing app at its Talon base URL and use its dedicated key. Do not reuse the local demo's key or open admin endpoints.

**Python (`openai` package):**

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8080/v1/proxy/openai/v1",
    api_key="<your-agent-key>",
)
# Then use client.chat.completions.create(...) as usual.
```

**Node.js (`openai` package):**

```javascript
const OpenAI = require("openai");

const client = new OpenAI({
  baseURL: "http://localhost:8080/v1/proxy/openai/v1",
  apiKey: "<your-agent-key>",
});
// Then use client.chat.completions.create(...) as usual.
```

**curl:**

```bash
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-agent-key>" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'
```

For a full step-by-step with vault key, gateway config, first real request, and evidence, see [Add Talon to your existing app](../guides/add-talon-to-existing-app.md).

## What's happening under the hood

When your curl request hits Talon, the gateway path runs:

1. **Route** — the URL path determines the provider.
2. **Identify** — Talon resolves the agent from the presented key.
3. **Rate limit** — the token-bucket check runs.
4. **Extract** — Talon parses model and message text.
5. **PII scan** — recognizers find the email and IBAN.
6. **Classify** — the IBAN raises the input to confidential tier 2.
7. **Policy** — OPA evaluates the request; the decision is enforced (here: allow with redaction — `block` would deny before step 9).
8. **Tool policy** — there are no tools in this request.
9. **Forward** — the redacted request goes to the mock provider.
10. **Evidence** — Talon writes an HMAC-signed record to SQLite.

See [What Talon does to your request](../explanation/what-talon-does-to-your-request.md) for the full technical breakdown.

## You're done

You verified Talon policy decisions locally. Connect a real application using a separate installation and its own key; do not reuse the demo credentials.

| I want to… | Next doc |
|------------|----------|
| Reproduce the hero/deep controls manually | [Reproduce the governed session manually](manual-governed-session.md) |
| Attack the evidence integrity directly | [Evidence integrity: 5-minute proof](evidence-integrity-demo.md) |
| Put Talon in front of my real app | [Add Talon to your existing app](../guides/add-talon-to-existing-app.md) |
| Choose the right integration path | [Choose an integration path](../guides/choosing-integration-path.md) |
| Build a new agent with Talon | [Your first governed agent](first-governed-agent.md) |

## Clean up

```bash
TALON_IMAGE=ghcr.io/dativo-io/talon:1.17.0 docker compose -f docker-compose.yml -f docker-compose.published.yml down -v
```
