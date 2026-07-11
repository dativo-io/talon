# How to add Talon to your existing app

Get Talon intercepting your real traffic in a few minutes. You have an app (Python, Node.js, or curl) that calls the OpenAI API. By the end, every call goes through Talon and you see the first record from your real app.

## Prerequisites

- Talon installed (`go install github.com/dativo-io/talon/cmd/talon@latest` or `make build` from the repo). On macOS, if `go install` fails with a linker error, use `CC=/usr/bin/clang go install ...@latest`.
- Your real OpenAI API key.
- An existing app or script that calls OpenAI (any language or curl).

## Choose your track

### Track A: dev-mode quickstart (2 minutes)

Use this when you want a local OpenAI-compatible drop-in with no gateway YAML:

```bash
talon serve --proxy-quickstart --port 8080
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY=sk-your-key
```

Run one request from your existing app, then verify with:

```bash
talon audit list --tenant quickstart --limit 5
```

For full walk-through and troubleshooting, use [Tutorial: OpenAI proxy quickstart](../tutorials/proxy-quickstart.md).
When you are ready for production caller separation and vaulted upstream keys, continue with Track B.

### Track B: production gateway with YAML

### 1. Create a project directory and gateway config

```bash
mkdir my-talon-gateway && cd my-talon-gateway
```

Create `talon.config.yaml` with this content (copy-paste as-is):

```yaml
gateway:
  enabled: true
  mode: "shadow"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
  organization_policy:
    log_prompts: true
```

Identity lives in `agent.talon.yaml` (#266) — the scaffold binds
`my-app-talon-key`; mint the key your app will present:

```bash
talon secrets set my-app-talon-key "$(openssl rand -hex 24)"
```

Shadow mode means Talon logs every request and does not block. You can switch to `enforce` later.

### 2. Set the vault key and store your OpenAI key

Talon encrypts the OpenAI key. Use the same `TALON_SECRETS_KEY` when storing the secret and when starting the server.

```bash
export TALON_SECRETS_KEY=$(openssl rand -hex 32)
talon secrets set openai-api-key "sk-your-real-openai-key"
```

Save `TALON_SECRETS_KEY` somewhere safe; you need it whenever you run `talon serve`.

### 3. Start Talon with the gateway

From the same shell (so `TALON_SECRETS_KEY` is still set):

```bash
talon serve --port 8080 --gateway --gateway-config talon.config.yaml
```

Leave this running. You should see the server listening on port 8080.

### 4. Point your app at Talon

Change your app so it talks to Talon instead of OpenAI directly.

**Base URL:** `http://localhost:8080/v1/proxy/openai/v1`  
**API key:** use the caller key `talon-gw-myapp-001` (not your real OpenAI key). Talon identifies the caller by this key and uses the stored OpenAI key when forwarding.

**Python (openai package):**

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8080/v1/proxy/openai/v1",
    api_key="talon-gw-myapp-001",
)
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Say hello in one word."}],
    max_tokens=10,
)
print(response.choices[0].message.content)
```

**Node.js (openai package):**

```javascript
const OpenAI = require("openai");

const client = new OpenAI({
  baseURL: "http://localhost:8080/v1/proxy/openai/v1",
  apiKey: "talon-gw-myapp-001",
});

const completion = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Say hello in one word." }],
  max_tokens: 10,
});
console.log(completion.choices[0].message.content);
```

**curl:**

```bash
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <value-of-my-app-talon-key>" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello in one word."}],"max_tokens":10}'
```

### 5. Run your app and confirm the record

Run your app (or the curl command above) once. Then in another terminal, from the same project directory and with `TALON_SECRETS_KEY` set if you use a new shell:

```bash
talon audit list
```

You should see a new row: caller `my-app`, model, cost, and decision. **This is the first record from your real app.** Talon intercepted the request, forwarded it to OpenAI, and wrote a tamper-proof evidence record.

---

## You're done

You now have Talon in front of your app. Every LLM call is logged, PII is scanned, and you can verify the record with `talon audit verify <evidence-id>`.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Cap cost or restrict models for this app | [How to cap daily spend per team or application](cost-governance-by-agent.md) |
| Switch from shadow to block/redact when PII is found | [Configuration and environment](../reference/configuration.md) (gateway `mode`, `default_policy`) |
| Route another app (e.g. Slack bot) through Talon | [How to add compliance to your Slack bot](slack-bot-integration.md) |
| Understand what happens to each request | [What Talon does to your request](../explanation/what-talon-does-to-your-request.md) |
