# Talon Demo — No API Key Required

See governance working in 60 seconds. The mock OpenAI provider handles all LLM
calls, so you don't need a real API key.

## Quick Start

```bash
# Start Talon + mock provider
docker compose up

# In another terminal, send a request with PII:
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {"role": "user", "content": "My email is jan@example.com and my IBAN is DE89370400440532013000. Help me reset my password."}
    ]
  }'

# Check the audit trail:
docker compose exec talon /usr/local/bin/talon audit list
```

You'll see an evidence record with PII detected (email, IBAN), cost tracked,
and HMAC signature.

## Run the Full Demo

```bash
# Send 5 varied requests (clean, email PII, IBAN PII, multi-PII, different model):
bash demo-client/demo.sh

# View the evidence trail:
docker compose exec talon /usr/local/bin/talon audit list

# Inspect a specific record:
docker compose exec talon /usr/local/bin/talon audit show <evidence-id>

# Verify signature integrity:
docker compose exec talon /usr/local/bin/talon audit verify <evidence-id>

# Open the dashboard:
open http://localhost:8080/dashboard
```

## What's Happening

```
┌─────────────┐      ┌──────────────────┐      ┌──────────────┐
│  Your curl   │─────▶│   Talon Gateway   │─────▶│ Mock OpenAI  │
│  request     │      │                  │      │ (port 9090)  │
└─────────────┘      │  1. Identify caller │      └──────────────┘
                     │  2. Parse request   │
                     │  3. Scan for PII    │
                     │  4. Evaluate policy │
                     │  5. Forward request │
                     │  6. Scan response   │
                     │  7. Record evidence │
                     │  8. Track cost      │
                     └──────────────────┘
                              │
                     ┌────────┴────────┐
                     │  SQLite + HMAC   │
                     │  Evidence Store  │
                     └─────────────────┘
```

The mock provider returns realistic OpenAI-compatible responses with token
counts, so cost tracking and evidence generation work exactly as they would
with a real provider.

## Clean Up

```bash
docker compose down -v
```
