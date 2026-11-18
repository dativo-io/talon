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

## Run a published release image (no Talon build)

`docker compose up` above builds both Talon services (`talon`, `talon-ui`) from this checkout: the path for contributors and development CI. To run a **published** image instead, add the override file. Nothing of Talon is compiled; only the small mock provider is built locally:

```bash
TALON_IMAGE=ghcr.io/dativo-io/talon:<version> \
  docker compose -f docker-compose.yml -f docker-compose.published.yml up
```

- `<version>` is a release without the leading `v` (for example `1.17.0`, or a candidate such as `1.17.0-rc.1`). The read-only console (`talon-ui`) is part of Talon from v1.17.0; an older image has no `talon ui` command and that service will not start.
- The image is pulled anonymously from GHCR on every `up` (`TALON_PULL_POLICY` defaults to `always`).
- **No fallback to a source build.** The override removes the `build:` sections, so an image that cannot be pulled stops the stack. (This is why the published path is a second file: with a `build:` section present, Compose answers a failed pull by building.) `TALON_IMAGE` is required and has no default.
- The same image runs the data plane and the console. Ports stay on `127.0.0.1`, as in the default stack.
- Needs Docker Compose v2.24 or newer.

Which reference to use:

| Purpose | Image reference |
|---|---|
| Evaluation | the newest stable release |
| Production and reproducible demos | an explicit version, `ghcr.io/dativo-io/talon:<version>`, or its immutable digest `ghcr.io/dativo-io/talon@sha256:…` (printed by `scripts/verify-release.sh --tag v<version>`) |
| Release acceptance | the exact candidate or stable tag under test, never a moving tag |

Then open `http://127.0.0.1:8787/` and enter the one-time pairing code from `docker compose logs talon-ui`. `scripts/console-compose-smoke.sh` takes the same `TALON_IMAGE` variable and checks, against that image: an unresolvable image stops the stack and nothing is built, both services run the named image, pairing, the six pages, signature verification parity with the CLI, and loopback-only publication.

A quickstart that needs no checkout at all is tracked separately (#463).

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

# Operator status over the admin API (this demo stack sets no TALON_ADMIN_KEY,
# so no X-Talon-Admin-Key header is needed; set one for anything beyond a local demo):
curl http://localhost:8080/v1/status
```

## What's Happening

```
┌─────────────┐      ┌──────────────────┐      ┌──────────────┐
│  Your curl   │─────▶│   Talon Gateway   │─────▶│ Mock OpenAI  │
│  request     │      │                  │      │ (port 9090)  │
└─────────────┘      │  1. Identify agent  │      └──────────────┘
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
