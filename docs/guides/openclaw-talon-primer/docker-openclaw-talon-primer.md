# Docker primer: OpenClaw governed by Talon (cloud-ready)

This guide gives you a **predefined Docker setup** so you can run Talon as an LLM API gateway and point OpenClaw (or any OpenAI-compatible client) at it. Use it as a primer for deploying OpenClaw + Talon in the cloud.

## What's in the primer

- **Talon** runs in a container with the **gateway** enabled. It exposes `POST /v1/proxy/openai/...` (and optionally Anthropic/Ollama). Callers use a gateway API key; Talon injects the real provider key and enforces policy.
- **Gateway config** is predefined with a caller `openclaw-main` (API key: `talon-gw-openclaw-abc123`). You can add more callers or change policy in the included YAML.
- **Secrets**: The real OpenAI (and optionally Anthropic) key is passed via env and written into Talon's vault at startup so the gateway can forward requests.
- **Optional verify service**: A one-off container that sends a test request to the gateway so you can confirm the stack works without OpenClaw.

## Prerequisites

- Docker and Docker Compose
- Clone of the Talon repo (so the primer can build the Talon image from the repo root)
- Your real OpenAI API key (and optionally Anthropic)

## Quick start

All primer files live in this folder. Ensure `entrypoint.sh` is executable (`chmod +x entrypoint.sh`) so the container can run it.

### 1. Set environment

```bash
cd docs/guides/openclaw-talon-primer
cp .env.example .env
# Edit .env and set:
#   OPENAI_API_KEY=sk-your-openai-key
```

### 2. Build and run

From **inside** `docs/guides/openclaw-talon-primer/`:

```bash
docker compose build
docker compose up -d
```

Talon listens on **port 8080** (or `TALON_PORT` from `.env`). The gateway is at:

- OpenAI: `http://localhost:8080/v1/proxy/openai`
- Anthropic: `http://localhost:8080/v1/proxy/anthropic`

### 3. Point OpenClaw at the gateway

On your machine (or wherever OpenClaw runs):

- Set the OpenAI provider **base URL** to the Talon gateway URL (see table below).
- Set the OpenAI provider **API key** to the **caller** key: `talon-gw-openclaw-abc123` (from the primer's gateway config). Do not use your real OpenAI key in OpenClaw.

| Where Talon runs | OpenAI baseUrl in OpenClaw |
|------------------|----------------------------|
| Same machine     | `http://localhost:8080/v1/proxy/openai` |
| Cloud / remote   | `http://<talon-host>:8080/v1/proxy/openai` or `https://<talon-host>/v1/proxy/openai` if behind TLS |

Full OpenClaw configuration steps: [How to govern OpenClaw with Talon](../openclaw-integration.md).

### 4. Verify (optional)

Run the included verify profile to send a test request through the gateway:

```bash
docker compose --profile verify up verify
```

Then list evidence for the caller:

```bash
docker exec talon-gateway talon audit list --agent openclaw-main --limit 5
```

## Primer layout

```
docs/guides/openclaw-talon-primer/
├── docker-openclaw-talon-primer.md  # This guide
├── docker-compose.yaml              # Talon service + optional verify
├── .env.example                     # Copy to .env and set OPENAI_API_KEY
├── entrypoint.sh                    # Seeds vault from env, runs talon serve --gateway
├── talon.config.gateway.yaml        # Gateway config (callers, providers, policy)
└── agent.talon.yaml                 # Minimal policy for server boot (gateway uses talon.config.gateway.yaml)
```

- **Build**: The Talon image is built from the **repo root** (`context: ../..`) so the same `Dockerfile` as the main project is used.
- **Secrets**: `entrypoint.sh` runs `talon secrets set openai-api-key "$OPENAI_API_KEY"` (and optionally Anthropic) at startup so the gateway can forward without you running `talon secrets set` inside the container.
- **Persistence**: The `talon-data` volume holds the vault and evidence DB. Keep it for audit and for avoiding re-seeding secrets on every restart.

## Cloud deployment notes

1. **Port and URL**  
   Set `TALON_PORT` in `.env` if you need a different host port. In the cloud, use the host's public IP or DNS and, if you put a reverse proxy in front, the path `/v1/proxy/openai` must be forwarded to the Talon container.

2. **TLS**  
   The primer does not enable TLS. In production, run Talon behind a reverse proxy (e.g. nginx, Caddy, or a cloud load balancer) that terminates HTTPS and forwards to `http://talon:8080`. OpenClaw would then use `https://<your-domain>/v1/proxy/openai` as base URL.

3. **Secrets and keys**  
   For production, set `TALON_SECRETS_KEY` and `TALON_SIGNING_KEY` in `.env` (e.g. 64 hex chars each). Do not rely on default derived keys if the volume is not durable or is shared. Use your cloud's secret manager (e.g. AWS Secrets Manager, GCP Secret Manager) and inject them as env vars into the Compose/container.

4. **Persistence**  
   Keep the `talon-data` volume so evidence and the vault persist across restarts. Back it up according to your compliance needs.

5. **OpenClaw not in Docker**  
   This primer runs only Talon in Docker. OpenClaw typically runs on a desktop or another host. Configure OpenClaw with the **gateway URL** and **caller API key** as above; no need to run OpenClaw in the same Compose stack.

## Summary

| Step | Action |
|------|--------|
| 1 | `cd docs/guides/openclaw-talon-primer`, copy `.env.example` to `.env`, set `OPENAI_API_KEY` |
| 2 | `docker compose build && docker compose up -d` |
| 3 | In OpenClaw: baseUrl = `http://<talon-host>:8080/v1/proxy/openai`, API key = `talon-gw-openclaw-abc123` |
| 4 | (Optional) `docker compose --profile verify up verify` and `docker exec talon-gateway talon audit list --agent openclaw-main` |

After that, OpenClaw is governed by Talon: every request is audited and subject to gateway policy (cost, PII, models). For more policy options and caller setup, see [How to govern OpenClaw with Talon](../openclaw-integration.md) and `talon.config.gateway.yaml` in this directory.
