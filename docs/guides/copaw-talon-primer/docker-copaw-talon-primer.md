# Docker primer: CoPaw + Talon

Run Talon as a gateway in front of your LLM provider. CoPaw sends every chat request to Talon; Talon authenticates the caller, scans for PII, enforces cost and model limits, forwards to the provider, and writes an audit record.

## What you need

- **Base URL** in CoPaw: `http://localhost:8080/v1/proxy/openai/v1` (or `http://<talon-host>:8080/v1/proxy/openai/v1`).
- **API Key** in CoPaw: `talon-gw-copaw-001` (the caller key — not your real OpenAI/DashScope key).

Talon stores the real provider key in its vault; CoPaw only sends the caller key.

## Prerequisites

- Docker and Docker Compose
- Talon repo clone (image built from repo root)
- Your real OpenAI (or DashScope) API key for `.env`

## Quick start

1. **Copy env and set your provider key**

   ```bash
   cd docs/guides/copaw-talon-primer
   cp .env.example .env
   # Edit .env: OPENAI_API_KEY=sk-your-key
   ```

2. **Build and run Talon**

   ```bash
   chmod +x entrypoint.sh
   docker compose build
   docker compose up -d
   ```

3. **Configure CoPaw**

   In CoPaw Console (Settings → Models) or via env:

   - Base URL: `http://localhost:8080/v1/proxy/openai/v1`
   - API Key: `talon-gw-copaw-001`

4. **Verify**

   `talon audit list --agent copaw-main` and the dashboard **CoPaw Agents** tab.

See [CoPaw integration](../copaw-integration.md) for full steps and troubleshooting.
