# Docker primer: CoPaw + Talon

**Credential handling:** Load real provider keys from your secret manager into the environment before these commands; pass values to `talon secrets set` on stdin. Generated caller keys must be saved securely for the intended caller. For authenticated remote deployments, follow the secure installation procedure in the [existing application guide](../add-talon-to-existing-app.md).

Run Talon as a gateway in front of your LLM provider. CoPaw sends every chat request to Talon; Talon resolves the agent from the presented key, scans for PII, enforces cost and model limits, forwards to the provider, and writes an audit record.

## What you need

- **Base URL** in CoPaw: `http://localhost:8080/v1/proxy/openai/v1` (or `http://<talon-host>:8080/v1/proxy/openai/v1`).
- **API Key** in CoPaw: the primer agent's **Talon agent key** — the value minted into the vault secret referenced by `agent.key.secret_name` in this directory's `agent.talon.yaml` (`gateway-copaw-primer-talon-key` vault entry; generate a random value, retain it in the intended secret manager and supply it via stdin). Not your real OpenAI/DashScope key.

Talon stores the real provider key in its vault; CoPaw only ever holds the agent key, which resolves to exactly one agent and its tenant.

## Prerequisites

- Docker and Docker Compose
- **Image build:** This primer builds the Talon image from the repo root (`context: ../..`). You need a clone of the [Talon repo](https://github.com/dativo-io/talon). Alternatively, use a pre-built image if available (e.g. `ghcr.io/dativo-io/talon:latest`) and set `image: ghcr.io/dativo-io/talon:latest` in `docker-compose.yaml` instead of the `build` block.
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
   - API Key: the agent key minted for `gateway-copaw-primer-talon-key`

4. **Verify**

   `talon audit list --agent gateway-copaw-primer` (the `agent.name` from `agent.talon.yaml` is the evidence `agent_id`) and `GET /v1/copaw/stats` (admin key).

See [CoPaw integration](../copaw-integration.md) for full steps and troubleshooting.

---

## You're done

You now have CoPaw + Talon running in Docker. Talon is the gateway in front of your LLM provider; every request is logged, policy-checked, and recorded.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Cap cost or restrict models | [How to cap daily spend per team or application](../cost-governance-by-agent.md) |
| Run CoPaw + Talon without Docker | [How to govern CoPaw with Talon](../copaw-integration.md) |
| Export evidence for auditors | [How to export evidence for auditors](../compliance-export-runbook.md) |
| Add another app through the gateway | [Add Talon to your existing app](../add-talon-to-existing-app.md) |
