# CoPaw + Talon example

This folder contains example configs for governing [CoPaw](https://github.com/agentscope-ai/CoPaw) with Talon as the LLM gateway.

- **agent.talon.yaml** — Agent policy (cost limits, PII, audit).
- **talon.config.yaml** — Gateway config with `copaw-main` caller and OpenAI provider.

Quick start:

1. `talon init --pack copaw --name copaw-gateway` (or copy these files).
2. `talon secrets set openai-api-key "sk-..."`
3. `talon serve --gateway`
4. In CoPaw: Base URL = `http://localhost:8080/v1/proxy/openai/v1`, API Key = `talon-gw-copaw-001`

See [CoPaw integration guide](../../docs/guides/copaw-integration.md) for full steps.
