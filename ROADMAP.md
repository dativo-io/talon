# Roadmap

## v0.1.0 (March 2026) — MVP

- [x] Policy engine (embedded OPA/Rego)
- [x] PII detection (25+ EU patterns across 27 member states)
- [x] Evidence store (HMAC-SHA256 signed, SQLite)
- [x] Secrets vault (AES-256-GCM, per-agent ACL)
- [x] Multi-LLM support (OpenAI, Anthropic, Bedrock, Ollama)
- [x] MCP server (native JSON-RPC 2.0)
- [x] HTTP API + embedded dashboard
- [x] Agent memory (governed, PII-scanned, Constitutional AI)
- [x] LLM API Gateway (transparent proxy at `/v1/proxy/*`)
- [x] Attachment scanning (prompt injection prevention)
- [x] Cron scheduler + webhook triggers
- [ ] Mock provider + docker-compose demo (no API key)
- [ ] Flow 0 verification (60-second demo)

## v0.2.0 (April 2026) — Gateway & Proxy Polish

- [ ] MCP Proxy (vendor integration for Zendesk, Intercom, etc.)
- [ ] Shadow mode dashboard tab (AI usage discovery)
- [ ] Per-caller/team cost dashboards
- [ ] `talon init --pack` for more industry templates
- [ ] Quickstart tutorials (Diataxis)
- [ ] JSON Schema validation for configs

## v0.3.0 (May 2026) — Enterprise

- [ ] PostgreSQL backend (high-availability evidence store)
- [ ] LGTM observability stack integration (Grafana, Loki, Tempo, Mimir)
- [ ] Infisical integration (secret rotation, SAML)
- [ ] RBAC (role-based access control for the API)
- [ ] SSO/SAML authentication

## Future

- [ ] A2A protocol (agent-to-agent communication)
- [ ] Kubernetes operator
- [ ] Vector-search agent memory
- [ ] Advanced PII detection (Presidio integration)
- [ ] S3 WORM evidence storage
- [ ] gVisor/Firecracker agent isolation

## How to Influence the Roadmap

- Open a [feature request](https://github.com/dativo-io/talon/issues/new?template=feature_request.yml) with your use case
- Vote on existing issues with a thumbs-up reaction
- Join the discussion in [GitHub Discussions](https://github.com/dativo-io/talon/discussions)

Roadmap items are prioritized by: (1) community demand, (2) compliance
deadlines (EU AI Act August 2026), (3) engineering feasibility.
