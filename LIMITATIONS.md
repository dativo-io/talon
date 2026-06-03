# Limitations

Talon provides policy enforcement, routing controls, PII handling, and signed evidence records for AI gateway traffic. It does not determine legal compliance for an operator, and it does not prove that a downstream model, tool, or human decision was correct.

This page states plainly where Talon's claims stop. It applies to the network gateway / proxy path that every request flows through.

## Capability status

| Status | Capabilities |
|--------|--------------|
| **Available now** | OpenAI-compatible proxy governance; input and output PII scanning; OPA policy allow/deny decisions; HMAC-signed evidence records; `talon audit verify` |
| **Partial today** | EU routing and data sovereignty in the gateway path: a non-compliant route is **denied with signed evidence**, not silently re-routed across providers ([`internal/llm/router.go`](internal/llm/router.go)). The gateway proxy and the `talon run` router can differ on routing behavior. |
| **Roadmap** | Runtime tool **execution** interception via the MCP proxy; a filled-in auditor RoPA / EU AI Act Annex IV pack; broader trust mesh / agent-to-agent governance |

This table is the source of truth for capability claims. If a demo or doc describes a "partial" item, it should not be presented as generally available.

## Compliance boundary

- Talon provides supporting controls and evidence — for example, framework-mapped reports via `talon compliance report`. A report is a control-mapping summary, not a completed legal filing.
- The operator remains responsible for the legal and compliance determination.
- We use "supports evidence for GDPR Art. X" style wording, never "GDPR compliant" or "makes you compliant" (the built-in article mappings live in [`internal/compliance/mapping.go`](internal/compliance/mapping.go)).
- PII detection is regex- and heuristic-based. It supports GDPR Art. 32-style controls but does not guarantee complete recall.

## Evidence boundary

A valid signature proves that this evidence record was signed with the deployment's configured key and has not been modified since signing. It does not prove that the policy, model response, tool result, or operator decision was correct.

- Verify a record with `talon audit verify <id>` or `talon audit verify --file <export>` — see [evidence store](docs/explanation/evidence-store.md).
- The signature covers the canonical JSON of the stored fields ([`VerifyRecord`](internal/evidence/store.go)). It is not instance attestation, and it does not vouch for upstream provider behavior.

## Tool-governance boundary

- Today, forbidden tools are stripped from request bodies before forwarding ([`internal/gateway/tool_filter.go`](internal/gateway/tool_filter.go)); the README "pre-execution filter" wording reflects this.
- Not yet: runtime execution interception or per-execution MCP tool-call governance with a signed deny.
- "Tool governance: Yes" in the README comparison means request-body filtering today, not runtime execution control.

## Isolation boundary

- Talon applies process-level controls inside a single binary. It is not an OS or kernel sandbox, and it does not ship a gVisor, Kubernetes-operator, or container-escape isolation layer — these are deliberate non-goals for the current scope.
- Host hardening remains the operator's responsibility.
- LLM and MCP providers and any external tools are separate trust boundaries. Talon does not secure vendor infrastructure.

## Deployment and key-management assumptions

- Custody, rotation, and backup of `TALON_SIGNING_KEY` are operator responsibilities ([`NewSigner`](internal/evidence/signature.go) requires a key of at least 32 bytes).
- Provider registry and EU routing claims depend on accurate configuration (`.talon.yaml` and gateway config).
- Air-gapped deployment and an auditor-grade export pack are roadmap items unless explicitly documented as live.
- When Talon sits on the critical path, availability and failover are not yet claimed as production-grade.

## Further reading

- [ROADMAP.md](ROADMAP.md) — public anti-goals, wedge focus, and phased direction
- [SECURITY.md](SECURITY.md) — security boundaries and threat-model snapshot
- [Evidence store](docs/explanation/evidence-store.md) — how records are created, signed, and verified
- [Evidence integrity specification](docs/reference/evidence-integrity-spec.md) — byte-exact fields, serialization, signing, and independent verification
- [Threat model](docs/reference/threat-model.md) — attack surface, trust boundaries, and key-management assumptions
- [Reproducible benchmarks](docs/reference/benchmarks.md) — run `make benchmarks` on your hardware; retry/fallback overhead not included until Epic #113 lands.
