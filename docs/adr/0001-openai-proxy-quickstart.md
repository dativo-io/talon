# ADR 0001: OpenAI-compatible proxy quickstart

## Status

Accepted.

## Context

Many teams already have OpenAI SDK integrations and want to evaluate Talon governance quickly without writing gateway config first.

## Decision

Add `talon serve --proxy-quickstart` as a dev/local mode with these constraints:

- Host-root compatibility for `POST /v1/chat/completions` and `POST /v1/responses` only.
- Reuse the existing gateway pipeline (PII, policy, cost controls, evidence).
- Use a synthetic caller (`quickstart-local`) and tenant (`quickstart`) injected by an in-process facade.
- Do **not** register any synthetic tenant key; quickstart is strictly a host-root facade and must not unlock Talon's tenant-auth surface by side effect. Tenant endpoints (including the relocated `/v1/agents/chat/completions`) still require a real tenant key configured by the operator.
- Default to `enforce` mode and `redact` PII action.
- Use upstream BYOK (`client_bearer`) with env fallback (`OPENAI_API_KEY`) and fail with 401 when absent.
- Require loopback binds by default; non-loopback requires `--unsafe-listen`. The `--unsafe-listen` signal is threaded explicitly into the quickstart `GatewayConfig` (field `QuickstartUnsafeListen`) rather than set as a process env var, so evidence annotations remain deterministic and do not depend on ambient environment state.
- Keep mode mutually exclusive with `--gateway` / `--gateway-config`. The exclusivity check uses `cobra.Flags().Changed("gateway-config")` so it depends on whether the operator explicitly passed the flag, not on the default string value.

## Consequences

Positive:

- Existing SDK apps can adopt Talon with only a base URL swap.
- Governance and evidence stay active even in quickstart mode.
- Quickstart traffic is auditable and separable by tenant/caller.

Trade-offs:

- Partial OpenAI compatibility (no embeddings, no responses retrieval/delete paths).
- Dev-mode-only route relocation for tenant chat endpoint (`/v1/agents/chat/completions` while quickstart is enabled).
- BYOK path is intentionally scoped to quickstart and should not replace vaulted provider auth in production.
