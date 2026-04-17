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
- Default to `enforce` mode and `redact` PII action.
- Use upstream BYOK (`client_bearer`) with env fallback (`OPENAI_API_KEY`) and fail with 401 when absent.
- Require loopback binds by default; non-loopback requires `--unsafe-listen`.
- Keep mode mutually exclusive with `--gateway` / `--gateway-config`.

## Consequences

Positive:

- Existing SDK apps can adopt Talon with only a base URL swap.
- Governance and evidence stay active even in quickstart mode.
- Quickstart traffic is auditable and separable by tenant/caller.

Trade-offs:

- Partial OpenAI compatibility (no embeddings, no responses retrieval/delete paths).
- Dev-mode-only route relocation for tenant chat endpoint (`/v1/agents/chat/completions` while quickstart is enabled).
- BYOK path is intentionally scoped to quickstart and should not replace vaulted provider auth in production.
