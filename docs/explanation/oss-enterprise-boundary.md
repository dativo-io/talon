# Open source and Enterprise: product boundaries

**Talon OSS is the open-source control plane for company AI use cases.** It enforces the organization baseline plus explicit per-use-case rules on supported model and action paths; supports budget admission, policy-valid retries/fallback, sessions and signed evidence; and provides the canonical local operator and reviewer capabilities. Apache 2.0 does not impose an arbitrary count-of-use-cases limit.

**Talon Enterprise is a separate commercial edition in development.** It is intended to operate the *same* OSS policy, action, approval and evidence kernel in the corporate environment, not sell a second authorization engine. It must never make a safe OSS policy decision, a local exact-action approval, a signed record or independent evidence verification depend on a commercial license.

## The operational problem

A support assistant, a coding agent and an internal analysis workflow should not each invent their own budgets, provider-failure behavior, permissions, action controls and incident evidence. Talon lets a company put those AI use cases under one operating model. The primary jobs are **cost control, reliability, shared policy and session understanding**; exact-action enforcement illustrates what a preventive boundary means, and cryptographically verifiable evidence proves what Talon actually observed and decided.

One Talon installation can serve multiple use cases. Enforcement applies **only at supported interception or delegated paths**. Local side effects that bypass Talon are not controlled; customer or agent asserted session/subagent labels are attribution, not independent authentication.

## Who owns what

| Area | Talon OSS | Talon Enterprise (planned; subject to proven customer need) |
|---|---|---|
| AI use-case registration and effective company policy | Core implementation | Corporate management using identical policy semantics |
| Pre-call budget admission, retries and policy-valid fallback | Core implementation; cost estimate may differ from invoice | Same rules; supported shared production profiles when required |
| Supported exact HTTP action authorization and local human approval | Canonical action/approval decision engine | Corporate reviewer authentication and workflow integrations using the same action digest |
| Sessions, signed evidence, offline verify and exports | Core implementation | Advanced retention/delivery integration without redefining evidence truth |
| Identity | Local admin/reviewer principals and authenticated AI-use-case keys | Corporate OIDC with validated issuer/tenant/domain binding, group mapping, deprovisioning and delegated RBAC |
| Security operations | Generic structured logs/metrics/traces and neutral export | Supported customer-specific SIEM mapping, authenticated transport, replay/alerting and incident runbook |
| External approval tools | Canonical local reviewer interfaces | Customer-selected Teams, Slack or ITSM notification/deep link; never standalone approval authority |
| Secrets, storage, upgrades and support | Local vault, SQLite, documented single-instance production boundary | Customer-managed KMS/vault, PostgreSQL/backup/DR, selected multi-instance profile, commercial support |

The Enterprise release, connectors, HA topology and operational guarantees are **not available simply because a planning issue exists**. Do not label them shipped until the distribution/profile capability manifest and integrated release proof cover the precise version and selected integration.

## Enterprise integration safety contracts

- **Domain is not authorization.** An email address suffix never grants Talon access. A corporate identity needs a validated issuer/client, explicit company tenant binding, mapped group permissions, separation between operator/reviewer/runtime identities, and documented revocation.
- **SIEM is a destination, not the evidence authority.** Exported events must preserve a correlation/evidence reference, canonical decision/reason, outcome certainty and privacy minimization. A missing external delivery cannot be presented as an allowed action or verified outcome. Raw prompts, secrets or action payloads do not belong in SIEM by default.
- **External approval is a UX bridge, not a different state machine.** A chat/ITSM notification cannot itself authorize an action. Revalidate the human principal and bind a decision to the exact immutable operation; approval never implies dispatch or completed business effect.
- **Enforcement is locally authoritative.** Management-plane or SIEM outages must not silently bypass policy. State operational failure modes explicitly and independently test them.
- **No artificial OSS degradation.** Keep safety/correctness fixes and generic telemetry provider-neutral. When Enterprise composition needs an OSS extension, first prove the smallest public seam in the commercial composition spike.

## Adoption and claims

Start with one real use case, a supported boundary, and an allow/deny proof. Inspect the signed decision and actual downstream effect, then expand to a second use case. A company can pilot using OSS and buy enterprise operation/support only when integration and scale demand justify it.

Verify the precise installed version against [the released artifacts](https://github.com/dativo-io/talon/releases/latest), [limitations](../../LIMITATIONS.md) and [control-plane boundaries](../reference/control-plane-boundaries.md). For the public edition overview, see [dativo.io/enterprise](https://dativo.io/enterprise/). Product claims should not imply automatic GDPR/EU AI Act compliance, immutable records, universal agent control or an invoice-perfect spending ceiling.
