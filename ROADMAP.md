# Roadmap & focus

Talon is an Apache-2.0, self-hosted control plane for company AI use cases. It applies shared company policy and use-case restrictions to model calls and consequential actions at supported boundaries, controls budget admission and provider failures, and records attributable operational evidence. The AI use case is the stable operating object. External runtimes own their own orchestration.

This is the public OSS engineering roadmap, not a feature announcement. See [README](README.md), [CHANGELOG](CHANGELOG.md), [releases](https://github.com/dativo-io/talon/releases), [LIMITATIONS](LIMITATIONS.md) and [control-plane boundaries](docs/reference/control-plane-boundaries.md) for shipped behavior and explicit limits. Issues describe work, not availability. The public [engineering tracker #265](https://github.com/dativo-io/talon/issues/265) and linked release trackers govern scope.

## Current baseline: v1.17.0 (2026-11-24)

- Published first production pilot release: local use-case registration under shared policy, read-only Operations Console, exact-action HTTP and governed MCP dispatch, single-node backup/restore with recovery hold, and streaming response contract.
- Model governance: PII and egress checks on supported paths, budget admission (estimate-based, not an invoice ceiling), policy-valid retries/fallback, per-use-case attribution and signed evidence.
- Action governance: trusted catalog, argument-aware authorization, immutable operation binding, authenticated approval separate from dispatch, at-most-once Talon dispatch within the supported durable boundary; ambiguous outcomes remain unknown. Governed MCP uses the documented protocol and catalog.
- Evidence is tamper-evident and verifiable, not immutable or a guarantee of completeness or legal compliance. Off-path execution is not governed; delegated and observed facts are not Talon-enforced facts. See LIMITATIONS for protocol, recovery, identity and streaming boundaries.

## Active release scope

| Release | Authority | Engineering scope |
|---|---|---|
| v1.18 | [#579](https://github.com/dativo-io/talon/issues/579) | Frozen: [#575](https://github.com/dativo-io/talon/issues/575) connect two existing applications, [#576](https://github.com/dativo-io/talon/issues/576) repeatable n8n/HTTP action integration, [#577](https://github.com/dativo-io/talon/issues/577) investigate action failure/denial, [#580](https://github.com/dativo-io/talon/issues/580) instance and use-case cost/token visibility. [#578](https://github.com/dativo-io/talon/issues/578) remains optional and gated. |
| v1.19 | [#581](https://github.com/dativo-io/talon/issues/581) | Comparable cost receipts #583, provider-native cache economics #584, matched cost-per-successful-task benchmark #598, structured-format benchmark #585. No speculative optimizer. |
| v1.20 | [#582](https://github.com/dativo-io/talon/issues/582) | At most two opt-in improvements only after matched evidence of net billed-cost benefit, accepted task quality and safe host boundary. If no candidate qualifies, scope must be reconsidered. No unconditional optimizer or release date. |

v1.18 acceptance remains as specified in #579: pinned self-hosted n8n profile, stock HTTP, bounded native OpenAI-compatible inference and queue safety, documented Cloud experiment (successful connectivity not a release gate); two n8n acceptance templates, local CLI/API review and existing read-only Console. Usability targets are hypotheses: <=5 min first governed request from prepared working installation, <=3 min second prepared use case, <=1 min investigation. Security and published-artifact verification are mandatory; customer activation is not a publication gate.

## Engineering boundaries

- Preserve public [ADR-004](docs/contributor/adr/ADR-004-modular-control-plane-and-runtime-boundaries.md), one canonical policy/application kernel, the [object model](docs/reference/object-model.md) and explicit INTERCEPT/DELEGATE/COMPILE/VERIFY provenance. No parallel policy or state machine.
- Keep OSS standalone and supported defaults usable. Integrate external implementations through the smallest necessary documented interface, after a demonstrated need and conformance proof. No generic plugin platform or obligation to support arbitrary providers.
- Existing native context/memory and runtime remain supported within documented boundaries. External integrations do not imply blanket compatibility or new capabilities. No speculative memory, retrieval, semantic, workflow or observability engine development.
- Existing follow-up engineering issues include native parity #430/#432, lifecycle evidence #146, policy preview #459, protocol compatibility #469, generic OTLP #475, management permissions #446 and conformance #435. These are not added to frozen release scope by this document. Parked work stays parked per [#116](https://github.com/dativo-io/talon/issues/116).
- Public implementation issues must specify concrete user problems, affected boundaries, scoped acceptance and negative tests; distinguish shipped from planned. No publication promise for unapproved work.

## Contribute

See [CONTRIBUTING](CONTRIBUTING.md), [AGENTS](AGENTS.md) and [open issues](https://github.com/dativo-io/talon/issues). Propose a reproducible user problem and supported integration path; do not assume parked work or a new abstraction is approved. Report vulnerabilities via [SECURITY](SECURITY.md).
