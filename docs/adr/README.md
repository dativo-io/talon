# Architecture Decision Records

ADRs live in **contributor documentation** under [`docs/contributor/adr/`](../contributor/adr/). The numbered series there is canonical; `0001` below predates it.

| ADR | Status | Topic |
|---|---|---|
| [ADR-004](../contributor/adr/ADR-004-modular-control-plane-and-runtime-boundaries.md) | Accepted (2026-10) | One modular in-process control plane and runtime boundaries: model vs action governance, execution profiles, typed approval kernel, continuation ownership, MCP 2026-07-28, enforcement doctrine `INTERCEPT \| DELEGATE \| COMPILE \| VERIFY` (#424). Living companion: [Control-plane boundaries](../reference/control-plane-boundaries.md). |
| [ADR-003](../contributor/adr/ADR-003-graph-runtime-governance.md) | Accepted (2026-04), amended by ADR-004 | Graph runtime governance: graph events as context/telemetry. |
| [ADR-002](../contributor/adr/ADR-002-prompt-storage-data-minimization.md) | Accepted | Prompt storage data minimization. |
| [ADR-001](../contributor/adr/ADR-001-agent-planning-paradigm.md) | Accepted | Agent planning paradigm. User-facing doc: [Agent Planning in Talon](../AGENT_PLANNING.md). |
| [ADR 0001](0001-openai-proxy-quickstart.md) | Accepted, amended by #266/#285 | OpenAI-compatible proxy quickstart. |

A decision in an accepted ADR is reversed only by a superseding ADR, never by silently editing the original.
