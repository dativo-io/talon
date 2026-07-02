# Talon Security Boundaries & Limitations

Talon provides policy enforcement, routing controls, PII handling, and signed evidence records for AI gateway traffic. It does not determine legal compliance for an operator, and it does not prove that a downstream model, tool, or human decision was correct.

This document serves as an explicit boundaries guide so that operators and security teams can accurately evaluate Talon's trust model.

---

## Current Status Overview

| Capability | Status | Description |
| :--- | :--- | :--- |
| **Available Now** | ✅ | Proxy governance, input/output PII scan, policy decision, signed evidence, audit verify. |
| **Partial Today** | 🟡 | EU routing proof is currently deny/allow evidence, not silent rerouting. |
| **Roadmap** | ⏳ | Runtime tool execution interception, full auditor pack, broader trust mesh/A2A. |

---

## 1. Compliance Boundary

**Talon provides supporting controls and evidence.**
- The operator remains entirely responsible for legal and compliance determinations.
- Talon produces cryptographic receipts that assist with audits. It does not make an organization automatically compliant with GDPR, NIS2, or the EU AI Act.

## 2. Evidence Boundary

**HMAC proves record integrity and tamper evidence.**
- The signature proves that the request passed through the gateway and that the logged payload was not maliciously altered after the fact.
- It **does not** prove that the policy configured was correct, that the model's response was safe or hallucination-free, or that the operator configured the right security controls.

## 3. Tool-Governance Boundary

**Today: Forbidden tools are filtered from request bodies before forwarding.**
- Talon prevents the model from ever seeing forbidden tools by stripping them from the initial request JSON.
- **Not yet:** Talon does not currently provide runtime execution interception or full MCP tool-call governance. These are planned for future roadmap epics.

## 4. Isolation Boundary

**Talon provides process-level controls only.**
- Talon is **not** an OS-level or kernel sandbox. 
- External tools and providers remain completely separate trust boundaries and must be secured accordingly.

## 5. Scanner Compatibility Boundary

**Talon supports a Presidio-compatible result shape at the ingestion boundary.**
- Talon normalizes external scanner results to canonical internal entities and enforces byte-offset semantics for redaction and policy checks.
- This is a contract compatibility seam, **not** a claim of full Presidio behavioral parity across recognizer internals.
- HTTP and Unix-domain-socket adapters for Presidio-compatible engines are supported via the `scanner:` config block (see [external scanners](docs/reference/external-scanners.md)); the adapter protocol carries no authentication yet, so engines must be network-isolated. gRPC transports and Talon-managed sidecar lifecycles are not supported.
- Semantic enrichment is a built-in-regex-engine feature: when an external scanner engine is configured, enrichment is skipped and legacy `[TYPE]` placeholders are used.
- External engines report no Talon sensitivity levels; their entities default to tier 1 unless the engine supplies `expected_sensitivity` per result.
- Runtime remediation is intentionally minimal in MVP scope: Talon supports approval-flow re-redact/re-scan remediation for tool-approval decisions, but does not implement the full remediation workflow stack yet (tracked in follow-up epics).
- Residual PII enforcement remains fail-closed: remediation failures do not bypass policy blocks.

## 6. Deployment and Key-Management Assumptions

**Evidence signing depends on operator-controlled key handling.**
- The cryptographic guarantees of Talon's evidence records rely on the operator securing the signing keys.
- Provider registry and routing claims depend entirely on accurate provider configuration by the operator.
- Air-gapped deployments and full auditor-pack claims should be considered roadmap items unless marked as explicitly live.
