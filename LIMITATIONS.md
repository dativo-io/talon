# Talon Limitations

This document states the main guarantees Talon does not make today.

Talon is a governance layer for LLM and MCP request paths. It adds policy enforcement, evidence records, and routing controls, but it does not replace the rest of a production security, runtime, or compliance stack.

## Not a sandbox

Talon is not a VM, container boundary, kernel sandbox, or host-isolation product.

- It governs requests that pass through Talon.
- It does not prevent host escape, kernel compromise, or lateral movement on the machine where Talon runs.
- Use your own workload-isolation layer if you need stronger execution isolation.

## Not a full trust mesh

Talon is not a general trust mesh, service identity plane, or agent-to-agent coordination system.

- It governs model and tool traffic at the Talon boundary.
- It does not establish end-to-end trust across every downstream service, worker, agent, or human approval step in a larger system.

## Tool governance stops at request filtering

Talon's tool governance currently filters request payloads before forwarding them upstream.

- Talon checks requested tool names against allow and forbid policy and removes disallowed tools from the governed request path.
- It does not intercept tool execution inside another runtime.
- It does not supervise arbitrary code after a request leaves Talon.
- It does not guarantee that another system will not invoke the same tool through a separate path.

## Evidence signatures prove record integrity, not decision correctness

Talon signs evidence records with HMAC-SHA256.

- A valid signature shows the signed record was not modified after Talon wrote it, assuming the signing key remains protected.
- A signature does not prove Talon's decision was correct, complete, lawful, or appropriate for every environment.
- A signature does not prove upstream or downstream systems behaved correctly outside the signed record.

## Compliance remains the operator's responsibility

Talon can support GDPR, NIS2, DORA, EU AI Act, and similar programs with policy enforcement, evidence, and routing controls.

- It does not grant certification, legal sign-off, or guaranteed compliance by itself.
- Whether a deployment satisfies regulatory, contractual, or internal-policy obligations remains the operator's responsibility.

## Trust depends on operator-managed keys and deployment hygiene

Talon's trust properties depend on operator-managed secrets and deployment controls.

- If signing keys, provider credentials, or vault material are exposed, Talon's guarantees weaken accordingly.
- Evidence integrity depends on protecting the signing key and controlling who can write or export records.
- Operators remain responsible for key rotation, access control, host hardening, network security, backup handling, and environment-specific secret management.

## Scope reminder

Treat Talon as a governance layer on the request path, not a complete security or compliance platform.
