# Talon Limitations

Talon is a governance layer for LLM and MCP request paths. It can enforce policy, record evidence, and steer routing on the Talon path. It is not a complete security, runtime, or compliance platform.

## Not a sandbox

Talon is not a VM boundary, container runtime, kernel sandbox, or host-isolation layer.

- It governs requests that pass through Talon.
- It does not prevent host escape, kernel compromise, or lateral movement on the machine where it runs.
- If you need execution isolation, add your own workload sandboxing and host hardening.

## Not a full trust mesh

Talon is not a general service-identity plane, trust mesh, or agent-to-agent coordination system.

- It applies controls at the Talon boundary.
- It does not create end-to-end trust across downstream services, workers, agents, or human approval steps.

## Tool governance is request filtering today

Today Talon governs tools by filtering request payloads before they go upstream.

- It checks requested tool names against allow and forbid policy.
- It removes disallowed tools from the governed request path.
- It does not intercept tool execution inside another runtime.
- It does not supervise arbitrary code after a request leaves Talon.
- It does not stop the same tool from being invoked through a separate path outside Talon.

## HMAC signatures prove integrity, not correctness

Talon signs evidence records with HMAC-SHA256.

- A valid signature shows the signed record was not modified after Talon wrote it, assuming the signing key remains protected.
- It does not prove Talon's decision was correct, complete, lawful, or suitable for every environment.
- It does not prove upstream or downstream systems behaved correctly outside the signed record.

## Compliance remains the operator's determination

Talon can provide supporting controls and evidence for GDPR, NIS2, DORA, the EU AI Act, and similar programs.

- It does not grant certification, legal sign-off, or guaranteed compliance by itself.
- Whether a deployment satisfies regulatory, contractual, or internal obligations remains the operator's responsibility.

## Trust depends on operator-managed keys and deployment hygiene

Talon's trust properties depend on operator-managed secrets and deployment controls.

- If signing keys, provider credentials, or vault material are exposed, Talon's guarantees weaken accordingly.
- Evidence integrity depends on protecting the signing key and controlling who can write or export records.
- Operators remain responsible for key rotation, access control, host hardening, network security, backup handling, and environment-specific secret management.

## Scope reminder

Treat Talon as a governance layer on the request path, not as a complete security or compliance stack.
