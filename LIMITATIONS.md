# Talon Limitations

This document states what Talon does **not** guarantee today.

Talon is designed to provide governance controls, policy enforcement, and tamper-evident evidence around LLM and MCP traffic. It does **not** replace every security, compliance, or runtime-control layer that a production environment may need.

## Not an OS-level or kernel sandbox

Talon is not a VM, container boundary, kernel sandbox, or host-isolation product.

- It can govern requests that pass through Talon.
- It does not by itself prevent host-level escape, kernel compromise, or lateral movement on the machine where Talon runs.
- If you need stronger isolation, run Talon inside the operator's chosen sandboxing or workload-isolation layer.

## Not a full trust mesh or A2A fabric

Talon is not a general trust mesh, service identity plane, or full agent-to-agent coordination system.

- It focuses on governing model and tool traffic at the Talon boundary.
- It does not by itself establish end-to-end trust between every downstream service, agent, worker, and human approval step in a broader system.

## Tool governance is request filtering today

Today, Talon's tool governance is request-body filtering, not runtime execution interception.

- Talon evaluates requested tool names against allow/forbid policy and removes disallowed tools before forwarding the request.
- This is useful for preventing the model from seeing or selecting disallowed tools in the governed request path.
- It does not by itself supervise arbitrary code after a request leaves Talon, intercept tool execution inside another runtime, or guarantee that an external system will not invoke tools through some separate path.

## Evidence signatures prove integrity, not correctness

Talon signs evidence records with HMAC-SHA256 so operators can verify tamper-evidence and export integrity.

- A valid signature shows that the signed record was not modified after Talon wrote it, assuming the signing key remains protected.
- A signature does **not** prove that Talon's decision was correct, complete, lawful, or appropriate for every environment.
- A signature also does not prove that upstream or downstream systems behaved correctly outside the signed record.

## Compliance remains the operator's determination

Talon supports controls that operators may use in GDPR, NIS2, DORA, EU AI Act, or similar programs.

- Talon can provide policy enforcement, evidence, routing controls, and audit support.
- Talon does **not** grant certification, legal sign-off, or guaranteed compliance by itself.
- Whether a deployment satisfies regulatory, contractual, or internal-policy obligations remains the operator's responsibility.

## Key-management assumptions

Talon's trust properties depend on operator-managed secrets and deployment hygiene.

- If signing keys, provider credentials, or vault material are exposed, Talon's guarantees are weakened accordingly.
- Evidence integrity depends on protecting the signing key and controlling who can write or export records.
- Operators are responsible for key rotation, access control, network security, host hardening, backup handling, and environment-specific secret management.

## Scope reminder

Talon is best understood as a governance layer on the request path, not as a complete security or compliance stack.

Use Talon together with the rest of your platform controls when you need stronger isolation, runtime enforcement, or formal compliance determinations.
