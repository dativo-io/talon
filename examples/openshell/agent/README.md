# support-agent — the tool-using reference agent for Talon ↔ OpenShell

`support-agent` is a customer-support assistant in which **the model chooses
the tools**. It is built on the official OpenAI Go SDK
([`github.com/openai/openai-go`](https://github.com/openai/openai-go), Apache-2.0,
chat-completions tool calling) and runs inside an OpenShell sandbox with no
Talon credential, no reviewer credential and no provider credential:

```
model request  →  OpenShell  →  Talon middleware (model policy, PII, budget, tool governance)  →  provider
tool execution →  OpenShell  →  Talon middleware hop (sandbox identity → workload assertion)
                              →  Talon Action Gateway (exact authorization, human approval, at-most-once dispatch)
                              →  the protected business system (reachable only through Talon)
```

The agent offers the model three tools — `lookup_ticket` (allowed),
`delete_customer` (forbidden by the use case's policy), `create_refund_request`
(requires a human reviewer) — and executes **every** tool call as a Talon
action. Talon removes the forbidden tool before the model sees the tool list;
when a model asks for it anyway, Talon denies the exact action before any
dispatch. The refund waits for a reviewer who approves from outside the
sandbox; the agent's claim then dispatches it at most once, and a replay never
duplicates the effect.

## Why this SDK

The smallest maintained SDK that speaks the provider contract OpenShell's model
path forwards (OpenAI-compatible chat completions with tool calling) and needs
no framework runtime inside the sandbox: one static binary, no interpreter, no
package index access from the sandbox. It is its own Go module so Talon's core
never depends on it; the same loop is a few lines in the Python or TypeScript
SDKs, which speak the identical wire contract. The deterministic fixture test
(`TestE2E_OpenShell_SDKAgent`) drives this exact binary with a scripted model,
so CI proves the journey without spending money; set `PROVIDER_BASE` to a real
provider through OpenShell to run it against a real model.

## Run it

Operator prerequisites (one-time): Talon with `gateway.openshell` (identity,
`self_destination` listing the host the sandbox dials, `response_governance`
on), the use case bound to the sandbox id with `capabilities.allowed_tools:
[lookup_ticket, create_refund_request]`, `capabilities.forbidden_tools:
[delete_customer]`, the three actions in its catalog and the refund approval
rule (see `docs/integration/openshell.md`, "Operator runbook"), a reviewer
credential (`talon approver add --tenant <t> --groups support-leads`), and a
sandbox network policy that admits the provider host and Talon's host with the
`talon` middleware attached to both.

Build a static binary and run it inside the sandbox:

```bash
cd examples/openshell/agent && CGO_ENABLED=0 go build -o support-agent .
# inside the sandbox (the image must carry the binary, e.g. COPY it into your sandbox image)
TALON_BASE=http://host.openshell.internal:8080 \
PROVIDER_BASE=http://host.openshell.internal:9000 \
TALON_SESSION=sess-demo-1 OPERATION_ID=refund-demo-1 \
./support-agent
```

Output is one `KEY=VALUE` line per step:

```
TOOLS_OFFERED=lookup_ticket,create_refund_request,delete_customer
MODEL=ok TURN=1 TOKENS=40/12 TOOL_CALLS=1
OPERATION_REF=op_… VERDICT=ALLOW
ATTEMPT=succeeded TOOL=lookup_ticket OPERATION=refund-demo-1-lookup_ticket-1
MODEL=ok TURN=2 TOKENS=50/12 TOOL_CALLS=1
DENIED=delete_customer OPERATION=refund-demo-1-delete_customer-2 CODE=DENY
MODEL=ok TURN=3 TOKENS=60/12 TOOL_CALLS=1
OPERATION_REF=op_…
APPROVAL_ID=apr_…
APPROVAL=approved
ATTEMPT=succeeded TOOL=create_refund_request OPERATION=refund-demo-1-create_refund_request-3
REPLAY=operation_already_succeeded
MODEL=ok TURN=4 TOKENS=70/12 TOOL_CALLS=0
FINAL=Ticket T-1842 handled: …
RESULT=succeeded
```

While the agent waits at `APPROVAL_ID=…`, the reviewer approves from
**outside** the sandbox:

```bash
curl -X POST http://<talon>/v1/approvals/<approval_id>/decisions \
  -H "Authorization: Bearer talon_appr_cred_…" -H 'content-type: application/json' \
  --data '{"decision":"approve","reason":"verified with customer"}'
```

Then reconstruct and verify what happened:

```bash
talon audit list --runtime-ref <sandbox_id> --report   # identity, model exchanges + settlements, operations + human decision, verification
talon audit list --session sess-demo-1                  # the same session, record by record
talon audit verify --operation refund-demo-1-create_refund_request-3
```

Environment: `TALON_BASE`, `PROVIDER_BASE` (required); `TALON_SESSION`,
`OPERATION_ID` (prefix), `TICKET_ID` (default `T-1842`), `MODEL` (default
`gpt-4o-mini`), `APPROVAL_WAIT_S` (default 120), `MAX_TURNS` (default 8),
`OPENAI_API_KEY` (a placeholder: OpenShell injects the real credential after
Talon decided).

Exit codes: `0` completed as governed; `1` a step was refused (the Talon code
is printed); `2` the reviewer rejected or the approval expired; `3` no reviewer
decision in time; `4` a transport or SDK failure.

What the sandbox never holds: a Talon agent key, a reviewer credential, the
protected service's credential, the provider credential. What this example
does not prove: OpenShell's containment itself (the fixture test replays the
documented supervisor contract; the live lane proves the runtime with the shell
fixture agent, `../sandbox-agent.sh`).
