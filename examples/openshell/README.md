# OpenShell reference sandbox agents

Two reference agents live here. `agent/` (`support-agent`) is the
**tool-using** agent on the official OpenAI Go SDK — the model chooses the
tools, Talon governs each one — with its own README. `sandbox-agent.sh`,
described below, is the deterministic protocol fixture the live lane runs.

`sandbox-agent.sh` is the reference agent for the Talon ↔ NVIDIA OpenShell
composition (#457/#482). It runs **inside** an OpenShell sandbox with nothing
but POSIX `sh`, `curl` and `sed`, holds **no Talon credential**, and walks the
complete governed scenario:

1. asks the model through OpenShell → Talon's middleware → the provider
   (OpenShell injects the provider credential after Talon decided);
2. reads an authorized external resource through a governed read action;
3. requests a consequential mutation (`create_refund_request`);
4. receives `REQUIRE_APPROVAL` and waits for a human reviewer (the sandbox can
   read its approval, never decide it — the reviewer route is unreachable
   through the hop);
5. resumes after approval and claims the attempt: Talon revalidates and
   executes the action **at most once** through the supported HTTP contract;
6. proves replay safety (a second claim returns `operation_already_succeeded`)
   and prints the evidence references.

How the sandbox authenticates: the sandbox dials Talon's HTTP API like any
other allowed destination. OpenShell's supervisor calls Talon's middleware
with the gateway-signed sandbox token; Talon verifies it, binds the sandbox to
its use case and returns an `X-Talon-Workload-Assertion` header mutation that
OpenShell carries to Talon's Action Gateway. See
[`docs/integration/openshell.md`](../../docs/integration/openshell.md#action-gateway-through-the-hop-457482--the-sandbox-holds-no-talon-secret).

## Run it

Prerequisites on the operator side (one-time): Talon with
`gateway.openshell` (`self_destination` listing the host the sandbox dials,
`response_governance` recommended), the use case bound to the sandbox id and
carrying the `lookup_ticket` / `create_refund_request` catalog, a reviewer
credential (`talon approver add --tenant <t> --groups support-leads`), and a
sandbox policy that admits the provider host and Talon's host with the
`talon` middleware attached to both.

```bash
# inside the sandbox (or: openshell sandbox exec --name <sb> --env ... -- sh -c "$(cat sandbox-agent.sh)")
TALON_BASE=http://host.openshell.internal:8080 \
PROVIDER_BASE=http://host.openshell.internal:9000 \
TALON_SESSION=sess-demo-1 OPERATION_ID=refund-demo-1 \
sh sandbox-agent.sh
```

Output is one `KEY=VALUE` line per step:

```
MODEL=ok
READ=succeeded READ_EVIDENCE=act_…
OPERATION_REF=op_…
APPROVAL_ID=apr_…
APPROVAL=approved
ATTEMPT=succeeded
REPLAY=operation_already_succeeded
RESULT=succeeded
```

While the agent waits at `APPROVAL_ID=…`, the reviewer approves from
**outside** the sandbox:

```bash
curl -X POST http://<talon>/v1/approvals/<approval_id>/decisions \
  -H "Authorization: Bearer talon_appr_cred_…" -H 'content-type: application/json' \
  --data '{"decision":"approve","reason":"verified with customer"}'
```

Then reconstruct what happened:

```bash
talon audit list --session sess-demo-1          # model decisions + settlements + action lifecycle
talon audit list --runtime-ref <sandbox_id>     # everything attributed to the sandbox, incl. imported containment events
talon audit verify --operation refund-demo-1    # the whole lifecycle, signatures and consistency
```

Exit codes: `0` the scenario completed as governed; `1` a step was refused
(`RESULT=failed STEP=… CODE=… ERROR=<talon code>`); `2` the reviewer rejected
or the approval expired/invalidated; `3` no decision within
`APPROVAL_WAIT_S`.

The live lane (`make test-openshell-live`, case N) runs this exact script in
a real OpenShell sandbox against the released runtime and approves from the
host while the agent waits.
