# Govern an n8n refund workflow with Talon

Keep your n8n automation. Route the consequential business action through Talon's **HTTP Action Gateway**, so the company policy decides whether the action may proceed, a reviewer decides when required, and Talon—not n8n—dispatches the authorized action to your business adapter.

The [importable n8n refund reference](../../examples/n8n-refund/README.md) contains the workflow JSON, two-layer example policy, setup details and live acceptance script. This guide gives you the shortest operator journey and the checks worth showing in a pilot.

## The workflow

```text
Authenticated caller → n8n webhook → validate inputs
  → Talon establishes an exact refund operation
    → ALLOW             → claim → Talon dispatches to the adapter
    → REQUIRE_APPROVAL  → reviewer decides → n8n polls → claim → Talon dispatches
    → DENY              → stop; no dispatch

Talon's signed lifecycle: decision → review (if any) → attempt → outcome
```

For the reference policy, an amount **up to €50** is allowed; **above €50 through €500** requires approval from the `support-leads` group; **above €500** is denied by company policy. These are example rules, not baked-in Talon refund logic. The currency and decimal-string input shape are enforced by the action schema. n8n never independently decides the thresholds.

The fixture is a counting refund service, **not a payment processor**. A real adapter must check business eligibility, credentials, idempotency and the actual downstream result.

## 1. Register the use case under company policy

[Prepare a Talon installation](add-talon-to-existing-app.md#1-prepare-talon-once), with the company policy, Talon keys and provider configuration kept separately. From the installation directory:

```bash
talon agents add refund-bot --tenant acme --owner support-operations \
  --description "Support refunds requested from the n8n workflow"
```

Save the issued **use-case key** in n8n's credentials; it authorizes this use case's operations but cannot approve them.

Copy or incorporate the reference's company policy and action definition:

```bash
# From the Talon repository root, with the documented installation layout:
cat examples/n8n-refund/use-case-action.append.yaml >> agents/refund-bot/agent.talon.yaml
# Set actions.definitions.create_refund_request.destination.url to your test adapter.
talon validate
talon serve --host 127.0.0.1 --port 8080 --gateway --gateway-config talon.config.yaml
```

Use the [full setup](../../examples/n8n-refund/README.md#set-up) for prerequisites and the specific file layout. If n8n runs elsewhere, expose Talon through a TLS-terminating reverse proxy—not unauthenticated remote HTTP.

## 2. Connect the existing n8n workflow

Import [`refund-approval.workflow.json`](../../examples/n8n-refund/refund-approval.workflow.json) into n8n. Configure its two **Header Auth** credentials:

- **Refund webhook caller:** a shared secret required to trigger the n8n webhook.
- **Talon refund-bot key:** `Authorization: Bearer <use-case-key>`, used only on Talon requests.

Set `talon_url` in the workflow's Config node and publish it. The export contains **no secrets** and **no refund-adapter destination**; it is Talon that calls the adapter when a valid claim is made.

Use one stable `operation_id` per business action. The reference derives it from the ticket and optional request ID. Do not retry a claim blindly if the network fails during dispatch: read the recorded operation first.

## 3. Add a reviewer, then try the three decisions

Give a person separate authority to approve the held operations:

```bash
talon approver add --name lead-1 --tenant acme --groups support-leads
```

The reviewer uses their own credential—**not** the admin key or the use-case key:

```bash
export TALON_APPROVER_KEY=...   # load securely; do not put this key into the workflow
talon approvals list
talon approvals show <approval-id>
talon approvals approve <approval-id> --reason "customer verified"
# or: talon approvals reject <approval-id> --reason "duplicate"
```

Use the webhook body `{"ticket_id":"T-1","amount":"30.00","currency":"EUR"}` for **ALLOW**; `"75.00"` for **REQUIRE_APPROVAL**; and `"900.00"` for **DENY**. Include the separate webhook caller credential when posting. See the [runnable curl example](../../examples/n8n-refund/README.md#set-up).

**Approval is not execution.** The reviewer decision only authorizes the bound operation; n8n later claims it, and Talon dispatches. A denied, rejected or expired operation produces no dispatch.

## 4. Investigate and verify

```bash
talon agents                 # use cases, state and next steps
talon agents show refund-bot
talon audit verify --operation refund-T-1
talon ui                     # read-only Operations Console
```

The [Operations Console](operations-console.md) shows the use case, readiness findings, effective policy, operations, approvals and evidence. Review decisions remain in the CLI or reviewer API; the console does not approve or execute actions.

The example's live test checks the adapter's **own invocation counter** as well as the signed lifecycle. The expected result is one adapter call on an allowed or approved claim, zero on a denied or still-pending operation, and no additional call on replay.

For unknown outcomes, inspect the operation and reconcile with the downstream system before acting. After restoring a backup, Action Gateway dispatch remains held until [recovery reconciliation](single-node-production.md) is completed.

## Run it as a production pilot

For the full installation-to-second-use-case journey, use the [production pilot runbook](production-pilot.md). For the complete importable workflow, example files, test harness and state table, use the [n8n Action Gateway reference](../../examples/n8n-refund/README.md).

**Boundary:** The HTTP Action Gateway governs exactly the actions sent through it. MCP-proxied tools have their own permission enforcement but do not inherit the HTTP Action Gateway's bound approval and claim lifecycle. Neither path controls direct tool or business API calls that bypass Talon.