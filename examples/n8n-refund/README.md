# n8n refund workflow governed by Talon

An importable n8n workflow (`refund-approval.workflow.json`) for one consequential business action, `create_refund_request`. The roles are split:
- **n8n owns the workflow:** it receives the request, waits and responds.
- **Talon owns the decision and the dispatch:** Talon authorizes the exact refund and calls the refund service itself.
- **n8n never calls the refund service.** It only asks Talon to claim an operation that Talon has allowed or a reviewer has approved.

It uses stock n8n nodes only (Webhook 2, HTTP Request 4.2, Switch 3.2, Wait 1.1, Respond to Webhook 1.1, Stop and Error 1). There is no community or custom node.

> **Status:** the workflow's structure and safety properties are checked in Talon's CI (`go test ./tests -run TestN8nRefundWorkflow`). The Talon behaviour it relies on is proven over the real binary (`TestE2E_ActionGateway_AmountBands`). It has **not** been executed inside a running n8n by Talon's CI.

## What happens

```
POST /webhook/talon-refund {ticket_id, amount, currency}
  → Talon: establish operation   operation_id = "refund-<ticket_id>" (one refund per ticket; an n8n retry resumes it)
  → Talon verdict
      ALLOW             → Talon: claim → Talon dispatches the refund → 200 refunded
      REQUIRE_APPROVAL  → wait 1 min → read operation → authorized? → claim → 200 refunded
                                                       still pending? → wait again
                                                       rejected / expired / invalidated → 409 not_approved
      DENY              → 403 denied (nothing dispatched)
      anything else     → Stop and Error (conflict, schema error, auth error; nothing dispatched)
  → Outcome
      succeeded         → 200 refunded
      unknown           → 202 unknown — the refund may or may not have happened; do not retry, reconcile
      anything else     → Stop and Error
```

**When the workflow stops, nothing is refunded:**
- **Talon unreachable:** the HTTP node fails and the workflow stops. There is no fallback path to the refund service.
- **The amount changed under the same ticket:** Talon refuses with `operation_conflict` and the workflow stops. An approval binds the exact arguments.
- **An approval never decided:** the workflow's `executionTimeout` (1 h) ends the polling.

## Set up

1. **Talon side.** Register the use case and its key, then merge the catalog and the amount limits from [`agent.talon.yaml`](agent.talon.yaml) into its file, with your refund service's URL. Add a reviewer.
   ```bash
   talon agents add refund-bot --tenant acme          # prints the key once
   talon approver add --name lead-1 --tenant acme --groups support-leads   # prints the reviewer credential once
   talon validate
   ```
2. **n8n side.**
   - **Environment variable:** set `TALON_URL` (for example `http://talon.internal:8080`) for the n8n process.
   - **Credential:** create a **Header Auth** credential named `Talon refund-bot key`, with header `Authorization` and value `Bearer <the key from talon agents add>`. The key lives in n8n's credential store, never in the workflow JSON.
   - **Import:** import the workflow and select that credential on the three Talon HTTP nodes (the file carries a placeholder credential id).
3. **Reviewer.** Approvals are decided outside n8n with the reviewer's own credential:
   ```bash
   export TALON_APPROVER_KEY=...   # from talon approver add
   talon approvals list
   talon approvals show <approval-id>
   talon approvals approve <approval-id> --reason "customer verified"
   ```

## Check it

| Request | Talon verdict | Refund service calls |
|---|---|---|
| `{"ticket_id":"T-1","amount":"30.00","currency":"EUR"}` | ALLOW | 1 |
| `{"ticket_id":"T-2","amount":"75.00","currency":"EUR"}` | REQUIRE_APPROVAL: 0 until approved, then 1 | 1 after approval |
| `{"ticket_id":"T-3","amount":"900.00","currency":"EUR"}` | DENY | 0 |
| `{"ticket_id":"T-2","amount":"450.00","currency":"EUR"}` (after T-2 was approved) | `operation_conflict` | 0 |

Count the calls on the refund service itself; n8n's own execution log is not proof. Then verify Talon's signed evidence for each operation:

```bash
talon audit verify --operation refund-T-2     # Lifecycle: VALID, with the approval and the observed dispatch
```

## Boundaries

- **What Talon proves:** what it decided and what it dispatched (`talon_forwarded`). It does not see what n8n did with the response, or anything n8n does outside these HTTP nodes.
- **n8n identity:** the n8n credential authenticates the use case `refund-bot`. Per-run identity inside n8n is attribution only.
- **Waiting:** the Wait node polls every minute. Reduce the polling interval in production or move it to a resume webhook; the authorization semantics do not change.
