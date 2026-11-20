# n8n Action Gateway reference

**Keep your existing automation. Put consequential actions behind your company's Talon policy.**

You run a workflow in n8n that does something that matters to the business: a refund, a deletion, a deployment. This reference shows how to keep the workflow and route that one action through Talon, so that the company's policy decides it, a person approves it where the policy says so, Talon performs it, and signed evidence records what happened.

It is one importable workflow, `refund-approval.workflow.json`, built from stock n8n nodes only (Webhook 2, Edit Fields 3.4, HTTP Request 4.2, Switch 3.2, Wait 1.1, Respond to Webhook 1.1).

The refund is a fixture. The action is `create_refund_request` and the "refund service" is a deterministic endpoint that counts its calls. There is no model call, no Shopify connector, no payment credential and no business eligibility logic here. The pattern is the generic Talon Action Gateway and applies to any action ([reuse it](#reuse-the-pattern-for-another-action)).

| If you want | Go to |
|---|---|
| The generic contract, an importable workflow and its proof | this directory |
| A recognizable customer-support journey with order context and a buyer narrative | `dativo-io/talon-full-demo` |
| A polished template to install from the n8n community | not published yet ([handoff contract](#handoff-to-a-community-template)) |

## Who does what

| n8n (your workflow) | Talon | Your business adapter |
|---|---|---|
| receives the trigger and authenticates its caller | identifies the AI use case by its key | decides business eligibility |
| validates the input shape | holds the trusted action definition and its schema | authenticates and authorizes in the business system |
| maps business data to the action's arguments | applies the company policy and the use case's rules | holds the external system's credentials |
| keeps the stable operation identifier | binds a human approval to the exact operation | provides native idempotency and reconciliation |
| waits for approval and branches on Talon's answers | keeps the durable operation state | produces the actual business outcome |
| reports the outcome to its caller | **calls the business adapter itself** and signs the evidence | |

**n8n never calls the business adapter.** The workflow export contains no address of it. When Talon denies, or cannot be reached, nothing is dispatched: there is no fallback path.

## What happens

```
POST /webhook/talon-refund  {ticket_id, amount, currency, request_id?}      caller credential required
  → Validate request        ticket_id like ABC-123, amount a decimal STRING ("75.00"), 3-letter currency
       invalid              → 400 invalid_request            (nothing is sent to Talon)
  → Talon: establish        operation_id = refund-<ticket_id>[-<request_id>]
  → Talon's verdict         read only from a successful answer that carries exactly this operation
       ALLOW                → Talon: claim → Talon dispatches
       REQUIRE_APPROVAL     → wait 5 s → read the operation
                                authorized                    → Talon: claim → Talon dispatches
                                still pending, not expired    → wait again
                                rejected / expired / changed  → 409 not_approved
       DENY                 → 403 denied
       anything else        → 409 not_authorized             (conflict, schema refusal, error, malformed answer)
  → Outcome of the claim    succeeded → 200 refunded · unknown → 202 unknown · otherwise → 409 not_completed
```

| Answer | Was the action dispatched? |
|---|---|
| `400 invalid_request`, `403 denied`, `409 not_approved`, `409 not_authorized` | **No.** Decided before any claim. |
| `200 refunded` | **Yes, once.** A repeated request for the same operation gets the same answer from Talon's record, with no second dispatch. |
| `202 unknown` | **Unknown.** Talon dispatched and could not observe the result. It may have happened. Do not retry; reconcile with the business system. Repeating the request reports `unknown` again and dispatches nothing. |
| `409 not_completed` | **Read the operation.** The claim was refused or failed; `talon_code` says why (for example `attempt_already_in_progress` when another run is claiming the same operation). |
| The run fails (HTTP 500 from n8n) | **Before the claim: no.** Talon was unreachable, nothing was dispatched. **During the claim: unknown.** A connection that breaks while the claim is in flight does not show that nothing was executed. Read the operation (`GET /v1/action-operations/<operation_id>` with the use case's key) or send the same request again: Talon answers from its record. |

Talon dispatches an authorized operation at most once. That is not "exactly once" in the business system: if you need that, the business adapter must provide it (Talon sends an `Idempotency-Key` with every dispatch).

## The example policy

Two layers, in two files. The values are examples, not built-in rules; Talon has no notion of a refund or a currency.

| Amount (EUR) | Decision | Where the rule lives |
|---|---|---|
| at or below 50.00 | allow | no rule matches |
| above 50.00, at or below 500.00 | approval by `support-leads` | the use case's file (`use-case-action.append.yaml`) |
| above 500.00 | deny | the company's configuration (`talon.config.yaml`) |

- The **company rule cannot be relaxed** from the use case's file. A use case can add rules and loosen its own; `TestN8nRefundWorkflow_ExamplePolicyCompiles` loosens the use case's rule and shows that 500.01 is still denied by the company.
- What an amount may look like (a decimal string with at most two fractional digits) and which currency is accepted (`EUR`) belong to the action's trusted `input_schema`, which Talon enforces before any policy decision.
- The thresholds are not copied into the workflow. n8n branches on Talon's answer only.

## Set up

Works with a Talon build that contains the Action Gateway, argument rules, `talon approvals` and `talon agents add` (all on `main`; see [what was tested](#what-was-tested)). Run the `talon` commands on the host of the installation, with its keys loaded ([how to prepare an installation](../../docs/guides/add-talon-to-existing-app.md#1-prepare-talon-once)).

**1. The company configuration.** Copy `talon.config.yaml` next to your installation, or add its `organization_policy` block to yours.

**2. Register the AI use case.** The command issues the use case's Talon key once; store it in n8n in step 6.

```bash
talon agents add refund-bot --tenant acme --owner support-operations \
  --description "Support refunds requested from the n8n workflow"
```

**3. Give it the action.** Append the example's fragment to the file the registration wrote, set the destination to your business adapter, and validate:

```bash
cat examples/n8n-refund/use-case-action.append.yaml >> agents/refund-bot/agent.talon.yaml
# edit agents/refund-bot/agent.talon.yaml: actions.definitions.create_refund_request.destination.url
talon validate
```

**4. Start Talon** on the machine only, and look at the use case:

```bash
talon serve --host 127.0.0.1 --port 8080 --gateway --gateway-config talon.config.yaml
talon agents show refund-bot
```

Registered is not connected. Before `talon serve` runs the view reads `Not active`; with Talon running and nothing sent yet it reads `Waiting for its first request`. For n8n on another machine, put a TLS-terminating proxy in front of Talon ([guide](../../docs/guides/add-talon-to-existing-app.md#when-the-application-runs-on-another-machine)).

**5. Create a reviewer.** A separate identity with its own credential, shown once:

```bash
talon approver add --name lead-1 --tenant acme --groups support-leads
```

**6. Configure n8n** (Credentials → New → Header Auth). The values stay in n8n's encrypted credential store; the workflow export references them by name and carries no key.

- `Talon refund-bot key`: header `Authorization`, value `Bearer <the Talon key from step 2>`.
- `Refund webhook caller`: a header name and a secret you choose (for example `X-Refund-Caller`). Whoever calls the webhook must present it.

Import `refund-approval.workflow.json`, select the two credentials on the Webhook and on the three Talon nodes, set `talon_url` in the **Config** node to the address at which n8n reaches Talon, and publish the workflow.

**7. Send a request**, and look again:

```bash
curl -sS -X POST "$N8N_URL/webhook/talon-refund" -H 'Content-Type: application/json' \
  -H "X-Refund-Caller: $CALLER_SECRET" -d '{"ticket_id":"T-1","amount":"30.00","currency":"EUR"}'
talon agents show refund-bot
```

### Four identities, kept apart

| Identity | Who holds it | What it can do |
|---|---|---|
| Webhook caller secret | whatever calls the workflow | start a workflow run. Talon never sees it |
| Talon use-case key (`talon_uc_…`) | n8n's credential store | establish, read and claim this use case's operations. **It cannot approve** |
| Reviewer credential (`talon_appr_…`) | a person | decide approvals of their tenant and groups. It cannot establish or claim |
| Talon admin key | the operator | administer Talon. It cannot approve either |

Who asked for the refund is whatever your application put into the request. Talon authenticates the use case, not that person.

### The reviewer's part

A request above 50.00 waits. The reviewer works on their own machine with their own credential, which is read from the environment and never accepted as a flag:

```bash
export TALON_APPROVER_KEY=...            # the reviewer's credential
talon approvals list                     # what needs a decision
talon approvals show <approval-id>       # the exact action and arguments, why approval is required
talon approvals approve <approval-id> --reason "customer verified"
talon approvals reject  <approval-id> --reason "duplicate"
```

Add `--url <talon address>` when Talon does not listen on `http://localhost:8080`. A decision dispatches nothing. The waiting workflow reads the operation, sees that it is authorized and claims it; only that claim makes Talon call the business adapter. The Operations Console shows approvals read-only; decisions are made with the CLI or the reviewer API.

## Operation identity

The workflow derives the operation id from business data, and never invents one:

- `refund-<ticket_id>` when the request carries no `request_id`: one refund per ticket;
- `refund-<ticket_id>-<request_id>` when it does: `request_id` is an identifier your application issues for one business request (1 to 64 letters, digits, `_` or `-`), so that a ticket can have more than one legitimate refund.

This mapping belongs to the example. Talon's rule is only that an operation id names one exact operation. What follows from it:

| Situation | Result |
|---|---|
| A transport retry with the same ids | the same operation: Talon answers from its record, no second dispatch |
| A genuinely new business request (a new `request_id`) | a new operation, decided on its own |
| Changed arguments under an existing id | `operation_conflict`: `409 not_authorized`, nothing dispatched |
| A denied request sent again under another id | denied again: the policy decides on the arguments, not on the id |
| An `unknown` result, same request again | `unknown` again, nothing dispatched |
| Ids with other characters | `400 invalid_request` before Talon; ids are URL-encoded in request paths |

**Your application must persist the `request_id` and reuse it on a retry.** Talon cannot tell that two different ids describe the same business refund. A caller that answers an `unknown` result by sending a new `request_id` asks for a new operation, and Talon will decide it as one. Keeping that from happening is the caller's job, and making it harmless is the business adapter's (native idempotency on a business key).

## Operation states

What Talon records for an operation (`operation_status`), and what the workflow does with it:

| State | Meaning | The workflow answers |
|---|---|---|
| `denied` | denied before any dispatch | `403 denied` |
| `awaiting_approval` | a reviewer has not decided yet | keeps waiting until the approval's expiry |
| `cancelled` (approval `rejected`, `expired` or `invalidated`) | not approved; nothing was dispatched | `409 not_approved` |
| `authorized` | allowed, or approved; not yet claimed | claims it |
| `executing` | an attempt is in progress | `409 not_completed` for a second claimant |
| `succeeded` | Talon dispatched and observed the declared success | `200 refunded` |
| `failed` | Talon dispatched and observed a failure | `409 not_completed` |
| `unknown` | Talon dispatched and could not observe the result: it may have happened | `202 unknown`, never retried |

## Verify what happened

Count the calls in the business system itself; n8n's execution log is not proof. Then:

```bash
talon audit verify --operation refund-T-1     # the signed lifecycle: verdict, approval, dispatch, outcome
talon agents show refund-bot                  # the use case: whether Talon serves it, and its newest operation record
```

For a use case whose requests are Action Gateway operations, `talon agents show` names the newest operation record under `Last request`. Two things in that view are not about operations yet: the `Traffic` line counts LLM gateway requests, and the status reads `Needs attention` after a claim, because a claim record carries the policy the operation was bound to, not a policy evaluated for that event. The lifecycle check above is the proof for an operation.

## What was tested

`N8N_BIN=<n8n 2.48.5> scripts/n8n-refund-live.sh` imports this exact workflow into a real n8n **2.48.5**, publishes it and runs it against a real `talon serve` and the counting refund service. The installation is set up with the commands of this page (`talon agents add`, the appended fragment, `talon approver add`, `talon approvals`). The CI workflow `n8n refund live` runs the same script. Each line is checked against the refund service's own counter:

- import and publication; the use case registered (`Not active`), loaded (`Waiting for its first request`), and its newest operation record named by `talon agents show`;
- ingress: an unauthenticated and a wrongly authenticated caller; a malformed or missing ticket id, amount, currency and `request_id`: refused before Talon. A currency outside the action's schema: refused by Talon. Zero dispatch;
- allow: 30.00 and the boundary 50.00: one dispatch each;
- approval: 50.01, 75.00 and the boundary 500.00: zero dispatch until a reviewer approves with `talon approvals`, then one each;
- deny: 500.01 (by the company's rule) and 900.00, also under another id: zero dispatch;
- the use case's key and the admin key cannot decide an approval;
- rejection and expiry: zero dispatch;
- changed arguments under an existing operation: conflict, zero dispatch; exact replay: no further dispatch;
- two operations on one ticket with stable `request_id`s; four concurrent identical requests: one dispatch;
- Talon unreachable before the operation exists: the run fails, zero dispatch;
- the connection to Talon lost during the claim: the run fails, Talon's record says `succeeded`, the same request again reports the recorded refund, no second dispatch;
- the refund service accepts the request and loses its answer: `unknown`, never retried;
- every call the refund service received carried Talon's idempotency key; the workflow export names no refund service; every lifecycle verifies with `talon audit verify --operation`.

| Level | Status |
|---|---|
| Source-built Talon (this repository's `main` plus this change) with n8n 2.48.5 | tested by the script above |
| A Talon release candidate | **not run**: `v1.17.0-rc.1` predates part of what this page uses and is no proof for it |
| A published stable Talon release | **not run**: the latest stable, v1.16.1, does not contain argument rules, `talon approvals` or `talon agents add` |
| Other n8n releases, n8n Cloud, queue mode with several workers, a load test | **not run**. n8n 2.48.5 is the only tested release; do not assume that the workflow JSON imports unchanged elsewhere |

## Reuse the pattern for another action

The workflow is **establish → read the verdict → wait for a decision → claim → read the outcome**. To apply it to another action:

1. Define the action in Talon: its closed input schema, the fields a reviewer is shown, the destination and the success contract.
2. Put what the company requires into `gateway.organization_policy` and what the use case adds into its file, with `argument_rules`. Keep business eligibility in the business system.
3. In `generate-workflow.py`, change the action name, the validated argument mapping and the operation-id mapping; regenerate the JSON; run `go test ./tests -run N8nRefundWorkflow` and the live script. Do not copy thresholds into n8n branches.
4. Keep every dispatch behind Talon's claim. No direct call from n8n to the destination.
5. Report states truthfully; treat a failure during a claim as "may have happened".

Talon's HTTP dispatcher forwards the canonical JSON to one fixed destination with idempotency headers. It is not a SaaS authentication, GraphQL or domain-validation adapter: a system such as Shopify needs its own secured adapter, outside Talon core and outside the workflow.

## Handoff to a community template

A standalone template repository (`dativo-io/talon-n8n-templates`, not created yet) can take this reference as its contract:

| It takes from here | It adds |
|---|---|
| the node sequence and the answer-validation expressions of `generate-workflow.py` | community naming, descriptions and sticky notes |
| the credential types and names (two Header Auth credentials), the `Config` node | setup instructions for n8n users, example inputs |
| the tested n8n release (2.48.5) and the live script as its acceptance | its own version-compatibility matrix and Creator Hub assets |
| the answer table, the operation states and the identity rules of this page | distribution |

It must keep: no key in the export, no call to the business adapter from n8n, no threshold in n8n, no retry of a claim, answers read only from the exact requested operation.

## Boundaries

- **What Talon shows:** what it decided and what it dispatched. It does not see what n8n did with an answer, or anything n8n does outside these nodes.
- **Waiting:** the Wait node polls every 5 seconds until the approval's own expiry; the workflow's `executionTimeout` (1 h) is a second bound.
- **Effects:** the fixture returns HTTP 201 and performs no payment. A real adapter must validate identity, eligibility and refundable balance, be idempotent, and expose a success contract that reflects the business effect.
- **Ownership:** Talon OSS owns this contract and fixture. `talon-full-demo` owns the business journey and its presentations. The template repository will own community distribution.
