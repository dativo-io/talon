# Talon object model

This page defines the canonical objects Talon uses to operate AI use cases and the boundaries between their lifecycles. It is the vocabulary contract for the CLI, APIs, documentation, shared projections and the active approval/action roadmap.

Talon deliberately keeps these objects separate. A session is not a generic workflow state machine, an approval is not an execution attempt, and evidence is not mutable operational state.

## Relationship overview

```text
organization baseline
        |
        v
agent / AI use case
        |
        +--> sessions: correlation, cost and activity timeline
                |
                +--> native runs: Talon-owned executable lifecycle
                |
                +--> logical operations: exact governed side effects
                         |
                         +--> approvals: authorization decisions
                         |
                         +--> execution attempts: transport/business attempts

Every decision and observed/asserted result can append signed evidence.
```

Not every session has a native run. An external system such as n8n may own the workflow lifecycle while using Talon for model governance, action authorization, operation tracking and evidence.

## Agent / AI use case

An **AI use case** is the public product term. An **agent** is the corresponding Talon configuration and CLI object.

One `agent.talon.yaml` represents one operated AI use case and provides:

- Talon traffic identity;
- one explicit policy override over the organization baseline;
- budgets and provider/model constraints;
- a trusted action catalog;
- declared operating metadata and accountable contacts;
- the parent identity for sessions, runs, operations and evidence.

The agent is not an executing process instance. Runtime activity appears in sessions, runs and operations.

## Session

A **session** is the correlation and understanding boundary for related activity through Talon. It supports:

- request and action timelines;
- cost and token rollups;
- retries, fallbacks, denials and policy-intervention summaries;
- links to native runs, logical operations, approvals and evidence;
- operator attention projections.

A session is not a universal workflow lifecycle.

### Session status

The canonical field is named `status`. There is no separate `session.state` field.

A session has exactly two statuses:

```text
open | completed
```

| Status | Meaning |
|---|---|
| `open` | Talon has observed the session and no explicit completion has been recorded. This does not prove that an external workflow is currently executing. |
| `completed` | The lifecycle owner explicitly declared that no more activity is expected for this session. This says nothing about success, failure or approval outcome. |

The only transition is:

```text
open -> completed
completed -> completed
```

Completion is explicit, terminal and idempotent. Talon does not infer completion from inactivity. A completed external session ID cannot be reopened or reused for a new lifecycle; the caller must provide a new session ID.

### Session identity source

`source` records how Talon obtained the session identity:

```text
talon | client_asserted | vendor_asserted
```

This also determines lifecycle ownership:

| Source | Lifecycle owner |
|---|---|
| `talon` | Talon |
| `client_asserted` | external system |
| `vendor_asserted` | external system |

Lifecycle ownership is derived from `source`; Talon does not persist a second redundant owner field.

### Session manager attribution

`managed_by` is optional informational metadata naming the runtime or orchestrator responsible for the broader lifecycle, for example:

```text
talon-native | n8n | claude-code | codex | custom-client | unknown
```

Population rules:

- native Talon uses `talon-native`;
- official adapters use a normalized name such as `n8n`;
- recognized vendor integrations use their normalized adapter name;
- generic gateway clients reuse `X-Talon-Client`;
- the first non-empty manager value wins for the stored session;
- later conflicting claims do not silently rewrite the session manager;
- request-level conflicting claims may still appear in evidence;
- missing attribution is presented as `unknown`.

`managed_by` is attribution only. It does not authenticate the caller, authorize an approver, grant administrative rights or change policy.

### Session attention and failures

A session may require attention while its status remains `open`.

Examples of session-linked attention facts include:

- pending Plan Review or action approvals;
- an unresolved logical operation;
- an unknown downstream outcome requiring reconciliation;
- an unrecovered final provider/request failure.

These are shared projections over canonical run, approval, operation and evidence records. They are not additional session statuses and do not require a generic conditions store.

Provider/request failures are divided into:

- **recovered failures** — a retry or policy-valid fallback later succeeded;
- **unrecovered failures** — all configured retries/fallbacks were exhausted and the final request failed.

Recovered failures remain visible but do not trigger the fleet failure signal. Unrecovered final failures contribute to the evidence-derived `sessions_with_recent_failures` metric.

Policy denials, budget denials, approval rejection and inactivity are not classified as failed sessions.

## Native run

A **run** is a Talon-owned executable lifecycle created by the native runtime. Because Talon owns and observes this lifecycle, the run may have authoritative statuses such as:

```text
running
waiting_for_plan_approval
waiting_for_action_approval
executing
completed
failed
timed_out
cancelled
```

The exact run state machine is defined by the native runtime contract. Durable checkpoints must survive restart.

Run status is separate from session status:

- a run can wait for approval while its session remains open;
- a run can fail while the session remains open for further activity or explicit closure;
- completing a run does not redefine session completion as success.

## Logical operation

A **logical operation** is one exact governed side effect, such as creating a refund request with a bound ticket, amount and currency.

An operation owns:

- stable `operation_id`;
- exact action and normalized payload digest;
- policy/action-catalog binding;
- linked approval when required;
- one or more execution attempts;
- final or unknown outcome;
- downstream idempotency identity;
- observed versus client-asserted result provenance.

Canonical operation statuses are separate from approval decisions:

```text
awaiting_approval | authorized | executing | succeeded | failed | unknown | cancelled
```

One approval authorizes one unchanged logical operation, not an arbitrary later request and not one transport attempt. Reusing an operation ID with changed bound input is a conflict.

An operation failure or unknown outcome does not automatically complete or fail the enclosing session.

## Approval

An **approval** is an authorization decision over one immutable subject:

- a specific native plan version; or
- one exact logical operation.

Canonical approval decision statuses are:

```text
pending | approved | rejected | expired | cancelled | invalidated
```

Approval status is not execution status:

- approval permits an exact operation to proceed;
- it does not prove that execution started or succeeded;
- a plan approval never pre-authorizes later side effects;
- `DENY` cannot be overridden by an approval.

Pending approval is presented as human attention linked to the session, run or operation. It never becomes `session.status = pending_approval`.

## Execution attempt

An **execution attempt** is one transport or business-system attempt under a logical operation.

Typical attempt states are:

```text
started | succeeded | failed | unknown
```

Multiple failed transport attempts may occur under one approved logical operation when retries are safe and the operation identity/payload remain unchanged. A successful logical operation is permanently closed. An unknown outcome blocks automatic retry until reconciled.

## Evidence

**Evidence** is the signed record of a Talon decision, transition or observed/asserted result. It is the proof layer under the operational objects, not their mutable source of workflow commands.

Evidence should make provenance explicit:

- `talon_observed` for events Talon directly observed at its boundary;
- `client_asserted` or equivalent for outcomes reported by an external runtime;
- session identity source and client attribution where relevant.

External silence, stopped polling or inactivity is not evidence that the external orchestrator failed.

HMAC signatures make evidence tamper-evident and verifiable; they do not make storage immutable.

## Operator projection

CLI, API, dashboard and reviewer surfaces must consume one shared projection and keep object statuses separate.

Example session view:

```text
Session:              refund-workflow-8912
Status:               Open
Managed by:           n8n (external)
Identity source:      Client asserted
Last activity:        12 minutes ago
Attention required:   Yes
Pending approvals:    1
Waiting on:            create_refund_request
Recovered failures:   2
Unrecovered failures: 1
Last issue:           Provider attempts exhausted
Requests:             8
Cost:                 $0.014
```

The linked operation and approval views then show their own canonical statuses and exact authorization/execution facts.

## Integration rules

### Native Talon

- creates `source = talon` sessions;
- uses `managed_by = talon-native`;
- owns run lifecycle and checkpoints;
- may explicitly complete the session according to the native lifecycle contract.

### External workflows and adapters

- provide or persist a stable external session ID;
- identify the manager using `X-Talon-Client` or an official normalized adapter value;
- own their workflow waiting and resumption;
- explicitly complete the session when the external lifecycle is definitively finished;
- use a new session ID for a new lifecycle;
- keep `operation_id` separate from session, trace, run and tool-call identifiers;
- report outcomes with honest client-asserted provenance;
- never rely on inactivity or stopped polling as a failure signal.

### Provider/model failures

- individual failures remain request/evidence facts;
- retry/fallback recovery is visible;
- only an unrecovered final request failure contributes to session/fleet failure attention;
- provider failure does not automatically close the session.

### Upstream action failures

- Talon-observed connection/transport failures belong to operation attempts and evidence;
- downstream `unknown` outcome remains an operation state requiring reconciliation;
- external workflow failure reports remain client-asserted;
- operation outcomes do not redefine session status.

## Design constraints

To keep Talon lightweight:

- no generic workflow engine;
- no universal conditions framework for sessions;
- no inferred session timeout from inactivity;
- no automatic session generations;
- no duplication of run/operation/approval statuses onto sessions;
- no policy or authorization decisions based on `managed_by`;
- no claim of control over activity that bypasses Talon gateways/adapters.

See also:

- [Talon as a control plane](../explanation/control-plane.md)
- [Operational control plane](operational-control-plane.md)
- [Evidence integrity specification](evidence-integrity-spec.md)
- [Limitations](../../LIMITATIONS.md)
- GitHub issues [#401](https://github.com/dativo-io/talon/issues/401), [#424](https://github.com/dativo-io/talon/issues/424), [#426](https://github.com/dativo-io/talon/issues/426), [#430](https://github.com/dativo-io/talon/issues/430) and [#434](https://github.com/dativo-io/talon/issues/434)
