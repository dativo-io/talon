# MCP governance extension (`io.dativo.talon/governance`)

**Status:** shipped (#372) on the governed `POST /mcp` (MCP protocol `2026-07-28`); since #431 every governed `tools/call` is an Action Gateway operation and the extension carries its identifiers. The extension is the stable, versioned way Talon tells an MCP client *what governance decided* and *where the signed proof is*. Everything else about the response stays standards-native: JSON-RPC error numbers, `resultType`, MRTR fields and the Tasks extension are MCP's, not Talon's.

Architecture context: [Control-plane boundaries §10](control-plane-boundaries.md#10-mcp-2026-07-28-boundary); usage: [governed MCP tools](../guides/mcp-governed-tools.md). Tasks continuation is [#448](https://github.com/dativo-io/talon/issues/448). This page documents what is emitted and which codes are reserved.

## Identity and versioning

| | |
|---|---|
| Extension id | `io.dativo.talon/governance` (reverse-DNS, MCP `_meta`/extension key grammar) |
| Schema version | `1` (`schemaVersion` field). Additive fields may appear within a version; a semantic change is a new version. |
| Advertised | `server/discover` → `capabilities.extensions["io.dativo.talon/governance"] = {"schemaVersion": 1}`. No other extension is advertised; in particular not `io.modelcontextprotocol/tasks`. |
| Client capability | None required. Client `_meta` never grants authority; unknown client extension fields are ignored. |

## Placement

| Outcome | Where the object travels | JSON-RPC outer shape |
|---|---|---|
| Governance denial or Talon-shaped failure (incl. an action outcome: `policy_denied`, `approval_pending` on execute, `operation_conflict`, `operation_already_succeeded`, `upstream_outcome_unknown`, `recovery_hold`, …) | `error.data["io.dativo.talon/governance"]` | `error.code` `-32000`, HTTP 200 (application outcome on an accepted request) |
| Prepared operation (first call of the two-call flow) | `result._meta["io.dativo.talon/governance"]` with `code: operation_prepared` (or `approval_pending`), `decision: pending`, `provenance: not_dispatched`, `operationId`, `approvalId` | a normal `resultType: "complete"` result with `isError: false`, a text block and `structuredContent` (`operationId`, `status`, `next`) |
| Executed call | `result._meta["io.dativo.talon/governance"]` with `decision: "allow"`, `provenance: observed`, `operationId`, `attemptId` | the source's `resultType: "complete"` result |
| Protocol failure (parse, invalid params, unknown method, unsupported version, `-32020` header/body mismatch, missing `_meta`, malformed attribution header, unknown tool, schema violation) | **absent** | the MCP-defined error; HTTP 4xx. No governance evidence is written: nothing trustworthy was evaluated. |

The deprecated flat alias `error.data.talon_code` (`TALON_*`, #369) is still emitted next to the extension for codes that had one, for one release. New integrations should key on the extension; the alias will be removed.

## Object

```json
{
  "schemaVersion": 1,
  "code": "policy_denied",
  "decision": "deny",
  "reasonCode": "ACTION_POLICY_DENIED",
  "retryable": false,
  "evidence": { "id": "req_3f9a1c2b", "committed": true }
}
```

| Field | Meaning |
|---|---|
| `code` | Stable governance code from the registry below; the integration contract. `allowed` on an allowed result. |
| `decision` | `allow`, `deny`, `pending`, `failed` or `unknown`: the class of the outcome. |
| `reasonCode` | The **signed record's actual primary explanation code** whenever an evidence reference is present (e.g. `POLICY_DENIED_TOOL` for a proxy denial, `POLICY_ALLOWED` for an allowed call, `EXECUTION_FAILED` for a fail-closed evaluation failure, `EXECUTION_OUTCOME_UNKNOWN` for an unknown outcome). Without a record (no commit happened) it is the registry's default category for the code. The in-band reason therefore never disagrees with what was signed; `TestGovernance_ReasonCodeMatchesSignedExplanation` pins it. |
| `retryable` | Conservative: `true` only when the same request may legitimately be repeated without a human or operator change. Denials are never retryable; `unknown` outcomes block automatic retry. |
| `retryAfterMs` | Optional poll or back-off hint. |
| `operationId`, `operationRef`, `approvalId`, `attemptId`, `taskId` | Scoped resource locators when the outcome belongs to a logical operation. They are never bearer authorization and never replace each other (a Task id is not an operation id). Emitted on every governed call (#431); `taskId` is reserved for #448. |
| `evidence` | Reference to the signed record, see below. |
| `generation` | Short runtime-generation identity the decision was made against. |
| `provenance` | What Talon knows about the effect: `not_dispatched` for every pre-dispatch outcome, `unknown` for an `unknown`-class outcome, `observed` otherwise (an allowed call was authorized and answered; this does not by itself prove a downstream business effect succeeded). `client_asserted` and `reconciled` arrive with #434/#146. |
| `remediation` | One bounded sentence. |

Bounds: identifiers are at most 256 bytes, printable and whitespace-free; `remediation` at most 512 bytes. An object that violates its bounds, carries an unregistered code or an evidence id without `committed: true` is refused at serialization: Talon cannot emit an out-of-contract object.

Never present: raw or protected action payload, credentials or secret values, approver group or member internals, caller-provided reviewer authority, raw upstream bodies, stacks or paths, an evidence HMAC or signature fragment, or any reference that acts as bearer authorization.

## Evidence reference

```json
"evidence": { "id": "proxy_8b1e4d20", "committed": true }
```

- `id` appears **only after the complete signed record committed**. For a pre-dispatch outcome (denial, PII block, scanner outage, policy evaluation failure, credential unavailable, outbound request invalid) the record commits before the response; if it cannot — a failed write, **or a route configured without an evidence store** — the response is `evidence_commit_failed`, no id is fabricated, and nothing was dispatched. A governance failure that was never evidenced can never pass as a plain refusal.
- `committed: true` means Talon accepted the signed record. It is not a completeness, append-only or immutability claim.
- `committed: false` without an id appears on post-dispatch outcomes whose record could not be stored (the effect already happened and must not be relabelled).
- The reference is a locator, not proof. Cryptographic verification requires the complete canonical record: `talon audit verify <id>` (or `talon audit verify --operation <operation_id>` for an action lifecycle). Knowing an id grants no authority; retrieval stays tenant-scoped.

## Code registry

The registry is one Go package, `internal/govcode`, shared by the Action Gateway HTTP envelope (`error.code`, `operation.outcome_code`), the MCP extension and the LLM gateway [error contract](error-contract.md). Existing spellings were kept canonical; #372 added the codes nothing had a name for.

| Code | Decision | Retryable | Emitted by today |
|---|---|---|---|
| `policy_denied` | deny | no | Action Gateway DENY, over HTTP and on governed `/mcp` (a forbidden tool called directly, a company or use-case rule) |
| `pii_policy_violation` | deny | no | `/mcp` PII block (arguments before binding, or a withheld result), residual PII after redaction, invalid redaction output; LLM gateway |
| `scanner_unavailable` | failed | yes | `/mcp` scan engine unavailable or unverifiable (fail-closed); LLM gateway |
| `policy_evaluation_failed` | failed | yes | not emitted by `/mcp` since #431 (governed calls are decided by the Action Gateway); kept registered |
| `upstream_auth_unavailable` | failed | yes | `/mcp` execute: the source's vault credential unavailable before dispatch (zero upstream call; the operation can be executed again) |
| `upstream_tool_failed` | failed | no | `/mcp` execute: the request was not sent (source unreachable, outbound request invalid); the operation can be executed again |
| `upstream_outcome_unknown` | unknown | no | `/mcp` execute after the request was written: `isError`, a JSON-RPC error, `input_required`, a task, a lost, malformed or id-mismatched answer, a timeout. Operation `unknown`, never retried |
| `evidence_commit_failed` | failed | yes | `/mcp` when the adapter's own pre-binding record (PII refusal or redaction) cannot commit |
| `approval_required`, `approval_pending`, `approval_rejected`, `approval_expired`, `approval_not_authorized`, `approval_already_decided`, `approval_binding_stale`, `operation_id_required`, `operation_conflict`, `operation_already_succeeded`, `operation_outcome_unknown`, `attempt_already_in_progress`, `attempt_not_authorized`, `action_not_found`, `action_schema_invalid`, `payload_unavailable`, `recovery_hold`, `execution_unsupported`, `not_found`, `invalid_request`, `store_unavailable`, `generation_changed`, `agent_identity_required` | per code | per code | Action Gateway HTTP ([Action Gateway](action-gateway.md)) and governed `/mcp` (#431) |
| `operation_prepared` | pending | no | governed `/mcp`: the first call of the two-call flow prepared the operation; nothing was executed (#431) |
| `model_not_allowed`, `provider_not_allowed`, `budget_exceeded`, `session_budget_exceeded`, `budget_unavailable`, `pricing_unavailable`, `data_tier_exceeded`, `tool_policy_violation`, `egress_tier_destination_disallowed`, `egress_destination_disallowed`, `rate_limited`, `workload_identity_required`, `workload_identity_unbound`, `destination_not_governed`, `agent_disabled`, `model_required_for_policy_evaluation` | per code | per code | LLM gateway and delegated path ([error contract](error-contract.md)) |
| `approval_requires_tasks` | failed (unsupported) | no | **reserved** (#448): asynchronous approval needed and the current request does not advertise Tasks; honest non-execution, zero dispatch, request not held open, no hidden continuation |
| `approval_cancelled`, `approval_invalidated` | deny | no | **reserved** (#426 typed approval kernel); today an invalidated approval is reported as `approval_binding_stale` |
| `unsupported_runtime_posture` | failed (unsupported) | no | **reserved** (#431) |

`go test ./internal/govcode/ ./internal/action/ ./internal/gateway/ -run 'Registry|Govcode|RegisteredInGovcode'` proves the registry is complete, deduplicated, conservative on retryability, and that every action-domain and gateway code is registered under its canonical spelling.

## Known failure versus unknown outcome

Talon labels an effect **failed** only when it knows the request never left Talon; after the request was written, anything but a trustworthy success is **unknown**:

| Situation | Code | Operation | Why |
|---|---|---|---|
| credential unavailable, source unreachable, outbound request invalid (nothing written) | `upstream_auth_unavailable` / `upstream_tool_failed` (provenance `not_dispatched`) | `failed`, executable again under the same idempotency identity | nothing was handed to the transport |
| a complete result without `isError` | `allowed` (provenance `observed`) | `succeeded` | the source's success contract |
| `isError: true`, a JSON-RPC error, `input_required`, a task, a malformed, id-mismatched or lost answer, a timeout after send | `upstream_outcome_unknown` (provenance `unknown`, not retryable) | `unknown` | the source may have performed part of the effect; an answer Talon cannot trust proves nothing |
| a later execute of an unknown operation | `operation_outcome_unknown` | unchanged | `unknown` blocks retry until reconciliation |

Talon never re-sends on the client's behalf. The signed lifecycle record says the same: an unknown attempt is `ACTION_ATTEMPT_UNKNOWN`. `TestMCPDispatcher_UnknownOutcomes`, `TestMCPAction_UnknownBlocksEveryRetry` and `TestGoverned_UpstreamErrorAfterDispatchIsUnknownAndNeverRetried` pin it.

## Untrusted text: evidence stores tokens, never free text

**Untrusted fields.** A vendor's JSON-RPC error message and `data`, a tool's `isError` content, and every Go error from the transport or upstream decoding.

**Talon-authored public messages** are fixed strings per outcome; no untrusted text is echoed into them. The only protocol messages that carry caller-derived text are the `-32602` invalid-params answers (the caller's own tool name or schema error, sanitized and bounded); they write no evidence.

**Signed records never receive vendor text.** A governed call's lifecycle record keeps the outcome code only: `mcp_result_complete`, `upstream_tool_error`, `upstream_jsonrpc_error: code=<n> category=<c>` (`<c>` ∈ `parse_error`, `invalid_request`, `method_not_found`, `invalid_params`, `internal_error`, `server_error`, `vendor_defined`), `upstream_result_type_unsupported`, `upstream_input_required_unsupported`, `upstream_response_invalid`, `upstream_http_status`, `dispatch_response_lost`, `dispatch_timeout_after_send`, `dispatch_redirect_refused`, `dispatch_credential_unavailable`, `dispatch_transport_error`. The vendor's text is not logged either: the operator log line `mcp_action_outcome_unknown` carries the operation id, the action, the outcome code and the digest of what the source answered (`result_ref`), because no generic sanitizer reliably removes personal data or secrets from free text. Policy reasons are the Action Gateway's own (rule identity, never argument values). The adapter's own PII records keep structured triggers (`request_pii_blocked`, `request_pii_redacted`, `output_pii_blocked`, `output_pii_redacted`, scanner failure kinds) and digests, never values.

## Canonical resolution precedes governance

A `tools/call` for a name that is not a governed action of the authenticated use case is the spec's invalid-params protocol error (HTTP 400, `-32602`): no governance extension, no signed record, zero execution. The same holds for arguments that violate the closed schema and malformed arguments. A **forbidden** tool is resolvable (it is in the catalog, only hidden from `tools/list`): called directly, the Action Gateway denies it with a committed record and zero calls. `TestGoverned_RequestFaults` and `TestGoverned_ForbiddenToolCalledDirectlyIsDeniedWithZeroCalls` pin this.

## Protocol errors are not policy decisions

A request that fails the wire gate (#447) never receives the extension and never produces governance evidence: `-32700` parse, `-32600` invalid request, `-32601` method not found, `-32602` invalid params (including `meta_missing`/`meta_invalid` and `Mcp-Param-*` parse failures), `-32022` unsupported protocol version, `-32020` header/body mismatch. `tests: internal/mcp TestGovernance_ProtocolErrorsCarryNoExtension`, `TestProxyForwarding_IntegrityFailuresNeverReachUpstream`.

## MRTR and Tasks

An authorized governed action is executed as one `tools/call`; a source that answers `resultType: "input_required"` (MRTR) cannot continue it through an elicitation round-trip, so the outcome is `unknown`. The Tasks extension is not advertised, and an upstream `resultType: "task"` is `unknown` too, until #448 ships. Approval continuation does not need Tasks: the client executes the prepared operation with `talon_execute_operation` after the decision; nothing is held open and nothing dispatches in the background. `approval_requires_tasks` stays reserved for #448.

## Parity with the Action Gateway

The same domain outcome carries the same `code` over `POST /v1/action-operations` (HTTP envelope `error.code` / `operation.outcome_code`) and over a governed `tools/call`; both adapters call one in-process action service, so they create and reuse the same operations, approvals and evidence. Only the transport envelope differs.

## Verify

```bash
go test ./internal/govcode/ ./internal/mcp/ ./internal/action/ -run 'Registry|Extension|Governed|MCP'
make test-mcp-smoke test-mcp-governance-smoke      # offline black-box gates against the built binary
# fetch and verify an operation's signed lifecycle
talon audit verify --operation <operation_id>
```
