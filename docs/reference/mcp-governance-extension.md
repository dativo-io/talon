# MCP governance extension (`io.dativo.talon/governance`)

**Status:** shipped (#372) on `POST /mcp` and `POST /mcp/proxy` for MCP protocol `2026-07-28`. The extension is the stable, versioned way Talon tells an MCP client *what governance decided* and *where the signed proof is*. Everything else about the response stays standards-native: JSON-RPC error numbers, `resultType`, MRTR fields and the Tasks extension are MCP's, not Talon's.

Architecture context: [Control-plane boundaries §10](control-plane-boundaries.md#10-mcp-2026-07-28-boundary); the canonical governed MCP adapter over ActionGovernance is [#431](https://github.com/dativo-io/talon/issues/431), and Tasks continuation is [#448](https://github.com/dativo-io/talon/issues/448). This page documents what is emitted today and which codes are reserved for those issues.

## Identity and versioning

| | |
|---|---|
| Extension id | `io.dativo.talon/governance` (reverse-DNS, MCP `_meta`/extension key grammar) |
| Schema version | `1` (`schemaVersion` field). Additive fields may appear within a version; a semantic change is a new version. |
| Advertised | `server/discover` → `capabilities.extensions["io.dativo.talon/governance"] = {"schemaVersion": 1}` on both routes. No other extension is advertised; in particular not `io.modelcontextprotocol/tasks`. |
| Client capability | None required. Client `_meta` never grants authority; unknown client extension fields are ignored. |

## Placement

| Outcome | Where the object travels | JSON-RPC outer shape |
|---|---|---|
| Governance denial or Talon-shaped failure | `error.data["io.dativo.talon/governance"]` | `error.code` `-32000`, HTTP 200 (application outcome on an accepted request) |
| Allowed call | `result._meta["io.dativo.talon/governance"]` with `decision: "allow"` | the normal `resultType: "complete"` (or the relayed `input_required`) result |
| Protocol failure (parse, invalid params, unknown method, unsupported version, `-32020` header/body mismatch, missing `_meta`) | **absent** | the MCP-defined error; HTTP 4xx. No governance evidence is written: nothing trustworthy was evaluated. |
| Upstream (vendor) JSON-RPC error (`/mcp/proxy`, on `tools/call` or the definition capture) | `error.data["io.dativo.talon/governance"]` with `code: upstream_tool_failed`, `decision: failed`, `provenance: observed` | the **vendor's numeric `error.code`** and the request id are preserved; `message` is the fixed `Upstream tool returned an error; its code and category are recorded in Talon evidence`; the vendor's `message` and `data` are **not relayed** |

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
| `operationId`, `operationRef`, `approvalId`, `attemptId`, `taskId` | Scoped resource locators when the outcome belongs to a logical operation. They are never bearer authorization and never replace each other (a Task id is not an operation id). Emitted once MCP calls reach ActionGovernance (#431). |
| `evidence` | Reference to the signed record, see below. |
| `generation` | Short runtime-generation identity the decision was made against (#431). |
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
| `policy_denied` | deny | no | Action Gateway DENY; `/mcp` tool-access deny; `/mcp/proxy` `forbidden_tools` match and policy deny |
| `pii_policy_violation` | deny | no | `/mcp`, `/mcp/proxy` PII block, residual PII after redaction, invalid redaction output; LLM gateway |
| `scanner_unavailable` | failed | yes | `/mcp`, `/mcp/proxy` scan engine unavailable or unverifiable (fail-closed); LLM gateway |
| `policy_evaluation_failed` | failed | yes | `/mcp`, `/mcp/proxy` policy engine error (fail-closed, zero dispatch) |
| `upstream_auth_unavailable` | failed | yes | `/mcp/proxy` vault credential unavailable before dispatch (generic message, zero upstream call) |
| `upstream_tool_failed` | failed | no | `/mcp/proxy` outbound request could not be built, header generation failed, definition capture (`tools/list`) failed before any business call; `/mcp` process-local tool error (the tool reported its own failure) |
| `upstream_outcome_unknown` | unknown | no | `/mcp/proxy` after the business call was handed to the transport: transport failure, unreadable/malformed/id-mismatched response, wrong content type, missing or unsupported `resultType` (including `task`). Signed explanation `EXECUTION_OUTCOME_UNKNOWN` / `unknown`; record status `unknown` |
| `evidence_commit_failed` | failed | yes | `/mcp`, `/mcp/proxy` when a pre-dispatch record cannot commit |
| `approval_required`, `approval_pending`, `approval_rejected`, `approval_expired`, `approval_not_authorized`, `approval_already_decided`, `approval_binding_stale`, `operation_id_required`, `operation_conflict`, `operation_already_succeeded`, `operation_outcome_unknown`, `attempt_already_in_progress`, `attempt_not_authorized`, `action_not_found`, `action_schema_invalid`, `payload_unavailable`, `execution_unsupported`, `not_found`, `invalid_request`, `store_unavailable`, `generation_changed`, `agent_identity_required` | per code | per code | Action Gateway HTTP ([Action Gateway](action-gateway.md)); on MCP once #431 routes `tools/call` through ActionGovernance |
| `model_not_allowed`, `provider_not_allowed`, `budget_exceeded`, `session_budget_exceeded`, `data_tier_exceeded`, `tool_policy_violation`, `egress_tier_destination_disallowed`, `egress_destination_disallowed`, `rate_limited`, `workload_identity_required`, `workload_identity_unbound`, `destination_not_governed`, `agent_disabled`, `model_required_for_policy_evaluation` | per code | per code | LLM gateway and delegated path ([error contract](error-contract.md)) |
| `approval_requires_tasks` | failed (unsupported) | no | **reserved** (#431/#448): asynchronous approval needed and the current request does not advertise Tasks; honest non-execution, zero dispatch, request not held open, no hidden continuation |
| `approval_cancelled`, `approval_invalidated` | deny | no | **reserved** (#426 typed approval kernel); today an invalidated approval is reported as `approval_binding_stale` |
| `unsupported_runtime_posture` | failed (unsupported) | no | **reserved** (#431) |

`go test ./internal/govcode/ ./internal/action/ ./internal/gateway/ -run 'Registry|Govcode|RegisteredInGovcode'` proves the registry is complete, deduplicated, conservative on retryability, and that every action-domain and gateway code is registered under its canonical spelling.

## Known failure versus unknown outcome

Talon only labels an effect **failed** when it can know the effect did not happen or a trustworthy party reported the failure:

| Situation | Code | Evidence status | Why |
|---|---|---|---|
| request could not be built, credential unavailable, definition capture failed, policy/PII evaluation failed | `upstream_tool_failed`, `upstream_auth_unavailable`, `policy_evaluation_failed` (provenance `not_dispatched`) | `failed` / denied | nothing was handed to the transport |
| the process-local tool (`/mcp`) returned an error | `upstream_tool_failed` | allowed, execution error | the tool itself reported the failure |
| the vendor answered a well-formed JSON-RPC error (`/mcp/proxy`) | `upstream_tool_failed` (outer `error.code` = the vendor's code) | `failed` | a trustworthy vendor report; the vendor's text and data stay out of the response and out of the record, which keeps only `upstream_jsonrpc_error: code=<n> category=<jsonrpc category>` |
| transport failure after the request was handed over; response unreadable, malformed, id-mismatched, wrong content type; missing or unsupported `resultType` (including `task`) | `upstream_outcome_unknown` (non-retryable, provenance `unknown`) | `unknown` | the request may have reached the tool; an answer Talon cannot trust proves nothing about the effect |

`unknown` blocks automatic retry; Talon never re-sends on the client's behalf. The signed explanation agrees with the outcome: unknown records carry `EXECUTION_OUTCOME_UNKNOWN` with decision `unknown`; known failures carry `EXECUTION_FAILED` with decision `failure`. `TestSafety_OutcomeSemanticsTable` compares extension, record status and signed explanation for pre-dispatch failure, trustworthy vendor error, transport reset after an accepted effect, malformed post-dispatch response, unsupported `resultType: task` and allowed success; `TestGovernance_PostHandoffAmbiguityIsUnknown` and `TestGovernance_VendorErrorIsTrustworthyFailure` pin the boundary.

## Untrusted text: evidence stores tokens, never free text

**Untrusted fields.** Policy decision reasons (a policy engine or author can write anything into them; the rego used to interpolate caller-supplied argument values), vendor JSON-RPC error messages and `data`, vendor tool-definition errors, and every Go error from the policy engine, a tool, the transport, header generation or upstream decoding.

**Talon-authored public messages** are fixed strings chosen per outcome (`tool not allowed by policy`, `Tool call blocked: policy evaluation failed (fail-closed)`, `Upstream response invalid; the tool outcome is unknown`, …). No untrusted text is ever echoed into them. The only protocol messages that carry caller-derived text are the `-32602` invalid-params answers, which echo the caller's own tool name or schema error back to that caller, sanitized and bounded; they write no evidence.

**Signed, tenant-queryable records never receive free text**, sanitized or not. Every `policy_decision.reasons[]` entry, `execution.error` and explanation trigger written by `/mcp` and `/mcp/proxy` is one of these structured tokens:

| Source | Stored token | What is kept |
|---|---|---|
| Proxy `forbidden_tools` list (checked before the rego) | `forbidden_tools` | nothing beyond the rule identity |
| Policy denial, Talon rego template matched | `tool_not_allowed`, `tool_forbidden`, `tool_forbidden_override`, `tool_destructive_pattern`, `admin_operation_requires_allow`, `forbidden_path_pattern`, `row_count_exceeded:limit=<n>`, `dry_run_required:threshold=<n>`, `forbidden_argument_value:field=<name>` | the rule identity; a configured field name (`[A-Za-z0-9_.-]{1,64}`) or a numeric policy limit; never the tool name (already in `execution.tools_called`), never an argument or configured value |
| Policy denial, any other reason text | `policy_rule_denied` | nothing — a reason that is not exactly a Talon template is free text of unknown provenance, even when it contains words such as "tool" or "forbidden" |
| Policy or PII engine failure | `policy_evaluation_failed`, `pii_policy_evaluation_failed` | nothing |
| Vendor JSON-RPC error (`tools/call` / definition capture) | `upstream_jsonrpc_error: code=<n> category=<c>` / `definitions_upstream_jsonrpc_error: …` with `<c>` ∈ `parse_error`, `invalid_request`, `method_not_found`, `invalid_params`, `internal_error`, `server_error`, `vendor_defined` | the vendor's numeric code and its JSON-RPC category; never the message or data |
| Transport / decoding failure | `upstream_error: <kind>`, `upstream_response_invalid: <kind>`, `definitions_…` with `<kind>` ∈ `timeout`, `transport`, `connection_closed`, `redirect_refused`, `http_status`, `protocol_violation`, `result_type_missing`, `result_type_unsupported`, `list_result_invalid`, `secret_retrieval`, `unclassified` | the failure kind, classified from Talon's typed errors; never the error text |
| Outbound request construction | `outbound_request_invalid`, `outbound_header_params_invalid` | nothing |
| Process-local tool error (`/mcp`) | `tool_execution_failed` | nothing |

The raw text behind each token is available to operators in the process log (`mcp_policy_evaluation_failed`, `mcp_proxy_policy_evaluation_failed`, `mcp_tool_execution_failed`, `mcp_proxy_vendor_error`, `mcp_proxy_definition_capture_failed`) and the request span (`policy.deny_detail`), after `sanitizeDiagnostic` (control and format characters, secrets, URL credentials, paths, length). That sanitizer is defense in depth for logs and for the `-32602` echoes; it is not what keeps data out of evidence. `TestPolicyReasonTokens`, `TestVendorErrorToken`, `TestUpstreamFailureToken` pin the grammar; `assertOnlyEvidenceTokens` checks every reason, error and trigger of the records written in the safety tests against it.

**Vendor JSON-RPC errors are not relayed raw (contract change).** Earlier builds relayed the vendor's error object (`code`, `message`, `data`) to the client unchanged. That promise was unsafe: a vendor error routinely carries protected payload (customer ids, e-mail addresses, record contents), credentials or internal topology, and nothing in Talon could vouch for it. Now, on both `tools/call` and the definition capture (`tools/list`), Talon preserves the vendor's **numeric `error.code`** and the request id (so clients keep their error classification), replaces `message` with the fixed public string, drops the vendor's `data` entirely (no typed allowlist of vendor fields exists today; none is copied), and attaches its own governance extension (`upstream_tool_failed`, a trustworthy failure, never `unknown` or a policy denial). Talon's signed record stores the vendor code and its JSON-RPC category only; the vendor's message goes to the process log. **Migration:** clients that parsed vendor `message` or `data` must use the vendor's `code`, Talon's `evidence.id` (and `talon audit show`) or the vendor's own logs instead. Tests: `TestSafety_VendorErrorIsNeverRelayedRaw` (credential-shaped sentinels, an ordinary e-mail address and customer id, nested data, quoted JSON, oversized message, a benign-looking message; both paths; the entire signed record is checked), `TestGovernance_VendorErrorIsTrustworthyFailure`, the smoke's vendor-error step (asserts the record holds the `code=-32001 category=server_error` token and none of the vendor's customer id, e-mail or token).

**Policy denial reasons are structured, never values.** Talon's rego emits value-free reasons (rule identity, field name, policy limit), so a caller's argument value or a protected configured value is never interpolated at the source. The MCP evidence boundary does not rely on that: it matches each reason against Talon's templates exactly and stores the token (table above) or `policy_rule_denied`. Keyword classification (`BuildLegacyFacts`) is applied to the tokens, never to the text, so a reason such as `Tool rejected for customer private.person@example.test` cannot be retained because it contains "tool". Tests with the real rego and with injected engines, using ordinary identifiers (an e-mail address, a customer id, a project code name) and checking the whole signed record and its explanations: `TestSafety_RegoForbiddenArgumentValueNotEchoed`, `TestSafety_UnclassifiedPolicyReasonIsOpaque`, `TestSafety_OrdinaryIdentifiersNeverReachEvidence` (both routes), `TestSafety_NativePolicyDenialReasonsAreUntrusted`, `TestSafety_ProxyPolicyDenialReasonsAreUntrusted`; the smoke's forbidden step sends a customer id and an e-mail address as arguments and asserts the denial record holds only the fixed `forbidden_tools` token.

## Canonical resolution precedes governance

A `tools/call` for a name the native registry cannot resolve is the spec's invalid-params protocol error (HTTP 400, `-32602`), answered exactly like a wire-gate rejection: no governance extension, no legacy alias, no signed record, zero execution. The same holds for arguments that violate the trusted schema, malformed arguments and an invalid `tools/list` cursor on either route — every protocol failure is HTTP 4xx; only a governed outcome on an accepted request is HTTP 200 with `-32000`. Only a known tool reaches the policy boundary, so a committed `policy_denied` receipt always names a tool Talon can resolve. On `/mcp/proxy`, an explicitly forbidden or hidden name is denied before any upstream contact (not even a definition fetch), and an allowlisted name the upstream does not publish is HTTP 400 / `-32602` without a receipt. `TestSafety_NativeResolutionMatrix`, `TestSafety_ProxyUnknownVersusForbidden`, and the black-box smoke's unknown-native-tool step pin this.

## Protocol errors are not policy decisions

A request that fails the wire gate (#447) never receives the extension and never produces governance evidence: `-32700` parse, `-32600` invalid request, `-32601` method not found, `-32602` invalid params (including `meta_missing`/`meta_invalid` and `Mcp-Param-*` parse failures), `-32022` unsupported protocol version, `-32020` header/body mismatch. `tests: internal/mcp TestGovernance_ProtocolErrorsCarryNoExtension`, `TestProxyForwarding_IntegrityFailuresNeverReachUpstream`.

## MRTR and Tasks

`resultType: "input_required"`, `requestState` and `inputResponses` are core MCP continuation for non-authorizing input; they pass through `/mcp/proxy` unchanged and never satisfy a Talon approval. The Tasks extension is not advertised and an upstream `resultType: "task"` is reported as `upstream_outcome_unknown` (the call ran; the answer is a shape Talon does not accept) until #448 ships; when it does, task metadata and terminal task results use this same vocabulary, `tasks/get` polls canonical state without creating authorization, and `tasks/update` cannot submit a human approval.

## Parity with the Action Gateway

The same domain outcome carries the same `code` whether it is observed over `POST /v1/action-operations` (HTTP envelope `error.code` / `operation.outcome_code`) or, after #431, over `tools/call`. Only the transport envelope differs. The Action Gateway's projections now also carry `evidence: {id, committed, sequence}` for the lifecycle record the call committed, so an HTTP client and an MCP client receive the same evidence identifiers for the same operation.

## Verify

```bash
go test ./internal/govcode/ ./internal/mcp/ -run 'Governance|Registry|Extension|Sanitize'
make test-mcp-governance-smoke      # offline black-box gate (below)
# fetch and verify a referenced record
talon audit verify req_3f9a1c2b
```

Three smoke targets, three purposes:

| Target | Proves | Keys |
|---|---|---|
| `make test-mcp-smoke` | the 2026-07-28 wire (#447): discover, deterministic list, header/body integrity, legacy rejection | none |
| `make test-mcp-governance-smoke` | this contract (#372) against the **built binary over real HTTP**: exactly this extension advertised and no Tasks; allowed call → `decision: allow` + committed id + one effect + the full record HMAC-verified with `reasonCode` equal to the signed explanation; forbidden call → `policy_denied`, deny, non-retryable, committed ref, alias, zero dispatch; protocol errors → no governance object, no effect; effect followed by a severed answer → `upstream_outcome_unknown`, exactly one effect, record `unknown`; a tampered record fails `talon audit verify`; the smoke's own assertion set rejects a missing id, an uncommitted ref, a retryable denial and a leaked signature | none |
| `make test-action-catalog-smoke` | the trusted catalog (#427) | none |

`make test-mcp-governance-smoke` runs `scripts/mcp-governance-smoke.sh` → `TestE2E_MCP_GovernanceContract`. The same test is smoke section 37 of `make test-smoke` (counted in the consolidated report; a failure fails the suite) and a named step in PR CI. Pre-dispatch evidence-commit outages and adversarial sanitization cannot be injected into a running binary and are proven in-process by `TestGovernance_NativePolicyEvaluationFailure_CommitOutage`, `TestGovernance_ProxyPolicyEvaluationFailure_EvidencedZeroUpstream`, `TestGovernance_EvidenceCommitFailure_NoIDZeroExecution` and `TestGovernance_NativeToolErrorIsSanitized`.
