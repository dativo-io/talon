# Evidence Integrity Specification

**Status:** stable · **Version:** 1.6 · **Scope:** the signed evidence record produced by Talon.

This is the normative specification for how a Talon evidence record is serialized,
signed, and verified. It is written so that a third party can independently verify a
Talon record — or reproduce a signature — from this document alone, without reading the
Go source.

The normative source of the record shape is the `Evidence` struct in
[`internal/evidence/store.go`](../../internal/evidence/store.go); the signing and
verification primitives are in
[`internal/evidence/signature.go`](../../internal/evidence/signature.go). Where this
document and the source disagree, the source is authoritative — please file an issue so
the spec can be corrected.

> **Integrity, not correctness.** A valid signature proves that the record was signed
> with the deployment's configured key and has not been modified since signing. It does
> **not** prove that the policy decision, model response, tool result, or operator
> configuration was correct. See [LIMITATIONS.md](../../LIMITATIONS.md).

## 1. Overview

```
record (signature = "")  ──serialize──▶  canonical bytes  ──HMAC-SHA256(key)──▶  mac
                                                                                  │
                                              signature = "hmac-sha256:" + hex(mac)
```

Signing happens once, at record creation (`Store.Store` in
[`internal/evidence/store.go`](../../internal/evidence/store.go)). Verification recomputes
the signature from the stored record and compares it in constant time
(`Store.VerifyRecord`). The signing key never leaves the operator's deployment.

## 2. Record fields

A record is a single JSON object. Every field listed below is covered by the signature.
Fields marked **always** are always present; fields marked **optional** are omitted when
they hold their zero value (see [§3.3](#33-omitempty-rules)).

Top-level fields, **in serialization order** (this order is significant — see
[§3.2](#32-field-order)):

| # | JSON key | Type | Presence |
|---|----------|------|----------|
| 1 | `id` | string | always |
| 2 | `correlation_id` | string | always |
| 3 | `session_id` | string | optional |
| 4 | `stage` | string | optional |
| 5 | `candidate_index` | number | optional |
| 6 | `judge_score` | number | optional |
| 7 | `selected` | bool | optional |
| 8 | `timestamp` | string (RFC 3339) | always |
| 9 | `tenant_id` | string | always |
| 10 | `agent_id` | string | always |
| 11 | `team` | string | optional |
| 12 | `invocation_type` | string | always |
| 13 | `request_source_id` | string | optional |
| 14 | `policy_decision` | object | always |
| 15 | `classification` | object | always |
| 16 | `attachment_scan` | object | optional |
| 17 | `tool_governance` | object | optional |
| 18 | `execution` | object | always |
| 19 | `model_routing_rationale` | string | optional |
| 20 | `secrets_accessed` | array(string) | optional |
| 21 | `upstream_auth_mode` | string | optional |
| 22 | `upstream_key_source` | string | optional |
| 23 | `upstream_key_fingerprint` | string | optional |
| 24 | `gateway_annotations` | array(string) | optional |
| 25 | `memory_writes` | array(object) | optional |
| 26 | `memory_reads` | array(object) | optional |
| 27 | `audit_trail` | object | always |
| 28 | `compliance` | object | always |
| 29 | `agent_reasoning` | string | optional |
| 30 | `agent_verified` | bool | optional |
| 31 | `observation_mode_override` | bool | optional |
| 32 | `shadow_violations` | array(object) | optional |
| 33 | `status` | string | optional |
| 34 | `failure_reason` | string | optional |
| 35 | `signature` | string | always |
| 36 | `routing_decision` | object | optional |
| 37 | `cache_hit` | bool | optional |
| 38 | `cache_entry_id` | string | optional |
| 39 | `cache_similarity` | number | optional |
| 40 | `cost_saved` | number | optional |
| 41 | `plan_review` | object | optional |
| 42 | `retry_attempt` | string | optional |
| 43 | `explanations` | array(object) | optional |
| 44 | `plan_id` | string | optional |
| 45 | `graph_run_id` | string | optional |
| 46 | `data_flow` | object | optional |
| 47 | `egress_decision` | object | optional |
| 48 | `failover` | object | optional |
| 49 | `orchestration` | object | optional |

Nested objects (`policy_decision`, `classification`, `execution`, `audit_trail`,
`compliance`, and the optional objects) follow the same encoding rules recursively; their
field order and `omitempty` behavior are defined by their Go structs in
[`internal/evidence/store.go`](../../internal/evidence/store.go). The audit-critical
nested fields are:

- `policy_decision`: `allowed` (bool), `action` (string), `reasons` (array, optional),
  `policy_version` (string).
- `classification`: `input_tier`, `output_tier` (numbers), `pii_detected` (array,
  optional), `pii_redacted` (bool), and optional output-scan fields. The optional
  `scanner` object identifies the scan engine behind the verdict: `engine`
  (detector identity, e.g. `talon-regex` or the configured external engine
  name), `type` (`regex` | `presidio` | `http` | `llm`), and optional
  `version`, `scan_duration_ms`, and `failure` (adapter failure kind —
  `timeout`/`transport`/`status`/`decode`/`validation` — when a scanner
  failure drove a fail-closed block). Entity types only; never raw PII text
  or raw engine errors. The optional `tool_content` object (spec 1.5, #212)
  records the observation-only PII scan of tool-related request content
  (`scanned`, `has_pii`, `entity_types`, `entity_count`); detection is
  evidence-only and never influences allow/deny or redaction in this version.
- `execution`: `model_used` (string), `cost` (number), `tokens` (object),
  `duration_ms` (number), plus optional fields.
- `audit_trail`: SHA-256 `input_hash` / `output_hash` content digests.
- `compliance`: `frameworks` (array) and `data_location`.
- `data_flow` (optional): `detector` (string, optional) and `items` (array of
  objects linking classified data sources to destinations). Each item carries
  `source`, `source_detail` (optional), `tier`, `entity_types` (sorted array,
  optional), `entity_count` (optional), `value_digests` (sorted array of
  per-request salted SHA-256 prefixes, optional — never raw values),
  `entity_attributions` (optional array of compact attribution objects:
  `type`, `field_path` (optional), `start` (optional), `end` (optional),
  `attributes` (optional)),
  `disposition`, and a `destination` object (`kind`, `name`, `model`,
  `endpoint`, `region`; the last three optional).
- `egress_decision` (optional): outcome of the gateway egress policy
  (data tier × destination). Fields: `tier` (number), `provider` (string),
  `region` (string, optional), `decision` (`"allow"` or `"deny"`),
  `matched_rule` (string, optional — e.g. `tier_2:allowed_regions` or
  `default_action`), and `reason` (string, optional — machine code such as
  `egress_tier_destination_disallowed`). Present only when an egress policy
  is configured for the caller; recorded for allowed and denied requests so
  the control's execution can be evidenced.
- `failover` (optional): provider fallback-chain context (#191). Present when
  error-driven failover produced a failed-attempt record, a fallback decision,
  or a fail-closed outcome. Fields are defined by the `FailoverContext` Go
  struct; see the failover verifier (`talon audit verify --failover`).
- `orchestration` (optional): client-asserted coding-orchestration identity
  (#194). Fields: `session_id`, `agent_id`, `parent_agent_id`, `client`
  (adapter-detected: `"claude-code"`, `"codex"`, or `"generic"`),
  `session_source` (`client_asserted` | `vendor_asserted` | `synthetic`), and
  `provenance` (always `"client_asserted"` in this version). Attribution
  metadata only — as trustworthy as the caller that presented the tenant key;
  never a policy input. All fields optional/omitempty.

## 3. Canonical serialization

The canonical byte sequence is the JSON encoding of the record with the `signature` field
set to the empty string `""`. It is produced by Go's `encoding/json.Marshal`; a faithful
re-implementation in any language must reproduce the following rules byte-for-byte.

### 3.1 Object form

- A single JSON object, UTF-8 encoded.
- **No insignificant whitespace** between tokens (no spaces after `:` or `,`).
- **No trailing newline** (the encoder is `json.Marshal`, not a streaming `Encoder`).

### 3.2 Field order

Object members appear in the struct declaration order shown in [§2](#2-record-fields), not
alphabetical order. Go's `encoding/json` emits struct fields in declaration order; any
re-implementation must use the same fixed order. (There are no Go `map` fields at the top
level, so ordering is fully deterministic.)

### 3.3 `omitempty` rules

A field tagged `,omitempty` is omitted entirely when it holds its Go zero value:
`""` for strings, `0` for numbers, `false` for booleans, and `null`/length 0 for
pointers, slices, and maps. Note: Go's `omitempty` does **not** omit empty *structs*, so
the **always**-present object fields (e.g. `policy_decision`) are emitted even when their
sub-fields are zero.

The `signature` field is **not** tagged `omitempty`. In the canonical (pre-signing) form
it is therefore always present and serialized as `"signature":""`.

### 3.4 String, number, and time encoding

- **Strings** use standard JSON escaping, with Go's default **HTML escaping enabled**:
  `<` → `\u003c`, `>` → `\u003e`, `&` → `\u0026`, and U+2028 / U+2029 → `\u2028` /
  `\u2029`. A re-implementation must apply the same escaping or signatures will not match.
- **Timestamps** (`timestamp`) are RFC 3339 / ISO 8601 with up to nanosecond precision,
  the output of Go's `time.Time.MarshalJSON` (e.g. `2026-06-02T21:15:02.123456789Z`).
  Trailing-zero fractional digits are trimmed.
- **Numbers** use Go's default `encoding/json` formatting (integers without a decimal
  point; floats in the shortest round-trippable form).

## 4. Signing procedure

Given the canonical bytes `C` from [§3](#3-canonical-serialization) and the resolved key
`K` from [§6](#6-key-resolution):

1. Compute `mac = HMAC-SHA256(K, C)` (RFC 2104, SHA-256).
2. Encode `mac` as **lowercase** hexadecimal (64 hex characters).
3. The signature string is the literal prefix `hmac-sha256:` followed by that hex string,
   e.g. `hmac-sha256:9f86d081884c7d65...`.
4. Set the record's `signature` field to this string and persist the record.

See `Signer.Sign` in [`internal/evidence/signature.go`](../../internal/evidence/signature.go).

## 5. Verification procedure

Given a stored record `R` whose `signature` field holds `S`:

1. Save `S`, then set `R.signature = ""`.
2. Recompute the canonical bytes `C'` from `R` per [§3](#3-canonical-serialization).
3. Compute `expected = "hmac-sha256:" + hex(HMAC-SHA256(K, C'))`.
4. The record is **valid** iff `expected == S`, compared in **constant time**
   (`hmac.Equal` over the full prefixed strings). Restore `R.signature = S`.

Any post-signing modification to any field — timestamp, cost, PII findings, policy
decision, etc. — changes `C'` and causes verification to fail. See `Store.VerifyRecord` in
[`internal/evidence/store.go`](../../internal/evidence/store.go).

### CLI

```bash
talon audit verify <evidence-id>        # verify one record from the live store
talon audit verify --file export.json   # verify a signed export offline
```

The file verifier reports total / valid / invalid / missing-signature / unparseable
counts and exits non-zero if any record fails. See
[Evidence store](../explanation/evidence-store.md) and the
[compliance export runbook](../guides/compliance-export-runbook.md).

## 6. Key resolution

The signing key is supplied via `TALON_SIGNING_KEY` (or configuration). It is interpreted
by `resolveSigningKey` in
[`internal/evidence/signature.go`](../../internal/evidence/signature.go):

- If the value is **64 or more characters, even length, and all hexadecimal**, it is
  hex-decoded to raw bytes, which must be **at least 32 bytes**.
- Otherwise the value's **raw UTF-8 bytes** are used directly, and must be **at least 32
  bytes**.

The same `K` is used for signing and verification (symmetric HMAC). Custody, rotation, and
backup of the key are operator responsibilities; see [LIMITATIONS.md](../../LIMITATIONS.md).

## 7. Reproducibility test

The round-trip property — that following this spec independently produces a signature the
verifier accepts, and that tampering is detected — is asserted by
`TestEvidenceIntegritySpecRoundTrip` in
[`internal/evidence/integrity_spec_test.go`](../../internal/evidence/integrity_spec_test.go).
It serializes a record per [§3](#3-canonical-serialization), signs it per
[§4](#4-signing-procedure), verifies it with an independently constructed signer and with
`Store.VerifyRecord`, and confirms that mutating a field invalidates the signature.

## 8. Changelog

- **1.6** — added optional nested field `orchestration` (#194): client-asserted
  coding-orchestration identity (`session_id`, `agent_id`, `parent_agent_id`,
  `client`, `session_source`, `provenance`) observed on gateway requests.
  Attribution metadata only, marked `provenance: "client_asserted"`; never a
  policy input in this version. Additive and backward-compatible: records that
  omit the field keep identical canonical bytes and verify unchanged; use a 1.6
  verifier for records that carry it.

- **1.5** — added optional nested field `classification.tool_content` (#212):
  the observation-only PII scan of tool-related request content (tool_use
  inputs, tool_result outputs, function-call arguments) — `scanned`, `has_pii`,
  `entity_types`, `entity_count`. Detection is evidence-only: it never
  influences allow/deny or redaction in this version. Additive and
  backward-compatible: records that omit the field keep identical canonical
  bytes and verify unchanged; use a 1.5 verifier for records that carry it.
- **1.4** — added optional nested field `classification.scanner` (external
  EntityScanner adapter support, #181): scan engine identity, type, declared
  version, scan duration, and failure kind on fail-closed blocks. Additive and
  backward-compatible: records that omit the field keep identical canonical
  bytes and verify unchanged.
- **1.3** — added optional nested field `data_flow.items[].entity_attributions`
  (compact field-path + span attribution, no raw values). This is additive and
  backward-compatible: records that omit the field keep identical canonical
  bytes and verify unchanged.
- **1.2** — added optional top-level field `egress_decision` (#47), appended
  after `data_flow`. Records signed under spec 1.0/1.1 verify unchanged (the
  field is omitted when absent, so their canonical bytes are identical). The
  established additive-field caveat applies: a verifier built against an
  earlier spec drops the unknown `egress_decision` member on parse and
  therefore cannot verify records that carry it — use a 1.2 verifier for new
  records.
- **1.1** — added optional top-level field `data_flow` (#46), appended after
  `graph_run_id`. Records signed under spec 1.0 verify unchanged (the field is
  omitted when absent, so their canonical bytes are identical). Note the
  established caveat for every additive field: a verifier built against spec
  1.0 drops the unknown `data_flow` member on parse and therefore cannot
  verify records that carry it — use a 1.1 verifier for new records.
- **1.0** — initial version.

## 9. Limitations

- HMAC is **symmetric**: anyone holding the signing key can produce valid signatures. The
  signature attests integrity under the operator's key custody, not third-party
  non-repudiation. Asymmetric signing is out of scope for this version.
- The signature does not bind the record to a specific host or instance beyond the shared
  key, and it does not attest the correctness of the decision it records.
