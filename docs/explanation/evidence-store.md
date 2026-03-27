# Evidence Store

How Talon creates, signs, stores, and exports tamper-proof audit records.

## Overview

Every interaction that passes through Talon generates an **evidence record** --
a structured JSON document that captures what happened, what policy decided, and
what data was involved. Evidence records are the foundation of Talon's
compliance story.

```
Request → Pipeline → Evidence Record → HMAC Sign → SQLite Write → Export
```

## Evidence Record Structure

Each record contains these sections:

| Section | Fields | Purpose |
|---------|--------|---------|
| **Identity** | `id`, `session_id`, `correlation_id`, `timestamp`, `tenant_id`, `agent_id` | Who, when, which tenant; `session_id` links requests in the same lifecycle session |
| **Policy Decision** | `allowed`, `action`, `reasons`, `policy_version` | What the policy engine decided |
| **Classification** | `input_tier`, `output_tier`, `pii_detected`, `pii_redacted`, `output_pii_detected` | What PII was found |
| **Execution** | `model_used`, `cost`, `tokens`, `duration_ms`, `tools_called`, `error` | What the LLM did |
| **Audit Trail** | `input_hash`, `output_hash` | SHA-256 content hashes for forensics |
| **Compliance** | `frameworks`, `data_location` | Which regulations apply |
| **Signature** | `signature` | HMAC-SHA256 over all other fields |

**Sessions:** When the server or CLI creates a lifecycle session (e.g. for `POST /v1/agents/run` or `talon run`), that session’s ID is stored in `session_id`. Plan-gated runs and their subsequent auto-dispatch share the same session so that all evidence for that flow can be correlated. Export and API responses include `session_id` when present.

## HMAC Signing

Every evidence record is signed at creation time using HMAC-SHA256.

**How it works:**

1. The evidence record is serialized to JSON (excluding the `signature` field)
2. HMAC-SHA256 is computed using the server's `TALON_SIGNING_KEY`
3. The hex-encoded signature is stored in the `signature` field
4. The complete record (including signature) is written to SQLite

**Verification:** `talon audit verify <id>` recomputes the HMAC from the stored
record and compares it to the stored signature. If any field was modified after
creation -- timestamp, cost, PII findings, policy decision -- verification
fails.

```bash
$ talon audit verify req_a1b2c3d4
✓ Evidence req_a1b2c3d4: signature VALID

$ talon audit verify req_tampered
✗ Evidence req_tampered: signature INVALID
```

**What this proves:** The signing key never leaves the server. If the signature
is valid, the record has not been modified since Talon created it. This provides
ISO 27001 A.8.15 compliance (tamper-proof logging) without requiring external
infrastructure like a blockchain or append-only storage.

## Progressive Disclosure

Evidence is exposed at three levels of detail, matching different use cases:

### Layer 1: Index (List View)

`talon audit list` returns lightweight summaries for scanning:

```
ID          TIME                 CALLER        ALLOWED  COST(€)  MODEL
req_a1b2c3  2026-03-15T10:23:45  slack-bot     true     0.003    gpt-4o-mini
req_d4e5f6  2026-03-15T10:24:12  hr-assistant  false    0.000    gpt-4o
```

### Layer 2: Timeline

`talon audit timeline --around <id>` shows what happened before and after a
specific event, useful for incident investigation.

### Layer 3: Full Record

`talon audit show <id>` returns the complete evidence record with all fields,
PII findings, policy reasons, and HMAC signature status.

## Storage

**Default:** SQLite database at `~/.talon/evidence.db`. Single file, no
external dependencies. Suitable for single-instance deployments.

**Upgrade path:** PostgreSQL for high-availability deployments. Same evidence
schema, different storage backend. Configure via `talon.config.yaml`.

**Retention:** Configurable via `audit.retention_days` in `agent.talon.yaml`. Default: 90 days.

## Export

Evidence can be exported for compliance officers, auditors, or external systems:

```bash
# CSV for spreadsheets and compliance tools
talon audit export --format csv --from 2026-03-01 --to 2026-03-31 > march-audit.csv

# JSON for programmatic access
talon audit export --format json --from 2026-03-01 > march-audit.json
```

CSV columns: `id`, `session_id`, `timestamp`, `tenant_id`, `agent_id`, `invocation_type`, `allowed`, `cost`, `model_used`, `duration_ms`, `has_error`, `input_tier`, `output_tier`, `pii_detected`, `pii_redacted`, `policy_reasons`, `tools_called`, `input_hash`, `output_hash`, plus shadow/cache fields when applicable. JSON and NDJSON export include the same fields; `session_id` links evidence to a lifecycle session (e.g. plan-gated run and its dispatch).

## OpenTelemetry Export

Evidence records are also exported as OpenTelemetry spans, following the GenAI
semantic conventions. This allows integration with existing observability stacks
(Grafana, Datadog, etc.) without custom tooling.

## Prompt Storage and Data Minimization

Evidence records store **hashes** of prompts and responses (`input_hash`,
`output_hash`) — never verbatim text by default.  When `audit.include_prompts`
is enabled, prompt text is persisted in a separate **prompt version store**
(`prompt_versions.db`).

**Data minimization (GDPR Art. 5(1)(c)):** When input PII redaction
(`redact_input: true`) is active, the prompt version store saves the
**redacted** prompt — the text the LLM actually received — not the original
PII-bearing input.  This ensures that enabling prompt logging does not
inadvertently persist personal data that was intentionally stripped.

**Forensic opt-in:** If forensic reconstruction of original inputs is required
(e.g. legal hold), set `audit.include_original_prompts: true`.  This persists
**both** the redacted and original prompts.  Use this flag with care and
document its use in your data processing records (GDPR Art. 30).

| Storage Layer | Default Content | PII Risk |
|--------------|----------------|----------|
| Evidence record (`input_hash`) | SHA-256 hash | None |
| Step evidence (`input_summary`) | Truncated redacted prompt | Low |
| Prompt version store | Redacted prompt | Low |
| Prompt version store (`include_original_prompts`) | Original + redacted | High (opt-in) |

See [ADR-002](../contributor/adr/ADR-002-prompt-storage-data-minimization.md)
for the full rationale.

## Compliance Mapping

| Regulation | Article | Talon Feature |
|-----------|---------|--------------|
| GDPR | Article 30 (Processing records) | Evidence export with data categories, purposes |
| ISO 27001 | A.8.15 (Logging) | HMAC-signed tamper-proof records |
| NIS2 | Article 21 (Incident reporting) | Timeline view, correlation IDs |
| EU AI Act | Article 13 (Transparency) | Full execution records with model, cost, PII |
| DORA | Article 11 (ICT incidents) | Cost tracking, incident timeline |

## Source Code

| File | Responsibility |
|------|---------------|
| `internal/evidence/store.go` | SQLite storage, HMAC signing, querying |
| `internal/evidence/generator.go` | Evidence record creation from pipeline results |
| `internal/evidence/signature.go` | HMAC-SHA256 computation and verification |
| `internal/evidence/export.go` | OpenTelemetry span export |
| `internal/evidence/sanitize.go` | PII sanitization for exports |
