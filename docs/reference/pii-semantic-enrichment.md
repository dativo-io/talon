# PII Semantic Enrichment

Semantic enrichment adds structured attributes to PII placeholders so downstream systems can use them (e.g. gender for PERSON, scope for LOCATION) without seeing raw PII. When disabled, Talon uses legacy placeholders only.

## What it is

- **Detection:** Talon detects PII (email, IBAN, PERSON, LOCATION, etc.) and can redact it from both **input** (prompt before LLM) and **output** (LLM response before returning to user) independently.
- **Placeholder format (legacy):** `[EMAIL]`, `[PERSON]`, `[LOCATION]` — type only.
- **Placeholder format (enriched):** `<PII type="person" id="1" gender="female"/>`, `<PII type="location" id="2" scope="city"/>` — type, stable id, and policy-allowed attributes.

Enrichment runs **after** detection and **before** replacement. Only entity types that support attributes (currently PERSON and LOCATION) get extra fields; others keep the same placeholder shape (with `type` and `id` when enriched mode is on).

Redaction can be applied independently to input and output via `redact_input` and `redact_output`. When `redact_input` is enabled, the LLM sees redacted placeholders instead of raw PII, which is essential for semantic enrichment to be meaningful — the LLM responds to the placeholder format rather than raw PII.

## When to use it

- **Off (default):** No attributes; placeholders are `[TYPE]` only. Use when you don’t need attributes or want minimal change.
- **Shadow:** Enricher runs and attributes are logged/telemetry only; placeholders stay legacy. Use to validate enrichment without changing output.
- **Enforce:** Enricher runs and allowed attributes appear in XML-style placeholders. Use when downstream needs gender/scope (or other future attributes) for analytics or routing.

## Configuration

In `agent.talon.yaml` under `policies`:

```yaml
policies:
  data_classification:
    input_scan: true
    output_scan: true
    redact_pii: true           # shorthand: sets both redact_input and redact_output
    redact_input: true         # redact PII from prompt before LLM sees it (defaults to redact_pii)
    redact_output: true        # redact PII from LLM response before returning (defaults to redact_pii)

  semantic_enrichment:
    enabled: true
    mode: enforce          # off | shadow | enforce
    confidence_threshold: 0.80
    emit_unknown_attributes: false
    default_person_gender: unknown
    default_location_scope: unknown
    preserve_titles: true
    allowed_attributes: ["gender", "scope"]
```

| Field | Description |
|-------|-------------|
| `enabled` | Turn enrichment on for this agent. |
| `mode` | `off` = no enrichment; `shadow` = compute and log only; `enforce` = emit attributes in placeholders. |
| `confidence_threshold` | Minimum confidence (0–1) for an attribute to be set; below this, fallback or omit. |
| `emit_unknown_attributes` | If true, emit `gender`/`scope` even when enricher returns "unknown". |
| `default_person_gender` | Fallback when gender cannot be inferred (e.g. `unknown`). |
| `default_location_scope` | Fallback when scope cannot be inferred (e.g. `unknown`). |
| `preserve_titles` | When true, keep title-based logic; can affect when "unknown" is used. |
| `allowed_attributes` | List of attribute names the policy allows in placeholders (e.g. `gender`, `scope`). Rego can further restrict. |

## Placeholder formats

- **Legacy (enrichment off or shadow):**  
  `[PERSON]`, `[LOCATION]`, `[EMAIL]`, etc.

- **Enriched (enforce):**  
  `<PII type="person" id="1" gender="female"/>`, `<PII type="location" id="2" scope="city"/>`.  
  Attributes appear in deterministic order (type, id, then allowed attributes sorted). Unknown or policy-denied attributes are omitted. XML special characters in values are escaped (`&quot;`, `&amp;`, etc.).

## How to verify

### Input redaction

1. Set `redact_input: true` (or `redact_pii: true`) and `input_scan: true`.
2. Run a request with PII: `talon run "Contact user@example.com about IBAN DE89370400440532013000"`.
3. Check the evidence (`talon audit show <id>`): the `input_pii_redacted` field should be `true`.
4. The LLM receives the redacted prompt — raw PII never leaves the Talon process.

### Output redaction

1. Set `redact_output: true` (or `redact_pii: true`) and `output_scan: true`.
2. Run a request where the LLM response is likely to contain PII.
3. The returned response should show placeholders instead of raw PII.

### Semantic enrichment

1. **Enable enrichment:** Set `semantic_enrichment.enabled: true` and `mode: enforce` in agent policy; ensure `redact_input: true` and `input_scan: true`.
2. **Run a request** with PII that includes person and location (e.g. "Mrs Smith lives in Berlin. Email: user@example.com").
3. **Check output or evidence:**  
   - Legacy: you should see `[PERSON]`, `[LOCATION]`, `[EMAIL]`.  
   - Enriched: you should see `<PII type="person" ... gender="female"/>`, `<PII type="location" ... scope="city"/>`, and `<PII type="email" id="3"/>` (no extra attributes for email).
4. **Metrics:** Use `talon.pii.enrichment.attempts.total`, `talon.pii.enrichment.attributes.emitted.total`, and `talon.pii.enrichment.fallback_unknown.total` (see [Observability](#observability)).

## PERSON and LOCATION detection

PERSON and LOCATION are optional recognizers in the default EU PII patterns. If they are enabled (default in the built-in patterns), enrichment has entities to work on. You can restrict or extend entity types via `data_classification.enabled_entities` / `disabled_entities` / `custom_recognizers`. Enrichment only runs for types it supports (person → gender, location → scope).

## Observability

- **Metrics:** `talon.pii.enrichment.attempts.total` (by `entity_type`), `talon.pii.enrichment.attributes.emitted.total` (by `attr`, `value`), `talon.pii.enrichment.fallback_unknown.total` (by `entity_type`).
- **Spans:** `classifier.redact` and enricher spans with entity count and type.
- **Logs:** Structured (zerolog); in shadow mode, attribute decisions can be logged without rendering.

## Presidio migration

The canonical entity model and enrichment pipeline are detector-agnostic. If you later switch to Presidio (or another detector), an adapter can map Presidio results to the same canonical shape; the enricher and placeholder renderer stay unchanged. Rego policy continues to govern which attributes are emitted.
