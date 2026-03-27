# ADR-002: Prompt Storage Data Minimization

**Status:** Accepted  
**Date:** 2026-03  
**Context:** GDPR-aligned evidence storage for PII-bearing prompts in Dativo Talon.

---

## Context

Talon's evidence pipeline records every LLM interaction.  When `include_prompts` is
enabled in the audit configuration, the **prompt version store** persists the prompt
text for forensic and transparency purposes (EU AI Act Art. 11/13).

Before this decision, the prompt version store always saved `req.Prompt` — the
original, pre-redaction user input.  When input PII redaction (`redact_input: true`)
was also enabled, this created a contradiction: PII was stripped from the prompt
*before* the LLM received it, but the original PII-bearing text was persisted
verbatim in the prompt version store.

This violates the GDPR data minimization principle (Art. 5(1)(c)) and undermines
data protection by design (Art. 25).

---

## Decision

**When input PII redaction is active, the prompt version store saves the
redacted (post-PII-removal) prompt by default.**

An opt-in flag, `include_original_prompts`, allows organizations to additionally
persist the original pre-redaction prompt when forensic reconstruction is
explicitly required (e.g. internal audit under legal hold).

### Storage Layers After This Change

| Layer | Content | PII Exposure |
|-------|---------|-------------|
| Evidence record (`evidence.db`) | `input_hash` (SHA-256 of original prompt) | None — one-way hash |
| Step evidence (`step_evidence`) | `input_summary` (truncated redacted prompt) | Low — redacted text |
| Prompt version store (`prompt_versions.db`) | Full redacted prompt (default) | Low — redacted text |
| Prompt version store (when `include_original_prompts=true`) | Original + redacted | High — opt-in only |

### Hash Computation

The `input_hash` in the main evidence record continues to hash the **original**
prompt.  SHA-256 is one-way and contains no extractable PII.  This preserves
forensic fingerprinting (same user input always produces the same hash for
deduplication and integrity verification) without violating data minimization.

---

## Rationale

### Regulatory Alignment

| Regulation | Article | Alignment |
|-----------|---------|-----------|
| GDPR | Art. 5(1)(c) — Data minimization | Stored text limited to what is necessary; PII removed when redaction is active |
| GDPR | Art. 25 — Data protection by design | Default behavior minimizes PII; original storage is opt-in |
| GDPR | Art. 32 — Security of processing | Smaller PII surface reduces breach impact |
| EU AI Act | Art. 11 — Technical documentation | Redacted prompt + hash satisfies traceability |
| EU AI Act | Art. 13 — Transparency | Step evidence records what the LLM actually saw |

### Why Not Remove Prompt Storage Entirely?

Art. 11 and Art. 13 of the EU AI Act require technical documentation and
transparency of AI system behaviour.  Storing the prompt (even in redacted form)
provides evidence of what the system processed, enabling compliance audits and
incident investigations.

### Why Offer `include_original_prompts` at All?

Some organizations require forensic reconstruction of original inputs for
internal investigations or legal hold obligations.  Making this an explicit,
separately-named flag ensures:
1. It cannot be enabled accidentally.
2. It is clearly documented as a data governance trade-off.
3. Compliance officers can grep for it in policy files during audits.

---

## Consequences

- **Positive:** Default storage aligns with GDPR Art. 5(1)(c) and Art. 25.
  Breach impact is reduced because the prompt version store contains redacted
  text by default.
- **Positive:** Existing `input_hash` forensic fingerprinting is unaffected.
- **Negative:** Organizations that previously relied on `include_prompts` to
  store originals must now additionally set `include_original_prompts: true`.
  This is a deliberate breaking change toward a safer default.
- **Negative:** When `include_original_prompts` is used, the prompt version
  store contains two entries per run (redacted + original), increasing storage.

---

## References

- GDPR Art. 5(1)(c): Data minimization
- GDPR Art. 25: Data protection by design and by default
- GDPR Art. 32: Security of processing
- EU AI Act Art. 11: Technical documentation
- EU AI Act Art. 13: Transparency obligations
