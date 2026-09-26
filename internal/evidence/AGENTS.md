# Evidence subsystem invariants

These rules apply when changing `internal/evidence/**`.

- Signed evidence is historical operational proof; it is not the source of current runtime state when a canonical runtime/store already owns that state.
- HMAC evidence is tamper-evident and verifiable, not immutable and not a completeness proof.
- Historical signed records must remain verifiable unless an explicit migration/version contract says otherwise. Projection fixes should not rewrite signed history.
- New invocation/event types must be assigned to the correct canonical record class. Do not add query-local exclusion lists when the shared classifier can express the rule.
- Unknown invocation types currently fail visibly as request-class traffic. Do not change that default casually.
- Operator/config/lifecycle records must not contaminate request counts, denial rates, spend, last-request, or session traffic projections.
- Keep evidence payloads bounded and deterministic where signatures, exports, or stable comparisons depend on ordering.
- Never place credentials, raw authorization tokens, signing/vault keys, or unnecessary raw configuration into evidence.
- Evidence can prove what Talon observed or authorized at its boundary. Do not claim direct observation of external effects Talon did not see.
- State mutation plus mandatory evidence should share a transaction where the architecture supports it. Where filesystem/runtime/external boundaries prevent one transaction, define and test an explicit recovery protocol.
- CLI/API/dashboard summaries should consume shared evidence/projection semantics rather than independently reinterpret records.

When adding an evidence-producing feature, test both the record itself and the projections that depend on its classification.
