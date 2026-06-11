# How to export evidence for auditors

Use this runbook to export Talon evidence for auditors or regulators (e.g. GDPR Article 30, NIS2). Steps: export evidence in a chosen format, verify integrity (HMAC), and package for handoff.

---

## 1. Export evidence

Choose the export type based on your goal:

- **Reporting export (reduced fields):** `--format csv|json|ndjson` for spreadsheet/report tooling.
- **Integrity export (full signed records):** `--format signed-json|signed-ndjson` for offline verification.

**CLI:** Export a date range or limit.

```bash
# CSV for a date range (e.g. last month)
talon audit export --format csv --from 2026-02-01 --to 2026-02-28

# JSON with a limit
talon audit export --format json --limit 1000

# Full signed JSON for offline integrity verification
talon audit export --format signed-json --from 2026-02-01 --to 2026-02-28 --output feb-signed-evidence.json
```

**API:** Authenticate with `Authorization: Bearer <tenant-key>` (or admin key for operator workflows) and call:

```http
POST /v1/evidence/export
Content-Type: application/json

{"tenant_id": "default", "format": "json", "limit": 1000}
```

Reduced exports include evidence ID, session_id (lifecycle session linking), timestamp, tenant_id, agent_id, policy decision, cost, and (when configured) PII flags and data tier. For the full reduced column list see [Evidence store — Export](../explanation/evidence-store.md#export) or the CSV header row.

Signed exports include full evidence records with per-record `signature`, policy decision, hashes, model, token usage, and cost fields, suitable for offline verification.

**Scope:** Use `tenant_id` (in API body or CLI context) so the export is scoped to the tenant you are responsible for. For GDPR Art. 30 you typically export processing records for a defined period and scope.

---

## 2. Verify integrity (recommended)

Evidence records are signed with HMAC-SHA256. To prove integrity:

```bash
# Verify a single record from the store
talon audit verify <evidence-id>

# Verify a signed export file (offline workflow)
talon audit verify --file feb-signed-evidence.json
```

`talon audit verify --file` prints:

- total records
- valid records
- invalid records
- records that could not be parsed
- unsupported records

Exit code is non-zero when any record is invalid, malformed, missing signature, or unsupported.

For ad-hoc checks from the live store, `talon audit verify <evidence-id>` remains available.

---

## 3. Package for handoff

Suggested package for auditors:

- **Reporting file(s):** CSV/JSON reduced export from step 1, named with tenant and date range (e.g. `talon-evidence-default-2026-02.csv`).
- **Integrity file:** signed JSON export (e.g. `talon-evidence-default-2026-02-signed.json`).
- **Verification log:** Output of `talon audit verify --file ...` showing validity counts.
- **Scope description:** One-line summary (e.g. "Talon evidence for tenant default, 2026-02-01 to 2026-02-28, GDPR Art. 30 processing records").

Store the package in a secure location and hand off according to your audit process.

---

## If you need GDPR Article 30

Article 30 requires records of processing activities. Talon evidence provides a technical record of AI/LLM processing: what was processed, when, policy decision, cost, and (when enabled) PII and data classification. Export the relevant date range and tenant; combine with your organisational Art. 30 documentation as needed.

### Generate a formatted RoPA

`talon compliance ropa` renders a Record of Processing Activities shaped after GDPR Art. 30(1), merging **declared facts** with **runtime facts** from the signed evidence store:

| Source | Fields |
|--------|--------|
| Declared — `talon.config.yaml` `compliance.controller` | Controller name, contact, DPO, address (Art. 30(1)(a)) |
| Declared — `agent.talon.yaml` `compliance.declarations.processing` | Purposes, data-subject categories, retention, legal basis, safeguards (Art. 30(1)(b)(c)(f)(g)) |
| Evidence-derived (signed) | Processing activities observed, personal-data identifiers detected, recipients and regions, third-country transfers (Art. 30(1)(c)(d)(e)), technical measures |

```bash
# Prerequisite: fill in declarations with your DPO
#   talon.config.yaml -> compliance.controller
#   agent.talon.yaml  -> compliance.declarations  (see configuration reference)

# HTML (print-to-PDF-ready) for a date range
talon compliance ropa --format html --from 2026-01-01 --to 2026-06-30 --output ropa.html

# JSON for machine checks; scope by tenant/agent as needed
talon compliance ropa --format json --tenant default --agent support-agent
```

Missing declarations never fail the command: they are listed as warnings on stderr and rendered as flagged "DECLARATION MISSING" sections, so the document itself tells you what to complete before auditor handoff. That is a product strength — Talon does not fake completeness. See [How to clear DECLARATION MISSING blocks in RoPA exports](ropa-declarations.md) for the field-by-field checklist, [Configuration reference — Compliance declarations](../reference/configuration.md#compliance-declarations-auditor-exports) for the declaration schema, and `examples/auditor-pack/` for a generated sample with declarations filled in.

The output is supporting records for GDPR Art. 30 review — generated from HMAC-signed evidence plus your declared facts — not a completed legal filing. Review with your DPO.

## If you need EU AI Act Annex IV technical documentation

`talon compliance annex-iv` renders a technical-documentation pack shaped after EU AI Act Annex IV, combining declared system facts with runtime records:

| Source | Fields |
|--------|--------|
| Declared — `agent.talon.yaml` `compliance.declarations.system` | System description, intended purpose, human-oversight arrangements (Annex IV s.1, Art. 14) |
| Evidence-derived (signed) | Models/providers observed, policy denials and reasons, plan-review (human oversight) events, routing/egress decisions, audited memory writes (s.3, s.5, s.6, s.9) |

```bash
talon compliance annex-iv --format html --output annex-iv.html
talon compliance annex-iv --format json --tenant default --agent support-agent
```

The pack explicitly lists the Annex IV items Talon **cannot** produce (model development process, performance metrics, declaration of conformity) with their owners — Talon is the deployment-governance layer, not the model provider. As with the RoPA, missing declarations are flagged in the output rather than failing the command, and the result is supporting documentation for Annex IV review, not a conformity assessment.

## If you need NIS2 / incident evidence

For incident response, use the same export and verification steps. Use timeline or evidence ID to correlate with the incident window. The signed evidence supports non-repudiation and integrity for regulators.

---

## You're done

You now know how to export evidence for reporting and integrity, verify signatures offline, and package records for auditors. Talon evidence is HMAC-signed and independently verifiable.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Cap cost per team or app | [How to cap daily spend per team or application](cost-governance-by-caller.md) |
| Understand what each evidence record contains | [Evidence store](../explanation/evidence-store.md) |
| Run Talon in CI/CD with evidence | [How to run governed LLM calls in CI/CD](cicd-pipeline-governance.md) |
| Configure retention or scope | [Configuration and environment](../reference/configuration.md) |
