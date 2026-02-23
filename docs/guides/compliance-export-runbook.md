# How to export evidence for auditors

Use this runbook to export Talon evidence for auditors or regulators (e.g. GDPR Article 30, NIS2). Steps: export evidence in a chosen format, verify integrity (HMAC), and package for handoff.

---

## 1. Export evidence

**CLI:** Export a date range or limit. Formats: `csv` or `json`.

```bash
# CSV for a date range (e.g. last month)
talon audit export --format csv --from 2026-02-01 --to 2026-02-28

# JSON with a limit
talon audit export --format json --limit 1000
```

**API:** Authenticate with `X-Talon-Key` and call:

```http
POST /v1/evidence/export
Content-Type: application/json

{"tenant_id": "default", "format": "json", "limit": 1000}
```

Exports include fields such as evidence ID, timestamp, tenant_id, agent_id, policy decision, cost, and (when configured) PII flags and data tier. For exact fields see the API response or CSV headers.

**Scope:** Use `tenant_id` (in API body or CLI context) so the export is scoped to the tenant you are responsible for. For GDPR Art. 30 you typically export processing records for a defined period and scope.

---

## 2. Verify integrity (optional but recommended)

Evidence records are signed with HMAC-SHA256. To prove integrity, verify a sample or the full set:

```bash
# Verify a single record
talon audit verify <evidence-id>

# List IDs from your export, then verify each (or a sample)
talon audit list --limit 100
talon audit verify req_xxxxxxxx
```

Document the verification (e.g. "Verified N evidence IDs; signature VALID"). If you need to verify in bulk, script `talon audit verify` over the IDs from your export.

---

## 3. Package for handoff

Suggested package for auditors:

- **Export file(s):** CSV or JSON from step 1, named with tenant and date range (e.g. `talon-evidence-default-2026-02.csv`).
- **Verification log:** Short note or log listing evidence IDs verified and result (e.g. "signature VALID").
- **Scope description:** One-line summary (e.g. "Talon evidence for tenant default, 2026-02-01 to 2026-02-28, GDPR Art. 30 processing records").

Store the package in a secure location and hand off according to your audit process.

---

## If you need GDPR Article 30

Article 30 requires records of processing activities. Talon evidence provides a technical record of AI/LLM processing: what was processed, when, policy decision, cost, and (when enabled) PII and data classification. Export the relevant date range and tenant; combine with your organisational Art. 30 documentation as needed.

## If you need NIS2 / incident evidence

For incident response, use the same export and verification steps. Use timeline or evidence ID to correlate with the incident window. The signed evidence supports non-repudiation and integrity for regulators.
