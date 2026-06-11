# How to clear DECLARATION MISSING blocks in RoPA exports

Use this guide when `talon compliance ropa` (or `talon compliance annex-iv`) renders flagged **DECLARATION MISSING** sections or prints warnings on stderr. Talon does not fake completeness: it fills what can be **proven from signed evidence** and clearly flags what your organisation must **declare**. That is intentional — a trustworthy compliance story, not "one-click compliance."

Missing declarations never fail the command. Fill the fields below, regenerate, and the placeholders disappear.

---

## Where declarations live

| File | Owner | Supplies |
|------|-------|----------|
| `talon.config.yaml` | DevOps / platform + DPO | Controller identity (GDPR Art. 30(1)(a)) |
| `agent.talon.yaml` (or `--policy`) | Governance / compliance | Processing facts (RoPA) and system facts (Annex IV) |

Run export commands from the directory where those files exist, or pass `--config` / `--policy` explicitly. `config.Load()` reads `./talon.config.yaml` (or `~/.talon/talon.config.yaml`) automatically.

---

## 1. Controller — `talon.config.yaml`

Required for RoPA Section **1. Controller (Art. 30(1)(a))**:

| Field | Required? |
|-------|-----------|
| `compliance.controller.name` | Yes |
| `compliance.controller.contact` **or** `dpo_contact` | At least one |
| `address`, `representative` | Recommended |

```yaml
compliance:
  controller:
    name: "Example GmbH"
    contact: "privacy@example.eu"
    dpo_contact: "dpo@example.eu"
    address: "Examplestr. 1, 10115 Berlin, Germany"
    # representative: "EU Rep B.V."   # where applicable (GDPR Art. 27)
```

---

## 2. Processing — `agent.talon.yaml`

Add under the existing `compliance:` block as `declarations.processing`.

**Required** (each missing field → stderr warning + flagged section):

| YAML field | RoPA section |
|------------|--------------|
| `purposes` | 3. Purposes (Art. 30(1)(b)) |
| `data_subject_categories` | 4. Categories (Art. 30(1)(c)) |
| `retention_period` | 7. Retention (Art. 30(1)(f)) |

**Optional** (no warning if omitted; improves the report):

| YAML field | Effect |
|------------|--------|
| `personal_data_categories` | Extra row in Section 4 (merged with PII observed in evidence) |
| `legal_basis` | Appended to Section 3 |
| `safeguards` | Extra row in Section 8 (organisational measures) |

```yaml
compliance:
  frameworks: [gdpr, eu-ai-act]
  data_residency: eu
  declarations:
    processing:
      purposes:
        - "customer support ticket triage"
        - "internal AI assistance"
      data_subject_categories:
        - "customers"
        - "employees"
      personal_data_categories:
        - "contact details"
        - "payment identifiers"
        - "support ticket content"
      retention_period: "90 days after ticket closure"
      legal_basis: "contract (Art. 6(1)(b))"
      safeguards: "Role-based access; vendor DPAs on file; signed evidence retained for audit review"
    system:                          # Annex IV only — see below
      system_description: "..."
      intended_purpose: "..."
      oversight_description: "..."
```

`declarations.system` is for **`talon compliance annex-iv`**, not RoPA. See [Configuration reference — Compliance declarations](../reference/configuration.md#compliance-declarations-auditor-exports) for the full schema.

---

## 3. What does not need declarations

These RoPA sections come from **signed evidence** only:

| Section | Source |
|---------|--------|
| 2. Processing activities observed | Tenant/agent activity in evidence store |
| 5. Recipients | Data-flow evidence (provider, region) |
| 6. Third-country transfers | Non-EU/LOCAL destinations in data-flow evidence |
| 8. Technical measures | Talon controls + optional `safeguards` declaration |

Section **4** can be partly evidence-derived: if Talon has observed PII (e.g. `email`, `iban`), an "observed in evidence" row appears even without `personal_data_categories`. You still need `data_subject_categories` declared, or stderr warns and Section 4 stays missing when there is no evidence either.

---

## 4. Regenerate

After editing both files:

```bash
talon compliance ropa --format html --output ropa.html
talon compliance ropa --format json --output ropa.json
```

Useful flags:

- `--policy path/to/agent.talon.yaml` — when not using the default from `default_policy` in config
- `--from 2026-01-01 --to 2026-06-30` — scope evidence by date
- `--tenant acme --agent support-agent` — narrow the export

A complete configuration produces **no** stderr warnings and **no** `missing: true` sections in JSON output.

### Residency-consistency warning

One warning is independent of declarations: when `compliance.data_residency` is
`eu` but the data-flow evidence shows destinations **outside EU/LOCAL regions**
(Section 6 lists them), the export adds a `consistency:` warning. Your
declaration and your observed traffic disagree, and an auditor reading the
document would see the same thing. Two ways to resolve it:

- **Enforce the declaration** — set `llm.routing.data_sovereignty_mode: eu_strict`
  in `talon.config.yaml` so non-EU providers are denied at routing time
  (requires an EU or local provider to be configured).
- **Document the transfer** — keep the non-EU provider and record the transfer
  mechanism (SCCs, adequacy decision) with your DPO; Section 6 stays as the
  factual record.

---

## 5. Checklist vs. your export

| Flagged section | Fix |
|-----------------|-----|
| **1. Controller** | Add `compliance.controller` in `talon.config.yaml` |
| **3. Purposes** | Add `declarations.processing.purposes` in agent policy |
| **4. Categories** | Add `data_subject_categories` (and run governed traffic, or add `personal_data_categories`) |
| **7. Retention** | Add `declarations.processing.retention_period` |

Fill these with your DPO — Talon stores declarations; it does not validate legal correctness.

---

## 6. Sample pack

The committed sample in [`examples/auditor-pack/`](../../examples/auditor-pack/) uses the Example GmbH declarations above merged with synthetic demo evidence. Regenerate locally with `make auditor-pack`.

---

## Related docs

| Doc | Description |
|-----|-------------|
| [How to export evidence for auditors](compliance-export-runbook.md) | Full export, verify, and handoff workflow |
| [Configuration reference — Compliance declarations](../reference/configuration.md#compliance-declarations-auditor-exports) | Full YAML schema for both config files |

The output is **supporting records for GDPR Art. 30 review** — not a completed legal filing. Review with your DPO.
