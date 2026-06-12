# EU compliance policy packs

Curated `.talon.yaml` policy packs for GDPR, NIS2, DORA, and the EU AI Act,
selectable from `talon init`. Each pack is a ready-made starting point that
tightens Talon's policy defaults for one regulatory regime and annotates the
generated configuration with the articles those settings *support*.

> **Claims discipline.** Packs provide supporting controls and evidence for the
> annotated articles. They do not, by themselves, make you compliant — review
> the generated policy with your DPO or counsel. See `LIMITATIONS.md`.

## Selecting packs

Every `talon init` path accepts packs:

```bash
# Interactive wizard — step "Apply EU compliance policy packs?" (multi-select)
talon init

# Starter pack + compliance overlay
talon init --pack openclaw --compliance gdpr

# Scaffold or scripted init
talon init --scaffold --compliance gdpr,nis2
talon init --provider openai --name my-agent --compliance eu-ai-act

# Everything
talon init --pack generic --compliance all

# Catalog
talon init --list-compliance
```

Multiple packs merge in order; stricter settings win (highest retention,
union of frameworks, OR of scan/block flags).

## Pack catalog

| Pack | What it configures | Supports (linked to `internal/compliance/mapping.go`) |
|------|--------------------|--------------------------------------------------------|
| `gdpr` | PII input/output scanning + redaction, EU model routing (tier 1/2), 1y detailed audit retention, redacted-prompt-only storage | GDPR Art. 5(1)(c), Art. 30, Art. 32, Art. 44-50 |
| `nis2` | Rate limits, time restrictions, full audit logging with 2y retention | NIS2 Art. 21 |
| `dora` | Strict PII blocking, cost limits, EU-only routing for all tiers, full audit with 5y retention | DORA Art. 6, Art. 11 (plus GDPR Art. 32, Art. 44-50) |
| `eu-ai-act` | Input/output scanning, full audit trail, limited risk level, human oversight via plan review gate | EU AI Act Art. 9, Art. 11, Art. 13, Art. 14 |

## How the article links work

Each control inside a pack carries a structured annotation:

```yaml
audit:
  # supports: gdpr Art. 30 — internal/evidence/store.go (Processing records via signed evidence export)
  log_level: detailed
  retention_days: 365
```

Every `supports:` line must reference a `Framework + Article` entry in
`compliance.DefaultMappings()` (`internal/compliance/mapping.go`) — the same
mapping table that drives `talon compliance report` and the dashboard
compliance mode. A link-integrity test
(`internal/pack/overlay_mapping_test.go`) fails the build if an annotation
points at an article Talon has no shipping control for, so packs can never
over-claim.

The generated `agent.talon.yaml` also gets a header listing every applied pack
and the supported articles, so the provenance survives in the file an auditor
actually reads.

## Scope: curated YAML, not custom Rego

Packs are curated YAML that configures Talon's **embedded** Rego policies
(`internal/policy/rego/`). Loading custom Rego modules at runtime is
deliberately out of scope for these packs (planned v2 — see
`policies/README.md`). This keeps the single-binary, zero-config guarantee:
what a pack enables is exactly what `talon validate` and the policy engine
already enforce.

## Verifying the result

```bash
talon validate                      # schema + policy validation
talon compliance report --framework gdpr   # see covered controls + evidence
```

The dashboard compliance tab (`/dashboard` → Compliance) shows the same
per-framework coverage with evidence counts, derived from the identical
mapping table.
