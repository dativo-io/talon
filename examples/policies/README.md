# Starter Policy Library (reference for the planned custom-policy surface)

Example OPA/Rego policies for common governance scenarios — a **reference
library, not a loading mechanism**. Talon does not load custom Rego today:
the shipped policies are compiled into the binary (`internal/policy`,
`//go:embed rego/*.rego`) and configured via `.talon.yaml`; custom Rego
loading is planned for v2 (see `policies/README.md`). Use these files to
prototype and test policy logic standalone with the `opa` CLI, and to
express the rules you'll want when the custom surface ships. The governance
outcomes they describe (cost budgets, PII blocking, model allowlists, data
residency) are available TODAY via `.talon.yaml` configuration
(`policies.cost_limits`, PII actions, `allowed_models`/`allowed_providers`,
`compliance.data_residency`).

## Policies

| Policy | File | What It Does |
|--------|------|-------------|
| **Cost Budget** | `cost-budget.rego` | Deny requests exceeding daily/monthly cost limits |
| **PII Blocking** | `pii-block.rego` | Block requests with high-sensitivity PII (tier 3: IBAN, SSN, etc.) |
| **Model Allowlist** | `model-allowlist.rego` | Restrict which models agents can use |
| **Data Residency** | `data-residency.rego` | Ensure sensitive data stays in EU-hosted models |

## How to Use (today)

1. Pick the scenario you need and read its `.rego` file — the `input` shape
   documents which request facts the rule keys on
2. Configure the equivalent shipped control in your `.talon.yaml`
   (cost limits, PII action, model allowlist, data residency)
3. Iterate on the Rego logic standalone with `opa eval` (see Testing below)
   so it's ready for the v2 custom-policy surface

These files are NOT loaded by Talon — there is no `policies/rego/`
auto-load, and restarting Talon does not pick them up.

## Writing Custom Policies

All policies follow the same pattern:

```rego
package talon.gateway

import rego.v1

default allow := true

deny contains reason if {
    # your condition here
    reason := "human-readable explanation"
}

allow := false if {
    count(deny) > 0
}
```

The `input` object contains request metadata (model, cost, PII findings, data
tier, agent info). See each policy file for the expected input shape.

## Testing

```bash
# Evaluate a policy against sample input (standalone, no Talon involved)
echo '{"model": "gpt-4o", "allowed_models": ["gpt-4o-mini"]}' | \
  opa eval -d examples/policies/model-allowlist.rego -I 'data.talon.gateway.allow'

# Run Rego unit tests you write alongside these files
opa test examples/policies/ -v
```
