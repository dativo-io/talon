# Starter Policy Library

Ready-to-use OPA/Rego policies for common governance scenarios. Copy and
customize for your needs.

## Policies

| Policy | File | What It Does |
|--------|------|-------------|
| **Cost Budget** | `cost-budget.rego` | Deny requests exceeding daily/monthly cost limits |
| **PII Blocking** | `pii-block.rego` | Block requests with high-sensitivity PII (tier 3: IBAN, SSN, etc.) |
| **Model Allowlist** | `model-allowlist.rego` | Restrict which models callers can use |
| **Data Residency** | `data-residency.rego` | Ensure sensitive data stays in EU-hosted models |

## How to Use

1. Copy the policy file to `policies/rego/` in your Talon project
2. Edit thresholds and rules to match your requirements
3. Test with `opa test policies/rego/ -v`
4. Restart Talon — policies are loaded automatically

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
tier, caller info). See each policy file for the expected input shape.

## Testing

```bash
# Run all Rego tests
opa test policies/rego/ -v

# Test a specific policy with sample input
echo '{"model": "gpt-4o", "allowed_models": ["gpt-4o-mini"]}' | \
  opa eval -d examples/policies/model-allowlist.rego -I 'data.talon.gateway.allow'
```
