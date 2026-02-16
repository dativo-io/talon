# Policies

Rego policy source files are embedded into the Go binary at build time.

**Location:** `internal/policy/rego/*.rego`

They are co-located with the policy engine package that consumes them
via Go's `//go:embed` directive. This is standard Go practice for
embedded assets.

## Policy Files

| File | Purpose |
|------|---------|
| cost_limits.rego | Per-request, daily, monthly budget enforcement |
| rate_limits.rego | RPM and concurrency limits |
| time_restrictions.rego | Business hours and weekend restrictions |
| tool_access.rego | Allowlist + forbidden pattern checks |
| data_classification.rego | PII-based tier determination + EU routing |
| secret_access.rego | ACL with glob pattern matching |
| memory_governance.rego | Constitutional AI category governance |

## Customization

Custom Rego policies are planned for v2. Current policies are
compiled into the binary and configured via `.talon.yaml`.
