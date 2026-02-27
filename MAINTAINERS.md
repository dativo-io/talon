# Maintainers

## Core Maintainers (full merge rights)

| Name | GitHub | Focus Areas |
|------|--------|-------------|
| Sergiusz | [@sergiusz](https://github.com/sergiusz) | Architecture, policy engine, gateway, strategy |

## Reviewers (review + approve, no merge)

Open for community members after 3+ merged PRs. If you're interested in
becoming a reviewer, start by contributing to areas you're familiar with and
engage in PR reviews.

## Review Rules

- All PRs need 1 maintainer approval
- Security-sensitive changes (secrets vault, HMAC signing, auth) need 2 approvals
- Breaking changes require an RFC discussion in GitHub Discussions first
- Squash merge preferred for clean history

## Areas of Ownership

| Area | Primary | Notes |
|------|---------|-------|
| `internal/gateway/` | @sergiusz | LLM API proxy pipeline |
| `internal/policy/` | @sergiusz | OPA/Rego policy engine |
| `internal/evidence/` | @sergiusz | Audit trail, HMAC signing |
| `internal/secrets/` | @sergiusz | Encrypted vault, ACL |
| `internal/classifier/` | @sergiusz | PII detection patterns |
| `docs/` | Community welcome | Docs contributions encouraged |
| `examples/` | Community welcome | New examples and integrations |
| `policies/rego/` | Community welcome | Policy contributions |

## Becoming a Maintainer

1. Make 3+ merged PRs with substantive changes
2. Participate in code reviews and discussions
3. Demonstrate understanding of the project's compliance-first architecture
4. Be nominated by an existing maintainer
