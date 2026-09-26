---
paths:
  - "**/*.go"
  - "tests/**"
  - "Makefile"
---

# Claude Code testing workflow

Use the narrowest relevant test during iteration.

Typical progression:

1. focused test: `go test ./internal/<pkg> -run <TestName> -count=1`;
2. affected package tests;
3. relevant integration/E2E/smoke target;
4. broader `make test` / `make check` when the change is stable and the handoff requires repository-level confidence.

Do not launch multiple heavyweight Talon test suites concurrently.

Testing principles:

- A bug fix should have a regression that fails on the old behavior.
- Prefer extending the closest existing table-driven test over creating redundant suites.
- Test observable contracts rather than implementation details.
- Enforcement tests must prove the forbidden side effect did not occur when that is part of the claim.
- E2E/smoke tests must exercise the actual feature; server startup, status 200, or row existence alone is not proof of policy/action behavior.
- Stateful changes should include failure/concurrency/crash cases proportional to the contract risk.
- Use race-enabled repository targets where the Makefile defines them; do not silently substitute weaker commands for final verification.
- Do not add arbitrary sleeps to fix timing tests. Prefer explicit synchronization, bounded timeouts, deterministic clocks, or observable state.
- Do not weaken an assertion because the implementation currently disagrees with the active contract.

At handoff, report the exact commands run and whether they passed.
