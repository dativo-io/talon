# Dativo Talon — Engineering Contract

Repository-wide guidance for AI coding agents and contributors using them.
Keep durable invariants here; implementation detail belongs in code, tests, docs, or GitHub issues.

## Authority

Before changing code, establish the relevant source of truth:

1. Explicit task instructions.
2. Current code and tests for shipped behavior.
3. The current GitHub issue and #265 for active product/architecture direction.
4. README.md, ROADMAP.md, LIMITATIONS.md, CONTRIBUTING.md, and docs/** for public product truth.
5. Historical issue text, demos, generated artifacts, and agent memory only as supporting context.

If sources conflict, surface the conflict. Do not silently reconcile it or implement stale roadmap behavior.

## Product and trust boundaries

The stable product object is the AI use case (`agent` in CLI/config).

Preserve these boundaries unless an active issue explicitly changes them:

- Talon controls only traffic/actions available through an actual enforcement boundary.
- Local shell, filesystem, browser, and direct API actions bypassing Talon are not controlled.
- Attribution is not authentication.
- Admin/operator, workload, approver, and session/run/operation identities are distinct.
- Evidence is tamper-evident/verifiable proof, not immutability, completeness proof, or a compliance determination.
- External runtimes own workflow/agent-loop lifecycle unless Talon explicitly owns a transition.
- Talon is not a generic orchestrator, workflow engine, router optimizer, observability suite, GRC platform, IdP, vector DB, or universal memory layer.
- Parked work is not an implicit dependency.

## Investigate before editing

Never speculate about code that has not been inspected.

For non-trivial work:
- read the complete current issue and linked dependencies;
- inspect affected implementation and nearest tests;
- identify the authoritative contract and existing source of truth;
- distinguish shipped behavior from target behavior;
- identify trust, persistence, compatibility, and failure boundaries;
- present a plan before editing when multiple packages or durable contracts are involved.

Small isolated fixes can proceed after focused inspection.

## Scope discipline

Implement the smallest coherent change that satisfies the active contract.

Do not:
- add unrelated cleanup or opportunistic refactors;
- create abstractions for hypothetical future requirements;
- preserve obsolete protocols unless explicitly required;
- duplicate a semantic model, policy path, state machine, or projection;
- create a second source of truth;
- revive parked capability because adjacent code exists.

Report unrelated technical debt in the handoff unless it blocks correctness.

## Contract surfaces

Treat these as compatibility-sensitive:
- SQLite schemas/migrations;
- signed evidence and verification;
- YAML configuration/defaults;
- HTTP/JSON shapes;
- machine reason/error codes;
- MCP/protocol behavior;
- provider request/response compatibility;
- script-consumed CLI output;
- exported Go APIs.

Before changing one, identify compatibility, migration, rollback, and historical-data implications.
Prefer unexported APIs unless a public surface is genuinely required.

## State and failure correctness

For state-changing features, reason explicitly about desired state, active runtime state, persistence, evidence, retry/idempotency, concurrency, crash recovery, and failures between transitions.

Do not call a multi-step operation atomic without the required transactional boundary.
Where risk warrants it, test failures between meaningful steps such as source-write→validation, validation→activation, activation→evidence, authorization→dispatch, or dispatch→result persistence.

## Preventive-control proof

When Talon's promise is preventive, prove the forbidden side effect did not occur.
A denial response alone is insufficient when the contract claims a provider, tool, or action was never reached.
Use mock invocation counts, upstream receipts, persisted attempt state, or equivalent boundary evidence.

## Security

Validate at trust boundaries. Treat request metadata, MCP/client metadata, external action schemas, provider responses, external workflow results, and input-derived paths as untrusted until validated.

- Never infer authority from attribution metadata.
- Never log/persist credentials, raw authorization tokens, signing keys, or vault keys.
- Never use substring checks as filesystem traversal protection.
- Bound work/allocation derived from untrusted input.
- Preserve fail-closed behavior where the active contract requires prevention.

For security-sensitive issues, identify who can trigger the behavior: remote caller, authenticated workload, MCP client, provider, external runtime, or local operator.

## Go implementation

Follow existing package conventions before introducing a new pattern.

- Propagate context across blocking/I/O boundaries.
- Preserve typed/domain errors when callers depend on them.
- Keep interfaces narrow and near consumers.
- Prefer explicit typed state over stringly-typed behavior.
- Avoid global mutable state.
- Preserve deterministic ordering where output becomes evidence/API/contract.
- Run gofmt on changed Go files.
- Comments explain non-obvious reasons/invariants, not what code already says.
- Follow existing telemetry semantics rather than adding instrumentation mechanically.

Before adding a dependency, establish that stdlib/existing modules are insufficient and account for binary-size, security, and maintenance cost.

## Generated and mirrored artifacts

Before editing a generated, embedded, mirrored, or derived artifact, identify its canonical source.
Change the canonical source and run the repository generator/check.
Do not fix drift by manually editing multiple generated copies unless both are explicitly hand-maintained.

## Testing

Tests prove contracts; they do not define product direction.

- Bug fixes should include a regression reproducing the bug.
- Contract changes test observable behavior, not implementation trivia.
- Prefer the closest existing table-driven suite over redundant test hierarchies.
- Never weaken/delete a valid test merely to make a change pass.
- Never hide failures with sleeps, retries, ignored errors, or fixture-specific branches.
- Performance claims require measurement/benchmarks.
- Smoke/E2E tests must exercise the claimed feature, not merely startup or HTTP 200.
- Enforcement tests prove the forbidden side effect did not happen when that is part of the claim.

Run narrow relevant tests during iteration and broader verification before PR/release handoff when warranted.
See `.claude/rules/testing.md` for Claude Code execution guidance.

## Git, GitHub, and external systems

Never discard work you did not create.

Without explicit user instruction, do not:
- run destructive reset/clean or force-push;
- delete branches/tags or rewrite published history;
- push commits;
- create/edit/close/comment on GitHub issues or PRs;
- create releases/tags;
- mutate cloud/infrastructure resources.

Local inspection and reversible edits are allowed. Do not commit unless the task permits commits.

## Documentation and claims

Distinguish shipped behavior from target behavior.
Do not claim Talon makes a deployment compliant.
Use "supporting controls/evidence" for regulatory mappings.
Say tamper-evident/verifiable rather than immutable unless immutability truly exists.
Say attribution rather than authentication for client-asserted metadata.
State enforcement boundaries honestly.

Update relevant docs/examples/LIMITATIONS.md/CHANGELOG.md when the existing contribution contract requires it.

## Completion

Before claiming completion:
- inspect the final diff;
- remove temporary/debug files;
- confirm no secrets or accidental artifacts were added;
- run required verification;
- compare the result with the issue acceptance criteria.

Handoff states what changed, which contract it satisfies, exact tests run/results, and unresolved limitations or risks.
