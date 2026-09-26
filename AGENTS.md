# Dativo Talon — Engineering Contract

This file defines repository-wide guidance for AI coding agents and human contributors using them.
Keep it concise: durable invariants belong here; implementation detail belongs in code, tests, docs, or the issue tracker.

## Authority and source of truth

Before changing code, establish the relevant source of truth.

1. Explicit task instructions.
2. Current code and tests for shipped behavior.
3. The current GitHub issue being implemented and issue #265 for active product/architecture direction.
4. `README.md`, `ROADMAP.md`, `LIMITATIONS.md`, `CONTRIBUTING.md`, and `docs/**` for public product truth.
5. Historical issue text, demos, generated artifacts, and agent memory only as supporting context.

If sources conflict, surface the conflict. Do not silently reconcile it.
Do not implement roadmap behavior merely because it appears in an old document or comment.

## Product and trust boundaries

The stable product object is the AI use case (`agent` in CLI/config).

Preserve these boundaries unless the active issue explicitly changes them:

- Talon controls only traffic and actions available through an actual enforcement boundary.
- Local shell, filesystem, browser, and direct API actions that bypass Talon are not controlled by Talon.
- Attribution is not authentication.
- Admin/operator identity, workload identity, approver identity, and session/run/operation identifiers are distinct concepts.
- Evidence is tamper-evident/verifiable operational proof, not immutability, completeness proof, or a compliance determination.
- External runtimes own their workflow/agent-loop lifecycle unless Talon explicitly owns a particular state transition.
- Talon is not a generic orchestration framework, workflow engine, router optimizer, observability suite, GRC platform, identity provider, vector database, or universal memory layer.
- Parked work is not an implicit dependency and must not shape active implementation unless it is formally activated.

## Investigate before editing

Never speculate about code that has not been inspected.

For non-trivial work:

- read the complete current issue and linked dependencies;
- inspect the affected implementation and nearest tests;
- identify the authoritative contract and existing source of truth;
- distinguish shipped behavior from target behavior;
- identify trust, persistence, compatibility, and failure boundaries;
- prefer an implementation plan before editing when multiple packages or durable contracts are involved.

Small, isolated fixes can proceed after focused inspection.

## Scope discipline

Implement the smallest coherent change that satisfies the active contract.

Do not:

- add unrelated cleanup or opportunistic refactors;
- create abstractions for hypothetical future requirements;
- add compatibility with obsolete protocols unless explicitly required;
- duplicate an existing semantic model, policy path, state machine, or projection;
- create a second source of truth for data already derived canonically elsewhere;
- revive parked capability because adjacent code already exists.

If unrelated technical debt is discovered, leave it unchanged and report it in the handoff unless it blocks correctness.

## Contract surfaces

Treat these as compatibility-sensitive contracts, not ordinary implementation details:

- persisted SQLite schemas and migrations;
- signed evidence fields and verification;
- YAML configuration and defaults;
- HTTP/JSON response shapes;
- machine error/reason codes;
- MCP/protocol behavior;
- provider request/response compatibility;
- CLI output intentionally consumed by scripts;
- exported Go APIs.

Before changing one, identify compatibility, migration, rollback, and historical-data implications.

Prefer unexported APIs unless a public surface is genuinely required.

## State and failure correctness

For state-changing features, reason explicitly about:

- desired/source state;
- active runtime state;
- persistent state;
- historical evidence;
- retry/idempotency;
- concurrent execution;
- crash/restart recovery;
- failures between transition steps.

Do not call a multi-step operation atomic unless it has the required transactional boundary.

For durable/runtime transitions, test at least one failure between meaningful steps when the risk warrants it, for example:

- source write -> validation;
- validation -> runtime activation;
- runtime activation -> evidence commit;
- authorization -> dispatch;
- dispatch -> result persistence.

## Preventive-control proof

When Talon's promise is preventive, tests must prove the forbidden side effect did not occur.

A denial response alone is insufficient when the contract claims that a provider, tool, or action was never reached.
Use observable proof such as mock invocation counts, upstream receipts, persisted attempt state, or equivalent boundary evidence.

## Security

Validate at trust boundaries.

Treat request metadata, MCP/client metadata, external action schemas, provider responses, external workflow results, and input-derived paths as untrusted until validated.

- Never infer authority from attribution metadata.
- Never log or persist credentials, raw authorization tokens, signing keys, or vault keys.
- Never use substring checks as filesystem traversal protection; use canonical path relationships and existing helpers.
- Bound allocations and work derived from untrusted input.
- Preserve fail-closed behavior where the active contract requires prevention.

When reviewing a security-sensitive issue, identify who can trigger it: unauthenticated remote caller, authenticated workload, MCP client, provider, external runtime, or local operator.

## Go implementation

Follow existing package conventions before introducing a new pattern.

- Propagate `context.Context` across blocking/I/O boundaries.
- Preserve typed/domain errors when callers depend on them.
- Keep interfaces narrow and define them near consumers.
- Prefer explicit typed state over stringly-typed behavior.
- Avoid global mutable state.
- Preserve deterministic ordering where output becomes evidence, an API, or a testable contract.
- Use `gofmt` on changed Go files.
- Comments should explain non-obvious reasons or invariants, not restate code.
- Do not add telemetry mechanically; follow existing repository semantics and instrumentation patterns.

Before adding a third-party dependency, establish that the standard library and existing module graph are insufficient and account for binary-size, security, and maintenance cost.

## Generated and mirrored artifacts

Before editing a generated, embedded, mirrored, or derived artifact, identify its canonical source.

Change the canonical source and run the repository generator/check.
Do not fix drift by manually editing multiple generated copies unless the repository explicitly defines them as independently maintained.

## Testing

Tests prove contracts; they do not define product direction.

- Bug fixes should reproduce the bug before or alongside the fix.
- Contract changes should test observable behavior rather than implementation trivia.
- Prefer extending the closest existing table-driven suite over creating overlapping test hierarchies.
- Never weaken/delete a valid test merely to make a change pass.
- Never hide failures with sleeps, retries, ignored errors, or fixture-specific branches.
- Performance claims require measurement or benchmarks, not intuition.
- Smoke/E2E tests must exercise the claimed behavior; process startup or HTTP 200 alone is not enough for enforcement, denial, fallback, approval, or evidence claims.

Run the narrowest relevant tests during iteration. Run broader repository verification before PR/release-level handoff when warranted by the change.

See `.claude/rules/testing.md` for Claude Code execution guidance.

## Git, GitHub, and external systems

Never discard work you did not create.

Without explicit user instruction, do not:

- run `git reset --hard`, destructive `git clean`, or force-push;
- delete branches/tags or rewrite published history;
- push commits;
- create, edit, close, comment on, or relabel GitHub issues/PRs;
- create releases/tags;
- mutate cloud/infrastructure resources.

Local inspection and reversible source edits are allowed.
Do not commit unless the task explicitly permits commits.

## Documentation and claims

Documentation must distinguish shipped behavior from target behavior.

- Do not claim Talon makes a deployment compliant.
- Use "supporting controls/evidence" for regulatory mappings.
- Say tamper-evident/verifiable, not immutable, unless an implementation truly provides immutability.
- Say attribution, not authentication, for client-asserted metadata.
- State enforcement boundaries honestly.

User-facing behavior changes should update the relevant docs, examples, `LIMITATIONS.md`, and/or `CHANGELOG.md` when required by the existing contribution contract.

## Completion

Before claiming completion:

- inspect the final diff;
- remove temporary/debug files;
- confirm no secrets or accidental generated artifacts were added;
- run the required verification;
- compare the result with the original issue acceptance criteria.

Handoff must state:

- what changed;
- which contract it satisfies;
- tests actually run and their results;
- unresolved limitations, risks, or follow-up work.
