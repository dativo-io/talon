---
name: implement-issue
description: Implement a Dativo Talon GitHub issue from investigation through verified handoff.
disable-model-invocation: true
---

Implement GitHub issue $ARGUMENTS.

## Before editing

1. Read the complete current issue and linked blocking/dependent issues.
2. If the issue affects product/architecture direction, read current #265.
3. Inspect the relevant implementation and nearest tests.
4. State:
   - current behavior;
   - target behavior;
   - invariants and trust boundaries;
   - compatibility/persistence implications;
   - explicit non-goals.
5. Identify the smallest coherent implementation.
6. For non-trivial changes, present the plan before editing.

Do not treat historical comments, old docs, or agent memory as newer than the current issue/code/tests.

## Implement

- Stay inside issue scope.
- Reuse canonical state, policy, evidence, projection, and error paths.
- Do not create speculative abstractions or duplicate sources of truth.
- Add the lowest useful regression first, then implementation.
- Add integration/E2E coverage when the contract crosses a real storage/API/runtime/protocol boundary.
- Update docs/CHANGELOG/LIMITATIONS only to describe behavior actually implemented.

## Verify

Run, in order as appropriate:

1. focused/changed-package tests;
2. relevant integration tests;
3. relevant E2E/smoke proof;
4. broader repository checks when required.

Inspect the final diff and compare it against every acceptance criterion.

Do not commit, push, mutate the issue, or create a PR unless the user's task explicitly authorizes it.

## Handoff

Report:

- files/areas changed;
- important design decisions;
- acceptance criteria satisfied;
- exact tests run and results;
- unresolved limitations, risks, or follow-up work.
