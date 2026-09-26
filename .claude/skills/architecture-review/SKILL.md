---
name: architecture-review
description: Review a proposed or existing Talon change against current architecture and product boundaries without implementing it.
disable-model-invocation: true
---

Review $ARGUMENTS without editing code.

1. Read current #265 and the relevant active issue(s).
2. Inspect the existing implementation and tests; do not review from issue text alone.
3. Identify:
   - canonical domain owner;
   - adapters and trust boundaries;
   - persisted/wire/config contracts;
   - source-of-truth relationships;
   - failure/retry/recovery semantics;
   - enforcement boundary and bypasses;
   - evidence/projection consequences.
4. Check for duplicated policy/state/projection paths and accidental scope expansion.
5. Separate:
   - shipped behavior;
   - active target;
   - parked/future capability.
6. Evaluate migration/rollback and compatibility consequences.
7. Define the minimum test pyramid needed to prove the design, including negative proof and failure injection where relevant.
8. Recommend the smallest architecture that satisfies the active contract.

Do not create issues, comments, branches, commits, or PRs unless explicitly authorized.

Return findings ordered by correctness/security risk first, then complexity/maintainability, then optional improvements.
