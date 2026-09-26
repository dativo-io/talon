---
name: investigate-bug
description: Reproduce and root-cause a Talon bug before deciding on a fix.
disable-model-invocation: true
---

Investigate $ARGUMENTS.

1. Establish the expected contract from current code/tests/docs/issues.
2. Reproduce the reported behavior with the smallest reliable command or test.
3. Minimize the reproducer and identify the first incorrect boundary/state transition.
4. Trace data/identity/state from entry point to the failing effect.
5. Check whether the bug is:
   - local implementation error;
   - duplicated semantic path;
   - stale compatibility behavior;
   - projection/classification drift;
   - persistence/migration issue;
   - race/recovery failure;
   - trust-boundary validation issue.
6. Identify who can trigger it and the realistic blast radius.
7. Search for variants of the same pattern.
8. Propose the smallest fix and the regression test that proves it.

Do not edit code unless the user asked for a fix as well as investigation.
Do not mutate GitHub unless explicitly authorized.

Handoff with reproducer, root cause, affected contract, proposed regression, and any sibling risks.
