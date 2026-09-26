# Session subsystem invariants

These rules apply when changing `internal/session/**` and session projections.

A session is application correlation, cost, and timeline. It is not a generic workflow, approval, run, or business-operation state machine.

Keep separate:

- AI use case / agent identity;
- application session correlation;
- native run lifecycle;
- logical operation lifecycle;
- approval lifecycle;
- execution attempts.

Client/vendor session and orchestration metadata are attribution unless separately authenticated.

Issue #401 owns the current simplification target. Current shipped code may still contain pre-#401 vocabulary; do not opportunistically rewrite it unless the task is #401 or explicitly depends on that contract.

For work implementing #401, preserve these target invariants:

- persisted/public session status becomes exactly `open | completed`;
- completion is explicit, terminal, and idempotent;
- completed sessions do not accept later accounting/activity mutations;
- `managed_by` is lifecycle-manager attribution only, not authentication/authorization;
- `source` remains identity provenance and is not a second ownership concept;
- failures/attention are derived from evidence/run/operation facts, not invented session failure states.

Session summaries, fleet health, API, CLI, and dashboard projections should share one semantic source rather than recompute independently.

Concurrency tests are required where completion races with reservation/settlement or other session mutation.
