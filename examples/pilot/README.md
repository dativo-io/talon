# Production pilot starter

`talon.config.yaml` is a company baseline policy to start a pilot from: one provider, PII blocked, per-use-case budgets with company ceilings, two forbidden actions, and example argument rules for a refund (above 50.00 approval, above 500.00 deny). Copy it to `/etc/talon/talon.config.yaml`, adjust the lines marked `ADJUST` and the thresholds, then follow the [production pilot runbook](../../docs/guides/production-pilot.md).

Every AI use case registered with `talon agents add` inherits it. A use case's own file can add restrictions; it cannot lift a constraint.

`TestE2E_PilotJourney` loads this exact file (with the provider URL pointed at a test provider) and checks that a use case trying to raise the refund bands or to perform a forbidden action is still held to the company policy.
