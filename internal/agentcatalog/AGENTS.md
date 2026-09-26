# Agent catalog invariants

These rules apply when changing `internal/agentcatalog/**` or catalog-backed discovery/reload behavior.

The catalog is the canonical runtime discovery path for configured AI use cases.

Preserve the shipped foundations unless an active issue explicitly changes them:

- one configured `agents_dir`, recursively scanned;
- one operational identity per unique `agent.name`;
- duplicate names fail closed and identify the conflicting sources;
- a never-valid config is reported as a path/config issue, not invented as a synthetic agent;
- a previously valid agent whose new candidate is invalid retains last-known-good runtime attribution/state;
- validation happens before activation;
- activation publishes one coherent runtime generation/snapshot rather than partially updating subsystems;
- execution surfaces resolve from the shared catalog/runtime snapshot rather than maintaining parallel registries.

Desired YAML/source state, active compiled runtime state, and historical evidence are different truths. Do not report a source-file edit as active until activation is proven.

Reload/recovery tests should cover invalid candidates, duplicate identities, concurrent readers, and last-known-good preservation.
