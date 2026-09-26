# Policy subsystem invariants

These rules apply when changing `internal/policy/**`.

- The stable policy subject is one AI use case (`agent` in configuration).
- Preserve the organization-baseline -> explicit use-case override -> effective-policy model unless an active issue explicitly changes it.
- Policy evaluation must use trusted/normalized inputs. Client metadata may provide attribution but must not silently become authority.
- Keep policy semantics centralized. Do not create a second evaluator or surface-specific interpretation of the same rule.
- Effective policy should be deterministic and expose source/provenance where the public contract requires it.
- Hard policy, budget, data, sovereignty, and action denials must not be bypassed by retry/fallback/reliability behavior.
- For action-authorization work under the current contract, preserve the ordering `DENY > REQUIRE_APPROVAL > ALLOW`.
- A proposal/discovery event is not authorization. Authorization must bind to the exact material subject defined by the active action-governance contract.
- Policy/config fields are compatibility surfaces. Add new public fields only when the active issue requires them and update validation, defaults, docs, and tests together.
- Do not infer risk tiers, approval roles, identities, destinations, schemas, or enforcement posture from caller-controlled values unless the active contract explicitly allows it.
- Parked capabilities must not leak into current policy semantics.

Tests should cover effective-rule resolution, provenance, conflicting inputs, and fail-closed boundaries rather than only happy-path parsing.
