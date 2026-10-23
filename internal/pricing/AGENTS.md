# Pricing table invariants

These rules apply when changing `internal/pricing/**`, `pricing/models.yaml` or any code that reads cost from the table.

- Two hand-maintained mirrors carry the catalog: `pricing/models.yaml` (the repository file; demos copy it verbatim and `talon serve` resolves it relative to the config directory) and `internal/pricing/default_models.yaml` (embedded; `talon init` and `talon openshell prepare` write it when no table exists). Edit both identically in the same commit.
- Three shapes, three meanings: `models: {…}` priced; `models: {}` an explicit zero-cost provider (self-hosted); `inherit: <catalog provider>` an aliased endpoint priced as the catalog entry (single depth, no chains). A provider or model that is absent is **unknown**, and the gateway denies it `pricing_unavailable` under a binding cap. Do not add a free placeholder for a commercial endpoint.
- `Estimate` returns `(cost, known)`; callers must never read `cost` without `known`. Unknown is not zero.
- Prices are per 1M tokens in the table's declared currency (default USD); every cost Talon records and every cap it compares against is in that currency. Negative prices and invalid currency codes fail `Load`.
- Model lookup tolerates dated or versioned API suffixes (`gpt-4o-2024-08-06` → `gpt-4o`); do not add provider-specific normalizers elsewhere.
- Changing semantics touches `docs/reference/provider-registry.md` (cost estimation), `LIMITATIONS.md` §7, `TestResolve_ZeroCostVersusUnknown` and the gateway's pricing gate tests.
