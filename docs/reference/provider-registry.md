# Provider registry reference

Talon’s LLM router uses a **provider registry**: each provider implements the same interface, registers itself at startup, and is selected by the router using policy (tier, cost, and EU data sovereignty). This page describes the registry, the Provider interface, compliance metadata, and the `talon provider` CLI.

---

## Provider interface

All providers implement [internal/llm/provider.go](https://github.com/dativo-io/talon/blob/main/internal/llm/provider.go):

| Method | Purpose |
|--------|---------|
| `Name() string` | Canonical provider ID (e.g. `openai`, `anthropic`). |
| `Metadata() ProviderMetadata` | Static compliance and identity (jurisdiction, EU regions, wizard hint). |
| `Generate(ctx, req) (*Response, error)` | Send a completion request; return content and token counts. |
| `Stream(ctx, req, ch) error` | Stream completion; return `ErrNotImplemented` if not supported. |
| `EstimateCost(model, in, out) float64` | Cost in EUR for the given model and token counts. |
| `ValidateConfig() error` | Validate config at startup (no network). |
| `HealthCheck(ctx) error` | Optional liveness check. |
| `WithHTTPClient(*http.Client) Provider` | Return a copy with the given client (for tests). |

The router and CLI never depend on concrete provider types; they use this interface only.

---

## Compliance metadata

`ProviderMetadata` is used for:

- **EU routing** — OPA `routing.rego` allows or denies a provider by jurisdiction and region (see [EU data sovereignty](#eu-data-sovereignty)).
- **Evidence** — Traces and evidence can record provider jurisdiction and region.
- **Init wizard** — In a terminal, `talon init` runs an interactive wizard that uses `ListForWizard()` to show providers with `WizardHint` (display name, suffix, order, region options). Use `talon init --list-providers` to print the same list and exit.

| Field | Type | Meaning |
|-------|------|---------|
| `ID` | string | Same as `Name()`. |
| `DisplayName` | string | Human-readable name. |
| `Jurisdiction` | string | `EU`, `US`, `CN`, `CA`, or `LOCAL`. |
| `DPAAvailable` | bool | Data Processing Agreement available. |
| `EURegions` | []string | EU region IDs (e.g. `westeurope`). |
| `GDPRCompliant` | bool | Self-declared / verified. |
| `AIActScope` | string | `in_scope`, `third_country`, or `exempt`. |
| `DataRetention` | string | Short summary. |
| `PricingAvailable` | bool | True when the pricing table has at least one model for this provider (set dynamically in `Metadata()`). |
| `Wizard` | WizardHint | Suffix, order, hidden, region list. |

---

## EU data sovereignty

When `talon.config.yaml` has an `llm.routing.data_sovereignty_mode` set to `eu_strict`, `eu_preferred`, or `global`, the router evaluates each candidate provider with the OPA policy in `internal/policy/rego/routing.rego`. Evidence records the selected provider and rejected candidates with reasons. See [Configuration reference](configuration.md#llm-block) for the `llm` block.

---

## Registered providers (built-in)

| ID | Jurisdiction | EU regions | Notes |
|----|--------------|------------|--------|
| openai | US | — | OpenAI API; custom base URL supported. |
| anthropic | US | — | Anthropic Messages API. |
| azure-openai | EU | westeurope, swedencentral, francecentral, uksouth | Azure OpenAI. |
| bedrock | US | eu-central-1, eu-west-1, eu-west-3 | AWS Bedrock. |
| mistral | EU | — | Mistral AI. |
| ollama | LOCAL | — | Local models. |
| vertex | US | europe-west1, europe-west4, europe-west9 | Google Vertex AI. |
| qwen | CN | — | Alibaba Cloud Qwen. |
| cohere | CA | — | Cohere. |
| generic-openai | US | — | User-declared jurisdiction; any OpenAI-compatible API. |

To add a provider, use the [contributor guide](../contributor/adding-a-provider.md).

---

## Cost estimation

Talon estimates per-request LLM costs using a static pricing table at `pricing/models.yaml`. This file ships with current prices for all bundled providers and is operator-editable without recompilation. The path is configurable via `llm.pricing_file` in `talon.config.yaml` (default: `pricing/models.yaml`).

Cost estimates appear in the evidence trail (`pre_request_estimate` and `post_request_cost` on the routing decision) and as OTel span attributes (`talon.cost.estimated_usd`, `talon.cost.pricing_known`, etc.). They are **not** used for routing decisions in this version.

To update pricing, edit `pricing/models.yaml` and restart Talon. Hot-reload is not currently supported.

The table keys on the **gateway provider name**, and it distinguishes two explicit shapes from "unknown":

| Shape | Meaning | Example |
|---|---|---|
| `models: {}` | every model on this provider is **explicitly zero-cost** (self-hosted) | `ollama`, the product demo's `local-llama` (`inherit: ollama`) |
| `inherit: <catalog provider>` | an **aliased endpoint** priced as the catalog entry (an `openai-eu`, the OpenShell showcase's `openshell-mock`) | `my-endpoint: { inherit: openai }` |
| a model priced at `0` | that model is explicitly free | — |
| provider or model **absent** | **unknown**: the request cannot be priced | — |

A gateway agent always has a daily/monthly cap (the organization baseline), so an unknown provider or model is denied `pricing_unavailable` before dispatch ([error contract](error-contract.md)) — never estimated at a flat guess. `models: {}` is a declaration, not a placeholder: a commercial OpenAI-compatible endpoint (a `generic-openai` provider) must be populated with its real rates or inherit a catalog entry; the shipped table does not list it as free. `talon openshell prepare --provider-pricing <catalog provider>` writes the alias for the provider a sandbox dials. Run `talon init` (wizard or `talon init --scaffold`) to generate a project that includes `pricing/models.yaml` and `llm.pricing_file` in the config.

---

## talon provider CLI

| Command | Purpose |
|---------|---------|
| `talon provider list` | Table of all registered providers with ID, jurisdiction, GDPR, EU regions, DPA. |
| `talon provider info <type>` | Detailed compliance info for one provider (includes pricing status: available models or not configured). |
| `talon provider allowed` | List providers and whether they are allowed under the current `data_sovereignty_mode` (from config). |

Example:

```bash
talon provider list
talon provider info openai
talon provider allowed
```

---

## Makefile targets

| Target | Usage | Purpose |
|--------|--------|---------|
| `make provider-list` | — | Build and run `talon provider list`. |
| `make provider-new NAME=<name>` | e.g. `NAME=groq` | Copy `_scaffold` to `internal/llm/providers/<name>`. |
| `make test-provider PROVIDER=<name>` | e.g. `PROVIDER=openai` | Run tests for one provider. |
| `make test-provider-compliance` | — | Run metadata completeness checks for all providers. |
| `make opa-test` | — | Run OPA policy tests (e.g. routing.rego). |
