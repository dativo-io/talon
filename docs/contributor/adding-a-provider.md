# Adding a new LLM provider

This guide walks you through adding a new LLM provider to Talon’s registry so it can be used by the router, the CLI, and the init wizard. You should be able to go from scaffold to PR in under two hours.

---

## Prerequisites

- Go 1.22+
- Familiarity with the [Provider interface](../../internal/llm/provider.go) (seven methods)
- Your provider’s API docs (auth, base URL, request/response shape)

---

## Step 1: Copy the scaffold

From the repo root:

```bash
cp -r internal/llm/providers/_scaffold internal/llm/providers/<name>
```

Use a lowercase name with no spaces (e.g. `groq`, `together`). Example:

```bash
cp -r internal/llm/providers/_scaffold internal/llm/providers/groq
```

---

## Step 2: Rename the package

In every file under `internal/llm/providers/<name>/`:

- Change the package declaration from `scaffold` to `<name>` (e.g. `package groq`).
- Rename `ScaffoldProvider` to `<Name>Provider` (e.g. `GroqProvider`).
- Replace the string `"scaffold"` with `"<name>"` in `Name()` and in the `llm.Register(...)` call (you will add this in the next step).

---

## Step 3: Register the provider

In `provider.go`, add an `init()` that registers your provider with the llm registry:

```go
func init() {
	llm.Register("groq", func(configYAML []byte) (llm.Provider, error) {
		apiKey := ""
		if len(configYAML) > 0 {
			var cfg groqConfig
			if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
				return nil, fmt.Errorf("groq config: %w", err)
			}
			apiKey = cfg.APIKey
		}
		return &GroqProvider{apiKey: apiKey, httpClient: &http.Client{}}, nil
	})
}
```

Use the same config struct and fields you need (e.g. `api_key`, `base_url`, `region`).

---

## Step 4: Implement the seven interface methods

In `provider.go`:

| Method | What to do |
|--------|------------|
| `Name()` | Return your provider ID (e.g. `"groq"`). |
| `Metadata()` | Return the value from your `metadata.go` (see Step 5). |
| `Generate()` | Build the HTTP request from `llm.Request`, call the API, map the response to `llm.Response`. Use `p.httpClient` so tests can inject httptest. |
| `Stream()` | If the API supports streaming, implement it; otherwise `return llm.ErrNotImplemented`. |
| `EstimateCost()` | Return cost in EUR for the given model and token counts (use provider pricing). |
| `ValidateConfig()` | Check required config (e.g. non-empty API key, valid region). Return a clear error if invalid. |
| `HealthCheck()` | Optional: lightweight liveness check (e.g. GET /health). Return `nil` to skip. |
| `WithHTTPClient()` | Return a copy of the provider with the given client (for tests and cassettes). |

Map known HTTP errors to typed errors: 401 → `llm.ErrAuthFailed`, 429 → `llm.ErrRateLimit`, and use `llm.ProviderError{Code: "..."}` where needed.

---

## Step 5: Fill in compliance metadata

Edit `metadata.go`. Every field is used by the router (EU routing), evidence, and the init wizard:

| Field | Purpose |
|-------|---------|
| `ID` | Canonical provider ID (same as `Name()`). |
| `DisplayName` | Human-readable name (e.g. "Groq"). |
| `Jurisdiction` | `"EU"`, `"US"`, `"CN"`, `"CA"`, or `"LOCAL"`. |
| `DPAAvailable` | Whether a Data Processing Agreement is available. |
| `EURegions` | EU region identifiers if the provider has EU endpoints (e.g. `[]string{"westeurope"}`). |
| `GDPRCompliant` | Set `true` only if verified. |
| `AIActScope` | `"in_scope"`, `"third_country"`, or `"exempt"`. |
| `DataRetention` | Short summary; avoid "Unknown"; cite a URL in a comment. |
| `Wizard.Suffix` | Short text for the init wizard (e.g. "EU regions available"). |
| `Wizard.Order` | Sort order in the wizard list (lower = earlier). |
| `Wizard.Hidden` | Set `true` to hide from the wizard. |
| `Wizard.RequiresRegion` | Set `true` if the user must pick a region. |
| `Wizard.AvailableRegions` | If `RequiresRegion`, list regions with `ID`, `DisplayName`, `IsEU`. |

---

## Step 6: Add the blank import

In `internal/llm/providers/providers.go`, add:

```go
_ "github.com/dativo-io/talon/internal/llm/providers/<name>"
```

so your provider’s `init()` runs when the binary starts.

---

## Step 7: Run unit tests

```bash
go test ./internal/llm/providers/<name>/... -v
```

Fix any failures. Your tests should cover at least: `Metadata()` fields, `Generate()` request shape and response parsing, and error mapping (401, 429).

---

## Step 8: Run compliance check

```bash
make test-provider-compliance
```

This runs `TestAllProviders_MetadataComplete` and fails if any registered provider has empty or placeholder metadata (e.g. "TODO" in `DataRetention`). Update your `metadata.go` until it passes.

---

## Step 9: Run the full test suite

```bash
go test ./internal/llm/... ./internal/agent/... ./internal/policy/... -count=1
```

Fix any breakages in router or policy tests.

---

## Step 10: Verify from the CLI

```bash
make build
./bin/talon provider list
./bin/talon provider info <name>
./bin/talon provider allowed
```

Your provider should appear in the list and in `allowed` when the sovereignty mode permits it.

---

## Step 11: Open a PR

- Add a short entry to the “Provider registry” section in [reference/provider-registry.md](../reference/provider-registry.md) (ID, jurisdiction, EU regions, notes).
- Ensure `talon provider list` shows the new provider with correct metadata.
- Ensure `WizardHint` is filled in (no scaffold placeholders).
- Run `make check` (lint, vet, test) and fix any issues.

---

## Checklist summary

- [ ] Scaffold copied and package/type names updated
- [ ] `init()` registers the provider with the registry
- [ ] All seven interface methods implemented (or `Stream` returns `ErrNotImplemented`)
- [ ] `metadata.go` filled with real compliance data
- [ ] Blank import added in `providers.go`
- [ ] Unit tests pass
- [ ] `make test-provider-compliance` passes
- [ ] `talon provider list` and `talon provider info <name>` show the new provider
- [ ] Reference doc updated; PR opened
