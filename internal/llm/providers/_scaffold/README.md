# Provider scaffold

This directory is a **template** for adding a new LLM provider to Talon. Do not register it in `providers.go` — it is for copying only.

## Quick start

1. Copy the scaffold:
   ```bash
   cp -r internal/llm/providers/_scaffold internal/llm/providers/myprovider
   ```

2. Rename the package in every file from `scaffold` to `myprovider`.

3. In `provider.go`:
   - Replace `ScaffoldProvider` with `MyProvider`.
   - Replace `"scaffold"` in `Name()` and `llm.Register("scaffold", ...)` with `"myprovider"`.
   - Implement `Generate()` (and optionally `Stream()`).
   - Implement `EstimateCost()` and `ValidateConfig()`.

4. In `metadata.go`:
   - Set `ID`, `DisplayName`, `Jurisdiction`, `EURegions`, `GDPRCompliant`, `DataRetention`, and `Wizard` to real values.

5. Add a blank import in `internal/llm/providers/providers.go`:
   ```go
   _ "github.com/dativo-io/talon/internal/llm/providers/myprovider"
   ```

6. Run tests: `go test ./internal/llm/providers/myprovider/...`

7. Verify: `talon provider list` shows your provider.

See **docs/contributor/adding-a-provider.md** for the full 11-step guide.
