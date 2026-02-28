// Package doctor provides health checks for Talon configuration and runtime.
// Used by `talon doctor` and as a safety gate for `talon enforce enable`.
package doctor

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
)

// CheckResult is a single doctor check outcome.
type CheckResult struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Status   string `json:"status"` // pass, warn, fail
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
}

// Summary tallies pass/warn/fail counts.
type Summary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

// Report is the complete doctor output.
type Report struct {
	Status  string        `json:"status"` // worst of all checks
	Checks  []CheckResult `json:"checks"`
	Summary Summary       `json:"summary"`
}

// Options controls which check categories to run.
type Options struct {
	GatewayConfigPath string // Explicit gateway config path (empty = skip gateway checks)
	SkipUpstream      bool   // Skip upstream connectivity checks (for CI/offline)
}

// Run executes all doctor checks and returns a report.
func Run(ctx context.Context, opts Options) *Report {
	report := &Report{}

	report.Checks = append(report.Checks, checkConfig()...)
	if opts.GatewayConfigPath != "" {
		report.Checks = append(report.Checks, checkGateway(ctx, opts)...)
	}
	report.Checks = append(report.Checks, checkSystem()...)

	for _, c := range report.Checks {
		switch c.Status {
		case "pass":
			report.Summary.Pass++
		case "warn":
			report.Summary.Warn++
		case "fail":
			report.Summary.Fail++
		}
	}

	report.Status = "pass"
	if report.Summary.Warn > 0 {
		report.Status = "warn"
	}
	if report.Summary.Fail > 0 {
		report.Status = "fail"
	}
	return report
}

func checkConfig() []CheckResult {
	var results []CheckResult

	cfg, err := config.Load()
	if err != nil {
		return []CheckResult{{
			Name: "config_load", Category: "config", Status: "fail",
			Message: fmt.Sprintf("Cannot load config: %v", err),
			Fix:     "Check TALON_DATA_DIR and config file",
		}}
	}

	results = append(results, checkDataDir(cfg))
	results = append(results, checkPolicy(cfg))
	results = append(results, checkLLMKeys())
	results = append(results, checkCryptoKeys(cfg)...)
	results = append(results, checkEvidenceDB(cfg))
	return results
}

func checkDataDir(cfg *config.Config) CheckResult {
	if err := cfg.EnsureDataDir(); err != nil {
		return CheckResult{
			Name: "data_dir_writable", Category: "config", Status: "fail",
			Message: fmt.Sprintf("%s — %v", cfg.DataDir, err),
			Fix:     "Ensure directory exists and is writable",
		}
	}
	testFile := filepath.Join(cfg.DataDir, ".doctor-write-test")
	if err := os.WriteFile(testFile, []byte("ok"), 0o600); err != nil {
		return CheckResult{
			Name: "data_dir_writable", Category: "config", Status: "fail",
			Message: fmt.Sprintf("%s not writable — %v", cfg.DataDir, err),
		}
	}
	_ = os.Remove(testFile)
	return CheckResult{
		Name: "data_dir_writable", Category: "config", Status: "pass",
		Message: fmt.Sprintf("%s (writable)", cfg.DataDir),
	}
}

func checkPolicy(cfg *config.Config) CheckResult {
	policyPath := cfg.DefaultPolicy
	if _, err := os.Stat(policyPath); err != nil {
		return CheckResult{
			Name: "policy_valid", Category: "config", Status: "fail",
			Message: fmt.Sprintf("%s — file not found", policyPath),
			Fix:     "Run 'talon init' to create a policy file",
		}
	}
	pol, loadErr := policy.LoadPolicy(context.Background(), policyPath, false, ".")
	if loadErr != nil {
		return CheckResult{
			Name: "policy_valid", Category: "config", Status: "fail",
			Message: fmt.Sprintf("%s — %v", policyPath, loadErr),
		}
	}
	return CheckResult{
		Name: "policy_valid", Category: "config", Status: "pass",
		Message: fmt.Sprintf("%s (agent %s)", policyPath, pol.Agent.Name),
	}
}

func checkLLMKeys() CheckResult {
	hasOpenAI := os.Getenv("OPENAI_API_KEY") != ""
	hasAnthropic := os.Getenv("ANTHROPIC_API_KEY") != ""
	hasAWS := os.Getenv("AWS_ACCESS_KEY_ID") != "" || os.Getenv("AWS_PROFILE") != ""
	if !hasOpenAI && !hasAnthropic && !hasAWS {
		return CheckResult{
			Name: "llm_keys", Category: "config", Status: "fail",
			Message: "No OPENAI_API_KEY, ANTHROPIC_API_KEY, or AWS credentials found",
			Fix:     "Set at least one LLM provider key (env or vault)",
		}
	}
	var keys []string
	if hasOpenAI {
		keys = append(keys, "openai")
	}
	if hasAnthropic {
		keys = append(keys, "anthropic")
	}
	if hasAWS {
		keys = append(keys, "aws")
	}
	return CheckResult{
		Name: "llm_keys", Category: "config", Status: "pass",
		Message: fmt.Sprintf("%v (env)", keys),
	}
}

func checkCryptoKeys(cfg *config.Config) []CheckResult {
	var results []CheckResult
	if cfg.UsingDefaultSecretsKey() {
		results = append(results, CheckResult{
			Name: "secrets_key", Category: "config", Status: "warn",
			Message: "Using generated default", Fix: "Set TALON_SECRETS_KEY for production",
		})
	} else {
		results = append(results, CheckResult{
			Name: "secrets_key", Category: "config", Status: "pass", Message: "Configured",
		})
	}
	if cfg.UsingDefaultSigningKey() {
		results = append(results, CheckResult{
			Name: "signing_key", Category: "config", Status: "warn",
			Message: "Using generated default", Fix: "Set TALON_SIGNING_KEY for production",
		})
	} else {
		results = append(results, CheckResult{
			Name: "signing_key", Category: "config", Status: "pass", Message: "Configured",
		})
	}
	return results
}

func checkEvidenceDB(cfg *config.Config) CheckResult {
	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return CheckResult{
			Name: "evidence_db", Category: "config", Status: "fail",
			Message: fmt.Sprintf("%v", err),
		}
	}
	_ = store.Close()
	return CheckResult{
		Name: "evidence_db", Category: "config", Status: "pass",
		Message: cfg.EvidenceDBPath(),
	}
}

func checkGateway(ctx context.Context, opts Options) []CheckResult {
	var results []CheckResult

	gwCfg, err := gateway.LoadGatewayConfig(opts.GatewayConfigPath)
	if err != nil {
		return []CheckResult{{
			Name: "gateway_config_valid", Category: "gateway", Status: "fail",
			Message: fmt.Sprintf("Invalid config: %v", err),
			Fix:     "Check YAML syntax in " + opts.GatewayConfigPath,
		}}
	}
	results = append(results, CheckResult{
		Name: "gateway_config_valid", Category: "gateway", Status: "pass",
		Message: opts.GatewayConfigPath,
	})
	results = append(results, checkGatewayMode(gwCfg))
	results = append(results, checkGatewayCallers(gwCfg))
	results = append(results, checkGatewayToolPolicy(gwCfg))

	if !opts.SkipUpstream {
		results = append(results, checkGatewayUpstreams(ctx, gwCfg)...)
	}
	results = append(results, checkGatewaySecrets(ctx, gwCfg)...)
	return results
}

func checkGatewayMode(cfg *gateway.GatewayConfig) CheckResult {
	var msg string
	switch cfg.Mode {
	case gateway.ModeShadow:
		msg = "shadow (safe default — run 'talon enforce report' to review)"
	case gateway.ModeEnforce:
		msg = "enforce (active — violations are blocked)"
	case gateway.ModeLogOnly:
		msg = "log_only (evidence only)"
	default:
		msg = string(cfg.Mode) + " (unknown)"
	}
	return CheckResult{Name: "gateway_mode", Category: "gateway", Status: "pass", Message: msg}
}

func checkGatewayCallers(cfg *gateway.GatewayConfig) CheckResult {
	if len(cfg.Callers) == 0 {
		return CheckResult{
			Name: "gateway_callers_defined", Category: "gateway", Status: "warn",
			Message: "No callers configured",
			Fix:     "Add callers to gateway config for per-caller governance",
		}
	}
	return CheckResult{
		Name: "gateway_callers_defined", Category: "gateway", Status: "pass",
		Message: fmt.Sprintf("%d caller(s)", len(cfg.Callers)),
	}
}

func checkGatewayToolPolicy(cfg *gateway.GatewayConfig) CheckResult {
	if len(cfg.ServerDefaults.ForbiddenTools) == 0 {
		return CheckResult{
			Name: "gateway_forbidden_tools", Category: "gateway", Status: "warn",
			Message: "No forbidden tools configured",
			Fix:     "Add forbidden_tools to default_policy for tool governance",
		}
	}
	return CheckResult{
		Name: "gateway_forbidden_tools", Category: "gateway", Status: "pass",
		Message: fmt.Sprintf("%d pattern(s)", len(cfg.ServerDefaults.ForbiddenTools)),
	}
}

func checkGatewayUpstreams(ctx context.Context, cfg *gateway.GatewayConfig) []CheckResult {
	var results []CheckResult
	for name := range cfg.Providers {
		prov := cfg.Providers[name]
		if !prov.Enabled || prov.BaseURL == "" {
			continue
		}
		results = append(results, checkUpstream(ctx, name, prov.BaseURL)...)
	}
	return results
}

func checkGatewaySecrets(ctx context.Context, gwCfg *gateway.GatewayConfig) []CheckResult {
	var results []CheckResult
	cfg, err := config.Load()
	if err != nil {
		return results
	}
	secStore, secErr := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	if secErr != nil {
		return results
	}
	defer secStore.Close()

	for name := range gwCfg.Providers {
		prov := gwCfg.Providers[name]
		if !prov.Enabled || prov.SecretName == "" {
			continue
		}
		_, getErr := secStore.Get(ctx, prov.SecretName, "default", "*")
		if getErr != nil {
			results = append(results, CheckResult{
				Name: "gateway_secrets_" + name, Category: "gateway", Status: "fail",
				Message: fmt.Sprintf("Secret %q not found for provider %s", prov.SecretName, name),
				Fix:     fmt.Sprintf("Run: talon secrets set %s <your-api-key>", prov.SecretName),
			})
		} else {
			results = append(results, CheckResult{
				Name: "gateway_secrets_" + name, Category: "gateway", Status: "pass",
				Message: fmt.Sprintf("Secret %q present for %s", prov.SecretName, name),
			})
		}
	}
	return results
}

func checkUpstream(ctx context.Context, name, baseURL string) []CheckResult {
	var results []CheckResult

	client := &http.Client{Timeout: 5 * time.Second}
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodHead, baseURL, nil)
	if reqErr != nil {
		return []CheckResult{{
			Name: "gateway_upstream_" + name, Category: "gateway", Status: "fail",
			Message: fmt.Sprintf("Invalid URL: %v", reqErr),
		}}
	}
	start := time.Now()
	resp, err := client.Do(req) //nolint:gosec // G704: URL from operator-controlled gateway config, not user input
	latency := time.Since(start)

	if err != nil {
		return []CheckResult{{
			Name: "gateway_upstream_" + name, Category: "gateway", Status: "fail",
			Message: fmt.Sprintf("Connection failed: %v", err),
			Fix:     "Check network connectivity and provider base_url",
		}}
	}
	resp.Body.Close()

	results = append(results, CheckResult{
		Name: "gateway_upstream_" + name, Category: "gateway", Status: "pass",
		Message: fmt.Sprintf("%s — %dms", baseURL, latency.Milliseconds()),
	})

	if latency > 2*time.Second {
		results = append(results, CheckResult{
			Name: "gateway_upstream_latency_" + name, Category: "gateway", Status: "fail",
			Message: fmt.Sprintf("%.1fs (> 2s threshold)", latency.Seconds()),
			Fix:     "Consider a closer region or Azure OpenAI endpoint",
		})
	} else if latency > time.Second {
		results = append(results, CheckResult{
			Name: "gateway_upstream_latency_" + name, Category: "gateway", Status: "warn",
			Message: fmt.Sprintf("%.1fs (> 1s threshold)", latency.Seconds()),
			Fix:     "Consider a closer region or Azure OpenAI endpoint",
		})
	}

	if name == "openai" || name == "azure" {
		results = append(results, checkModelsEndpoint(ctx, client, name, baseURL)...)
	}

	return results
}

func checkModelsEndpoint(ctx context.Context, client *http.Client, name, baseURL string) []CheckResult {
	modelsURL := baseURL + "/v1/models"
	modelsReq, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
	if reqErr != nil {
		return []CheckResult{{
			Name: "gateway_upstream_models_" + name, Category: "gateway", Status: "fail",
			Message: fmt.Sprintf("invalid models URL %s: %v", modelsURL, reqErr),
			Fix:     "Check base_url in gateway provider config",
		}}
	}
	modelsResp, modelsErr := client.Do(modelsReq)
	if modelsErr != nil {
		return []CheckResult{{
			Name: "gateway_upstream_models_" + name, Category: "gateway", Status: "warn",
			Message: fmt.Sprintf("GET %s failed: %v", modelsURL, modelsErr),
			Fix:     "Verify base_url points to an OpenAI-compatible API",
		}}
	}
	modelsResp.Body.Close()
	if modelsResp.StatusCode < 500 {
		return []CheckResult{{
			Name: "gateway_upstream_models_" + name, Category: "gateway", Status: "pass",
			Message: fmt.Sprintf("GET /v1/models — %d", modelsResp.StatusCode),
		}}
	}
	return nil
}

func checkSystem() []CheckResult {
	var results []CheckResult

	cfg, err := config.Load()
	if err != nil {
		return results
	}

	evDir := filepath.Dir(cfg.EvidenceDBPath())
	if info, statErr := os.Stat(evDir); statErr == nil && info.IsDir() {
		testPath := filepath.Join(evDir, ".doctor-space-test")
		data := make([]byte, 1024)
		if writeErr := os.WriteFile(testPath, data, 0o600); writeErr != nil {
			results = append(results, CheckResult{
				Name: "disk_space", Category: "system", Status: "warn",
				Message: "Cannot write test file to evidence directory",
			})
		} else {
			_ = os.Remove(testPath)
			results = append(results, CheckResult{
				Name: "disk_space", Category: "system", Status: "pass",
				Message: evDir,
			})
		}
	}

	store, storeErr := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if storeErr == nil {
		defer store.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		count, countErr := store.CountInRange(ctx, "", "", time.Time{}, time.Time{})
		if countErr == nil {
			fi, _ := os.Stat(cfg.EvidenceDBPath())
			sizeStr := "unknown"
			if fi != nil {
				sizeMB := float64(fi.Size()) / (1024 * 1024)
				sizeStr = fmt.Sprintf("%.1f MB", sizeMB)
			}
			results = append(results, CheckResult{
				Name: "evidence_stats", Category: "system", Status: "pass",
				Message: fmt.Sprintf("%d records, %s", count, sizeStr),
			})
		}
	}

	return results
}
