// Package doctor provides health checks for Talon configuration and runtime.
// Used by `talon doctor` and as a safety gate for `talon enforce enable`.
package doctor

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/sovereignty"
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
	results = append(results, checkLLMKeys(cfg))
	results = append(results, checkCryptoKeys(cfg)...)
	results = append(results, checkEvidenceDB(cfg))
	results = append(results, checkCache(cfg))
	results = append(results, checkSovereignty(cfg, nil))
	results = append(results, checkAirGap(cfg, nil))
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
		// A missing agent policy is advisory, not fatal: gateway-only deployments
		// (e.g. air-gap proxy) govern requests via the gateway default_policy and
		// need no agent.talon.yaml. It is only required for the `talon run` path.
		return CheckResult{
			Name: "policy_valid", Category: "config", Status: "warn",
			Message: fmt.Sprintf("%s — file not found (not required for gateway-only deployments)", policyPath),
			Fix:     "Run 'talon init' to create an agent policy file (needed for 'talon run')",
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

func checkLLMKeys(cfg *config.Config) CheckResult {
	var sources []string
	if os.Getenv("OPENAI_API_KEY") != "" {
		sources = append(sources, "openai (env)")
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		sources = append(sources, "anthropic (env)")
	}
	if os.Getenv("AWS_ACCESS_KEY_ID") != "" || os.Getenv("AWS_PROFILE") != "" {
		sources = append(sources, "aws (env)")
	}
	// Local-first / air-gap deployments declare providers in llm.providers with
	// vault-backed (or, for Ollama, no) credentials. These are valid provider
	// paths and must not be reported as "no LLM keys" just because no cloud env
	// key is set.
	if cfg.LLM != nil {
		for id := range cfg.LLM.Providers {
			p := cfg.LLM.Providers[id]
			providerType := p.Type
			if providerType == "" {
				providerType = id
			}
			sources = append(sources, providerType+" (llm.providers)")
		}
	}
	if len(sources) == 0 {
		return CheckResult{
			Name: "llm_keys", Category: "config", Status: "fail",
			Message: "No LLM provider configured (no OPENAI_API_KEY/ANTHROPIC_API_KEY/AWS credentials and no llm.providers)",
			Fix:     "Set a provider key (env or vault) or declare a local provider (e.g. Ollama) in llm.providers",
		}
	}
	return CheckResult{
		Name: "llm_keys", Category: "config", Status: "pass",
		Message: "LLM providers available: " + strings.Join(sources, ", "),
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

// checkCache validates cache config when present. Pass when disabled; when enabled, validate config and writable path.
func checkCache(cfg *config.Config) CheckResult {
	if cfg.Cache == nil || !cfg.Cache.Enabled {
		return CheckResult{
			Name: "cache", Category: "config", Status: "pass",
			Message: "Cache disabled (optional)",
		}
	}
	if cfg.Cache.DefaultTTL <= 0 {
		return CheckResult{
			Name: "cache", Category: "config", Status: "fail",
			Message: "cache.default_ttl must be positive when cache is enabled",
			Fix:     "Set cache.default_ttl to a positive value (e.g. 3600) in talon.config.yaml",
		}
	}
	if cfg.Cache.SimilarityThreshold <= 0 || cfg.Cache.SimilarityThreshold > 1 {
		return CheckResult{
			Name: "cache", Category: "config", Status: "fail",
			Message: "cache.similarity_threshold must be in (0, 1] when cache is enabled",
			Fix:     "Set cache.similarity_threshold (e.g. 0.92) in talon.config.yaml",
		}
	}
	if cfg.Cache.MaxEntriesPerTenant <= 0 {
		return CheckResult{
			Name: "cache", Category: "config", Status: "fail",
			Message: "cache.max_entries_per_tenant must be positive when cache is enabled",
			Fix:     "Set cache.max_entries_per_tenant (e.g. 10000) in talon.config.yaml",
		}
	}
	for tier, ttl := range cfg.Cache.TTLByTier {
		switch tier {
		case "public", "internal", "confidential":
		default:
			return CheckResult{
				Name: "cache", Category: "config", Status: "fail",
				Message: fmt.Sprintf("cache.ttl_by_tier key %q is not a known tier", tier),
				Fix:     "Use public, internal, or confidential as ttl_by_tier keys in talon.config.yaml",
			}
		}
		if ttl <= 0 {
			return CheckResult{
				Name: "cache", Category: "config", Status: "fail",
				Message: fmt.Sprintf("cache.ttl_by_tier.%s must be positive (seconds)", tier),
				Fix:     "Set a positive TTL in seconds (e.g. 900) in talon.config.yaml",
			}
		}
	}
	cacheDir := filepath.Dir(cfg.CacheDBPath())
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return CheckResult{
			Name: "cache", Category: "config", Status: "fail",
			Message: fmt.Sprintf("Cache path directory %s: %v", cacheDir, err),
			Fix:     "Ensure data_dir is writable or create the cache directory",
		}
	}
	testPath := filepath.Join(cacheDir, ".doctor-cache-write-test")
	if err := os.WriteFile(testPath, []byte("ok"), 0o600); err != nil {
		return CheckResult{
			Name: "cache", Category: "config", Status: "fail",
			Message: fmt.Sprintf("Cache path not writable: %s — %v", cfg.CacheDBPath(), err),
			Fix:     "Ensure data_dir is writable",
		}
	}
	_ = os.Remove(testPath)
	return CheckResult{
		Name: "cache", Category: "config", Status: "pass",
		Message: fmt.Sprintf("%s (enabled, writable)", cfg.CacheDBPath()),
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
	results = append(results, checkGatewayAgentIdentity(ctx))
	results = append(results, checkGatewayToolPolicy(gwCfg))
	results = append(results, checkSovereigntyFromGateway(gwCfg, opts.GatewayConfigPath))
	results = append(results, checkAirGapFromGateway(gwCfg, opts.GatewayConfigPath))
	results = append(results, checkAirGapEgressGuardFromGateway(gwCfg, opts.GatewayConfigPath))

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

// checkGatewayAgentIdentity preflights the agent identity model (#266): the
// agent policy carries a key binding, the referenced vault secret exists, and
// a dry-run registry build passes the same fail-closed validation `talon
// serve --gateway` will run.
func checkGatewayAgentIdentity(ctx context.Context) CheckResult {
	cfg, err := config.Load()
	if err != nil {
		return CheckResult{
			Name: "gateway_agent_identity", Category: "gateway", Status: "warn",
			Message: fmt.Sprintf("Cannot load operator config: %v", err),
		}
	}
	pol, err := policy.LoadPolicy(ctx, cfg.DefaultPolicy, false, ".")
	if err != nil {
		return CheckResult{
			Name: "gateway_agent_identity", Category: "gateway", Status: "warn",
			Message: fmt.Sprintf("No agent policy loaded (%v)", err),
			Fix:     "Create agent.talon.yaml with agent.key.secret_name — gateway mode requires at least one keyed agent",
		}
	}
	if pol.Agent.Key == nil || pol.Agent.Key.SecretName == "" {
		return CheckResult{
			Name: "gateway_agent_identity", Category: "gateway", Status: "warn",
			Message: fmt.Sprintf("Agent %q has no key binding — it cannot authenticate to the gateway", pol.Agent.Name),
			Fix:     "Add agent.key.secret_name to agent.talon.yaml and run: talon secrets set <name> <key>",
		}
	}
	secStore, secErr := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	if secErr != nil {
		return CheckResult{
			Name: "gateway_agent_identity", Category: "gateway", Status: "warn",
			Message: fmt.Sprintf("Cannot open secrets vault: %v", secErr),
		}
	}
	defer secStore.Close()
	// Same collision rule as serve startup: an agent key equal to
	// TALON_ADMIN_KEY fails the dry-run (silent operator-authority elevation).
	if _, err := gateway.BuildIdentityRegistry(ctx, []gateway.LoadedAgent{{
		Path:          cfg.DefaultPolicy,
		Name:          pol.Agent.Name,
		TenantID:      pol.Agent.TenantID,
		KeySecretName: pol.Agent.Key.SecretName,
	}}, secStore, os.Getenv("TALON_ADMIN_KEY")); err != nil {
		return CheckResult{
			Name: "gateway_agent_identity", Category: "gateway", Status: "fail",
			Message: fmt.Sprintf("Identity registry dry-run failed: %v", err),
			Fix:     fmt.Sprintf("Run: talon secrets set %s <agent-key>", pol.Agent.Key.SecretName),
		}
	}
	return CheckResult{
		Name: "gateway_agent_identity", Category: "gateway", Status: "pass",
		Message: fmt.Sprintf("Agent %q key binding resolves (%s)", pol.Agent.Name, pol.Agent.Key.SecretName),
	}
}

func checkGatewayToolPolicy(cfg *gateway.GatewayConfig) CheckResult {
	if len(cfg.OrganizationPolicy.ForbiddenTools) == 0 {
		return CheckResult{
			Name: "gateway_forbidden_tools", Category: "gateway", Status: "warn",
			Message: "No forbidden tools configured",
			Fix:     "Add forbidden_tools to organization_policy for tool governance",
		}
	}
	return CheckResult{
		Name: "gateway_forbidden_tools", Category: "gateway", Status: "pass",
		Message: fmt.Sprintf("%d pattern(s)", len(cfg.OrganizationPolicy.ForbiddenTools)),
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
	modelsResp, modelsErr := client.Do(modelsReq) //nolint:gosec // G704: URL from operator-controlled gateway config, not user input
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

func checkSovereignty(cfg *config.Config, gwCfg *gateway.GatewayConfig) CheckResult {
	mode := cfg.EffectiveSovereigntyMode()
	if mode == "" || mode == config.DataSovereigntyGlobal {
		return CheckResult{
			Name: "sovereignty_mode", Category: "sovereignty", Status: "pass",
			Message: "no sovereignty restriction (mode unset or global)",
		}
	}
	eval := sovereignty.EvaluateSovereignty(cfg, gwCfg)
	if mode == config.DataSovereigntyEUStrict {
		// Gateway and native routability are evaluated separately: a compliant
		// native/LLM provider must not mask a gateway whose providers are all
		// excluded, and vice versa.
		if eval.GatewayEvaluated && !eval.HasCompliantGatewayProvider {
			return CheckResult{
				Name: "sovereignty_providers", Category: "sovereignty", Status: "fail",
				Message: fmt.Sprintf("sovereignty mode %q but the gateway has no EU/LOCAL provider routable", mode),
				Fix:     "Configure at least one enabled EU or LOCAL gateway provider, or relax sovereignty.mode",
			}
		}
		if !eval.GatewayEvaluated && !eval.HasCompliantOperatorProvider {
			return CheckResult{
				Name: "sovereignty_providers", Category: "sovereignty", Status: "fail",
				Message: fmt.Sprintf("sovereignty mode %q but no EU/LOCAL provider is routable", mode),
				Fix:     "Configure at least one EU or LOCAL LLM provider, or relax sovereignty.mode",
			}
		}
	}
	if len(eval.Excluded) > 0 {
		names := make([]string, 0, len(eval.Excluded))
		for _, ex := range eval.Excluded {
			names = append(names, ex.Provider)
		}
		sort.Strings(names)
		return CheckResult{
			Name: "sovereignty_providers", Category: "sovereignty", Status: "warn",
			Message: fmt.Sprintf("sovereignty mode %q: excluded declared provider(s): %s", mode, strings.Join(names, ", ")),
			Fix:     "Remove non-EU providers or relax sovereignty.mode; compliant providers remain available",
		}
	}
	return CheckResult{
		Name: "sovereignty_providers", Category: "sovereignty", Status: "pass",
		Message: fmt.Sprintf("all declared providers satisfy sovereignty mode %q", mode),
	}
}

func checkSovereigntyFromGateway(gwCfg *gateway.GatewayConfig, gatewayConfigPath string) CheckResult {
	cfg, err := config.Load()
	if err != nil {
		return CheckResult{
			Name: "sovereignty_gateway", Category: "sovereignty", Status: "warn",
			Message: "cannot load operator config for sovereignty gateway check",
		}
	}
	if err := config.ResolveSovereigntyForGateway(cfg, gatewayConfigPath); err != nil {
		return CheckResult{
			Name: "sovereignty_gateway", Category: "sovereignty", Status: "fail",
			Message: err.Error(),
			Fix:     "Reconcile sovereignty blocks in operator and gateway config (e.g. air_gap requires eu_strict)",
		}
	}
	return checkSovereignty(cfg, gwCfg)
}

func checkAirGap(cfg *config.Config, gwCfg *gateway.GatewayConfig) CheckResult {
	if cfg.Sovereignty == nil || !cfg.Sovereignty.AirGapEnabled() {
		return CheckResult{
			Name: "air_gap_mode", Category: "sovereignty", Status: "pass",
			Message: "standard deployment (sovereignty.deployment_mode not air_gap)",
		}
	}
	if cfg.UsingDefaultKeys() {
		return CheckResult{
			Name: "air_gap_crypto_keys", Category: "sovereignty", Status: "fail",
			Message: "air_gap requires explicit TALON_SECRETS_KEY and TALON_SIGNING_KEY",
			Fix:     "Set both keys via env vars before enabling air_gap mode",
		}
	}
	if gwCfg == nil {
		return CheckResult{
			Name: "air_gap_config", Category: "sovereignty", Status: "warn",
			Message: "air_gap enabled but no gateway config provided; provider region checks skipped",
			Fix:     "Run with --gateway-config to validate full air-gap deployment",
		}
	}
	if err := sovereignty.ValidateAirGap(cfg, gwCfg); err != nil {
		return CheckResult{
			Name: "air_gap_config", Category: "sovereignty", Status: "fail",
			Message: err.Error(),
			Fix:     "Set explicit TALON_SECRETS_KEY and TALON_SIGNING_KEY before enabling air_gap mode",
		}
	}
	return CheckResult{
		Name: "air_gap_config", Category: "sovereignty", Status: "pass",
		Message: "air_gap deployment configuration validated",
	}
}

func checkAirGapFromGateway(gwCfg *gateway.GatewayConfig, gatewayConfigPath string) CheckResult {
	cfg, err := config.Load()
	if err != nil {
		return CheckResult{
			Name: "air_gap_gateway", Category: "sovereignty", Status: "warn",
			Message: "cannot load operator config for air-gap gateway check",
		}
	}
	if err := config.ResolveSovereigntyForGateway(cfg, gatewayConfigPath); err != nil {
		return CheckResult{
			Name: "air_gap_gateway", Category: "sovereignty", Status: "fail",
			Message: err.Error(),
			Fix:     "Reconcile sovereignty blocks in operator and gateway config (e.g. air_gap requires eu_strict)",
		}
	}
	return checkAirGap(cfg, gwCfg)
}

// checkAirGapEgressGuard confirms a transport-level egress guard exists and
// actively blocks non-allowlisted hosts (not merely that config parsed). This
// is the buyer-facing promise of air_gap: "no surprise egress path exists."
func checkAirGapEgressGuard(cfg *config.Config, gwCfg *gateway.GatewayConfig) CheckResult {
	if cfg.Sovereignty == nil || !cfg.Sovereignty.AirGapEnabled() {
		return CheckResult{
			Name: "air_gap_egress_guard", Category: "sovereignty", Status: "pass",
			Message: "not applicable (sovereignty.deployment_mode not air_gap)",
		}
	}
	n, err := sovereignty.VerifyEgressGuard(cfg, gwCfg)
	if err != nil {
		return CheckResult{
			Name: "air_gap_egress_guard", Category: "sovereignty", Status: "fail",
			Message: fmt.Sprintf("transport egress guard not enforcing: %v", err),
			Fix:     "Ensure allowed_egress_hosts and gateway upstreams are valid URLs/hosts",
		}
	}
	return CheckResult{
		Name: "air_gap_egress_guard", Category: "sovereignty", Status: "pass",
		Message: fmt.Sprintf("transport egress guard blocks non-allowlisted hosts (%d hosts allowlisted)", n),
	}
}

func checkAirGapEgressGuardFromGateway(gwCfg *gateway.GatewayConfig, gatewayConfigPath string) CheckResult {
	cfg, err := config.Load()
	if err != nil {
		return CheckResult{
			Name: "air_gap_egress_guard", Category: "sovereignty", Status: "warn",
			Message: "cannot load operator config for egress guard check",
		}
	}
	if err := config.ResolveSovereigntyForGateway(cfg, gatewayConfigPath); err != nil {
		return CheckResult{
			Name: "air_gap_egress_guard", Category: "sovereignty", Status: "fail",
			Message: err.Error(),
			Fix:     "Reconcile sovereignty blocks in operator and gateway config (e.g. air_gap requires eu_strict)",
		}
	}
	return checkAirGapEgressGuard(cfg, gwCfg)
}
