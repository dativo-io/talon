package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/cache"
	"github.com/dativo-io/talon/internal/compliance"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/mcp"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/metrics"
	"github.com/dativo-io/talon/internal/policy"
	talonprompt "github.com/dativo-io/talon/internal/prompt"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/server"
	talonsession "github.com/dativo-io/talon/internal/session"
	"github.com/dativo-io/talon/internal/sovereignty"
	"github.com/dativo-io/talon/internal/trigger"
	"github.com/dativo-io/talon/web"
)

var (
	servePort            int
	serveHost            string
	serveProxyConfig     string
	serveDashboard       bool
	serveGateway         bool
	serveGatewayConfig   string
	serveProxyQuickstart bool
	serveUnsafeListen    bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Talon server with cron triggers and webhook endpoints",
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", 8080, "HTTP server port")
	serveCmd.Flags().StringVar(&serveHost, "host", "", "HTTP server host (empty means default bind behavior)")
	serveCmd.Flags().StringVar(&serveProxyConfig, "proxy-config", "", "Path to MCP proxy config YAML (optional)")
	serveCmd.Flags().BoolVar(&serveDashboard, "dashboard", true, "Serve embedded dashboard at / and /dashboard")
	serveCmd.Flags().BoolVar(&serveGateway, "gateway", false, "Enable LLM API gateway at /v1/proxy/*")
	serveCmd.Flags().StringVar(&serveGatewayConfig, "gateway-config", "talon.config.yaml", "Path to config file with gateway block (used when --gateway is set)")
	serveCmd.Flags().BoolVar(&serveProxyQuickstart, "proxy-quickstart", false, "Enable local/dev OpenAI-compatible quickstart proxy at host-root /v1/*")
	serveCmd.Flags().BoolVar(&serveUnsafeListen, "unsafe-listen", false, "Allow --proxy-quickstart to bind non-loopback addresses")
	rootCmd.AddCommand(serveCmd)
}

//nolint:gocyclo // orchestration flow is inherently branched
func runServe(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	gatewayConfigExplicit := cmd.Flags().Changed("gateway-config")
	if err := validateServeModeFlags(serveProxyQuickstart, serveGateway, gatewayConfigExplicit); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}
	cfg.WarnIfDefaultKeys()

	policyBaseDir := "."
	policyPath := cfg.DefaultPolicy
	safePath, err := policy.ResolvePathUnderBase(policyBaseDir, policyPath)
	if err != nil {
		return fmt.Errorf("policy path: %w", err)
	}
	pol, err := policy.LoadPolicy(ctx, policyPath, false, policyBaseDir)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}
	policyPath = safePath
	policyBaseDir = filepath.Dir(safePath) // so pricing and other project paths resolve relative to policy directory

	policyEngine, err := policy.NewEngine(ctx, pol)
	if err != nil {
		return fmt.Errorf("policy engine: %w", err)
	}

	cls, err := policy.NewPIIScannerForPolicyWithEnrichment(ctx, pol, "", policyEngine)
	if err != nil {
		return fmt.Errorf("initializing policy-aware PII scanner: %w", err)
	}
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(cfg.MaxAttachmentMB)

	if serveGateway {
		if err := config.ResolveSovereigntyForGateway(cfg, serveGatewayConfig); err != nil {
			return fmt.Errorf("resolving sovereignty config: %w", err)
		}
	}

	if err := sovereignty.ValidateSovereignty(cfg, nil); err != nil {
		return fmt.Errorf("sovereignty validation: %w", err)
	}

	providers := buildProviders(cfg)
	pricingTable := loadPricingTable(cfg, policyBaseDir)
	injectPricingInProviders(providers, pricingTable)
	gatewayEstimator := gatewayCostEstimator(providers)
	routing, costLimits := loadRoutingAndCostLimits(ctx, policyPath, policyBaseDir)
	router := llm.NewRouter(routing, providers, costLimits)

	secretsStore, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	if err != nil {
		return fmt.Errorf("initializing secrets: %w", err)
	}
	defer secretsStore.Close()

	evidenceStore, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return fmt.Errorf("initializing evidence: %w", err)
	}
	defer evidenceStore.Close()
	sessionStore, err := talonsession.NewStore(cfg.EvidenceDBPath())
	if err != nil {
		return fmt.Errorf("initializing sessions: %w", err)
	}
	defer sessionStore.Close()
	promptStore, err := talonprompt.NewStore(cfg.EvidenceDBPath())
	if err != nil {
		return fmt.Errorf("initializing prompt store: %w", err)
	}
	defer promptStore.Close()

	var planReviewStore *agent.PlanReviewStore
	dbPlan, err := sql.Open("sqlite3", cfg.EvidenceDBPath()+"?_journal_mode=WAL&_busy_timeout=5000")
	if err == nil {
		defer dbPlan.Close()
		planReviewStore, err = agent.NewPlanReviewStore(dbPlan)
		if err != nil {
			log.Warn().Err(err).Msg("plan review store unavailable")
			planReviewStore = nil
		}
	} else {
		log.Warn().Err(err).Msg("plan review DB unavailable")
	}

	var idempotencyStore *agent.IdempotencyStore
	dbIdem, err := sql.Open("sqlite3", cfg.EvidenceDBPath()+"?_journal_mode=WAL&_busy_timeout=5000")
	if err == nil {
		defer dbIdem.Close()
		idempotencyStore, err = agent.NewIdempotencyStore(dbIdem)
		if err != nil {
			log.Warn().Err(err).Msg("idempotency store unavailable")
			idempotencyStore = nil
		}
	} else {
		log.Warn().Err(err).Msg("idempotency DB unavailable")
	}

	var memStore *memory.Store
	memStore, err = memory.NewStore(cfg.MemoryDBPath())
	if err != nil {
		log.Warn().Err(err).Msg("memory store unavailable")
	} else {
		defer memStore.Close()
	}

	activeRunTracker := &agent.ActiveRunTracker{}
	runRegistry := agent.NewRunRegistry()
	overrideStore := agent.NewOverrideStore()
	toolApprovalStore := agent.NewToolApprovalStore(5 * time.Minute)

	cbThreshold := 5
	cbWindow := 60 * time.Second
	if pol.Policies.RateLimits != nil {
		if pol.Policies.RateLimits.CircuitBreakerThreshold > 0 {
			cbThreshold = pol.Policies.RateLimits.CircuitBreakerThreshold
		}
		if pol.Policies.RateLimits.CircuitBreakerWindow != "" {
			if d, err := time.ParseDuration(pol.Policies.RateLimits.CircuitBreakerWindow); err == nil {
				cbWindow = d
			}
		}
	}
	circuitBreaker := agent.NewCircuitBreaker(cbThreshold, cbWindow)

	tfThreshold := 10
	tfWindow := 5 * time.Minute
	if pol.Policies.RateLimits != nil {
		if pol.Policies.RateLimits.ToolFailureThreshold > 0 {
			tfThreshold = pol.Policies.RateLimits.ToolFailureThreshold
		}
		if pol.Policies.RateLimits.ToolFailureWindow != "" {
			if d, err := time.ParseDuration(pol.Policies.RateLimits.ToolFailureWindow); err == nil {
				tfWindow = d
			}
		}
	}
	toolFailureTracker := agent.NewToolFailureTracker(tfThreshold, tfWindow)

	toolRegistry := tools.NewRegistry()
	var serveCacheStore *cache.Store
	var serveCacheEmbedder *cache.BM25
	var serveCacheScrubber *cache.PIIScrubber
	var serveCachePolicy *cache.Evaluator
	if cfg.Cache != nil && cfg.Cache.Enabled {
		cacheStore, err := cache.NewStore(cfg.CacheDBPath(), cfg.SigningKey)
		if err != nil {
			log.Warn().Err(err).Msg("cache store unavailable, running without semantic cache")
		} else {
			defer cacheStore.Close()
			serveCacheStore = cacheStore
			cachePolicy, err := cache.NewEvaluator(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("cache policy evaluator unavailable, running without semantic cache")
			} else {
				serveCachePolicy = cachePolicy
				serveCacheEmbedder = cache.NewBM25()
				serveCacheScrubber = cache.NewPIIScrubber(cls)
			}
		}
	}
	runnerCfg := agent.RunnerConfig{
		PolicyDir:         ".",
		DefaultPolicyPath: policyPath,
		Classifier:        cls,
		AttScanner:        attScanner,
		Extractor:         extractor,
		Router:            router,
		Secrets:           secretsStore,
		Evidence:          evidenceStore,
		SessionStore:      sessionStore,
		PromptStore:       promptStore,
		PlanReview:        planReviewStore,
		ToolRegistry:      toolRegistry,
		ActiveRunTracker:  activeRunTracker,
		RunRegistry:       runRegistry,
		Overrides:         overrideStore,
		ToolApprovals:     toolApprovalStore,
		CircuitBreaker:    circuitBreaker,
		ToolFailures:      toolFailureTracker,
		Memory:            memStore,
		Pricing:           pricingTable,
		Idempotency:       idempotencyStore,
	}
	if serveCacheStore != nil && serveCachePolicy != nil {
		runnerCfg.CacheStore = serveCacheStore
		runnerCfg.CacheEmbedder = serveCacheEmbedder
		runnerCfg.CacheScrubber = serveCacheScrubber
		runnerCfg.CachePolicy = serveCachePolicy
		runnerCfg.CacheConfig = &agent.RunnerCacheConfig{
			Enabled:             cfg.Cache.Enabled,
			DefaultTTL:          cfg.Cache.DefaultTTL,
			TTLByTier:           cfg.Cache.TTLByTier,
			SimilarityThreshold: cfg.Cache.SimilarityThreshold,
			MaxEntriesPerTenant: cfg.Cache.MaxEntriesPerTenant,
		}
	}
	runner := agent.NewRunner(runnerCfg)
	startPlanAutoDispatcher(ctx, planReviewStore, runner)

	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				toolApprovalStore.Cleanup(30 * time.Minute)
			case <-ctx.Done():
				return
			}
		}
	}()

	if memStore != nil && pol.Memory != nil && pol.Memory.Enabled {
		stopRetention := memory.StartRetentionLoop(ctx, memStore, pol, 24*time.Hour)
		defer stopRetention()
	}

	scheduler := trigger.NewScheduler(runner)
	if err := scheduler.RegisterSchedules(pol); err != nil {
		return fmt.Errorf("registering schedules: %w", err)
	}
	scheduler.Start()
	defer scheduler.Stop()

	webhookHandler := trigger.NewWebhookHandler(runner, pol)

	adminKey := os.Getenv("TALON_ADMIN_KEY")
	if adminKey == "" {
		log.Warn().Msg("TALON_ADMIN_KEY not set — admin-only endpoints will be unrestricted. Set for production.")
	}

	evidenceGen := evidence.NewGenerator(evidenceStore)

	opts := []server.Option{
		server.WithPlanReviewStore(planReviewStore),
		server.WithMemoryStore(memStore),
		server.WithSessionStore(sessionStore),
		server.WithCORSOrigins([]string{"*"}),
		server.WithActiveRunTracker(activeRunTracker),
		server.WithRunRegistry(runRegistry),
		server.WithOverrideStore(overrideStore),
		server.WithToolApprovalStore(toolApprovalStore),
		server.WithGraphEventsHandler(policyEngine, evidenceGen, evidenceStore),
		// Declared compliance facts for /v1/compliance/* auditor exports.
		// Loaded per request (like the compliance CLI) so config edits are
		// picked up without a restart; load warnings surface as document
		// warnings, not log noise.
		server.WithComplianceDeclarations(func(ctx context.Context) compliance.Declarations {
			return loadComplianceDeclarations(ctx, policyPath, io.Discard)
		}),
	}
	if serveDashboard {
		opts = append(opts, server.WithDashboard(web.DashboardHTML))
	}

	mcpHandler := mcp.NewHandler(toolRegistry, policyEngine, evidenceStore, cls)
	opts = append(opts, server.WithMCPServer(mcpHandler))

	var proxyHandler http.Handler
	if serveProxyConfig != "" {
		proxyCfg, err := mcp.LoadProxyConfig(ctx, serveProxyConfig)
		if err != nil {
			return fmt.Errorf("loading proxy config: %w", err)
		}
		proxyEngine, err := policy.NewProxyEngine(ctx, proxyCfg)
		if err != nil {
			return fmt.Errorf("proxy policy engine: %w", err)
		}
		proxyHandler = mcp.NewProxyHandler(proxyCfg, proxyEngine, evidenceStore, cls)
		opts = append(opts, server.WithMCPProxy(proxyHandler))
	}

	var gatewayHandler http.Handler
	var gatewayCfgForMode *gateway.GatewayConfig
	tenantKeys := map[string]string{}
	if serveGateway {
		gatewayCfg, err := gateway.LoadGatewayConfig(serveGatewayConfig)
		if err != nil {
			return fmt.Errorf("loading gateway config: %w", err)
		}
		if err := sovereignty.ValidateSovereignty(cfg, gatewayCfg); err != nil {
			return fmt.Errorf("sovereignty validation: %w", err)
		}
		if err := sovereignty.ValidateAirGap(cfg, gatewayCfg); err != nil {
			return fmt.Errorf("air-gap validation: %w", err)
		}
		guard, err := sovereignty.ApplyAirGapPreset(cfg, gatewayCfg)
		if err != nil {
			return fmt.Errorf("air-gap preset: %w", err)
		}
		if guard != nil {
			gatewayCfg.UpstreamTransport = guard
		}
		if err := gatewayCfg.ApplyDefaults(); err != nil {
			return fmt.Errorf("gateway defaults: %w", err)
		}
		tenantKeys = gatewayCfg.TenantKeyMap()
		log.Info().Int("tenant_keys", len(tenantKeys)).Int("callers", len(gatewayCfg.Callers)).Msg("gateway_tenant_keys_loaded")
		// --gateway flag explicitly opts in; override config's enabled field
		if !gatewayCfg.Enabled {
			log.Info().Msg("--gateway flag set; enabling gateway (config had enabled: false)")
			gatewayCfg.Enabled = true
		}
		{
			gatewayPolicy, err := policy.NewGatewayEngine(ctx)
			if err != nil {
				return fmt.Errorf("gateway policy engine: %w", err)
			}
			gw, err := gateway.NewGateway(gatewayCfg, cls, evidenceStore, secretsStore, gatewayPolicy, gatewayEstimator)
			if err != nil {
				return fmt.Errorf("initializing gateway: %w", err)
			}
			if serveCacheStore != nil && serveCachePolicy != nil && cfg.Cache != nil {
				gw.SetCache(serveCacheStore, serveCacheEmbedder, serveCacheScrubber, serveCachePolicy,
					cfg.Cache.Enabled, cfg.Cache.DefaultTTL, cfg.Cache.TTLByTier, cfg.Cache.SimilarityThreshold, cfg.Cache.MaxEntriesPerTenant)
			}
			gatewayHandler = gw
			gatewayCfgForMode = gatewayCfg
			opts = append(opts, server.WithGateway(gatewayHandler))
		}
	} else if serveProxyQuickstart {
		quickstartCfg, err := gateway.QuickstartConfig(gateway.QuickstartOptions{
			UnsafeListen: serveUnsafeListen,
		})
		if err != nil {
			return fmt.Errorf("building quickstart gateway config: %w", err)
		}
		gatewayPolicy, err := policy.NewGatewayEngine(ctx)
		if err != nil {
			return fmt.Errorf("gateway policy engine: %w", err)
		}
		gw, err := gateway.NewGateway(quickstartCfg, cls, evidenceStore, secretsStore, gatewayPolicy, gatewayEstimator)
		if err != nil {
			return fmt.Errorf("initializing quickstart gateway: %w", err)
		}
		if serveCacheStore != nil && serveCachePolicy != nil && cfg.Cache != nil {
			gw.SetCache(serveCacheStore, serveCacheEmbedder, serveCacheScrubber, serveCachePolicy,
				cfg.Cache.Enabled, cfg.Cache.DefaultTTL, cfg.Cache.TTLByTier, cfg.Cache.SimilarityThreshold, cfg.Cache.MaxEntriesPerTenant)
		}
		gatewayHandler = gw
		gatewayCfgForMode = quickstartCfg
		opts = append(opts,
			server.WithGateway(gatewayHandler),
			server.WithQuickstartEnabled(true),
			server.WithProxyQuickstart(server.NewQuickstartFacade(gw, quickstartCfg.ListenPrefix, &quickstartCfg.Callers[0])),
		)
		// Intentionally do NOT register a synthetic tenant key here. Quickstart is
		// a host-root OpenAI-compatibility facade backed by a synthetic in-process
		// caller; it must not silently unlock the tenant-auth surface. Tenant
		// endpoints (e.g. relocated /v1/agents/chat/completions) still require a
		// real tenant key from configuration if the operator wants to use them.
	}

	// Gateway dashboard metrics collector
	var metricsCollector *metrics.Collector
	if gatewayHandler != nil {
		enforcementMode := "enforce"
		if gatewayCfgForMode != nil {
			enforcementMode = string(gatewayCfgForMode.Mode)
		}

		metricsTenantID := "default"
		if gatewayCfgForMode != nil {
			metricsTenantID = gatewayCfgForMode.MetricsTenantScope()
		}
		collectorOpts := []metrics.CollectorOption{
			metrics.WithActiveRunsFn(func() int {
				return activeRunTracker.Count(metricsTenantID)
			}),
			metrics.WithTenantID(metricsTenantID),
		}
		if planReviewStore != nil {
			collectorOpts = append(collectorOpts, metrics.WithPlanStatsFn(func(ctx context.Context, tenantID string) (metrics.PlanStats, error) {
				stats, err := planReviewStore.Stats(ctx, tenantID)
				if err != nil {
					return metrics.PlanStats{}, err
				}
				return metrics.PlanStats{
					Pending:          stats.Pending,
					Approved:         stats.Approved,
					Rejected:         stats.Rejected,
					Modified:         stats.Modified,
					Dispatched:       stats.Dispatched,
					DispatchFailures: stats.DispatchFailures,
				}, nil
			}))
		}

		budgetDaily, budgetMonthly := 0.0, 0.0
		if pol.Policies.CostLimits != nil {
			budgetDaily = pol.Policies.CostLimits.Daily
			budgetMonthly = pol.Policies.CostLimits.Monthly
		}
		if gatewayCfgForMode != nil {
			if budgetDaily <= 0 && gatewayCfgForMode.ServerDefaults.MaxDailyCost > 0 {
				budgetDaily = gatewayCfgForMode.ServerDefaults.MaxDailyCost
			}
			if budgetMonthly <= 0 && gatewayCfgForMode.ServerDefaults.MaxMonthlyCost > 0 {
				budgetMonthly = gatewayCfgForMode.ServerDefaults.MaxMonthlyCost
			}
		}
		if budgetDaily > 0 || budgetMonthly > 0 {
			collectorOpts = append(collectorOpts, metrics.WithBudgetLimits(budgetDaily, budgetMonthly))
		}

		metricsCollector = metrics.NewCollector(enforcementMode, evidenceStore, collectorOpts...)
		defer metricsCollector.Close()
		evidenceStore.SetStoreObserver(func(ctx context.Context, ev *evidence.Evidence) {
			metricsCollector.Record(metrics.GatewayEventFromEvidence(ev))
		})

		if err := metricsCollector.BackfillFromStore(ctx, evidenceStore); err != nil {
			log.Warn().Err(err).Msg("dashboard backfill failed")
		}
		reconcileCfg := metrics.DefaultReconcileLoopConfig()
		if raw := strings.TrimSpace(os.Getenv("TALON_METRICS_RECONCILE_INTERVAL")); raw != "" {
			if d, err := time.ParseDuration(raw); err == nil {
				reconcileCfg.Interval = d
			}
		}
		if raw := strings.TrimSpace(os.Getenv("TALON_METRICS_RECONCILE_WINDOW")); raw != "" {
			if d, err := time.ParseDuration(raw); err == nil {
				reconcileCfg.Window = d
			}
		}
		stopReconcile := metricsCollector.StartReconcileLoop(ctx, evidenceStore, reconcileCfg)
		defer stopReconcile()

		if gw, ok := gatewayHandler.(*gateway.Gateway); ok {
			gw.SetSessionStore(sessionStore)
		}

		opts = append(opts,
			server.WithMetricsCollector(metricsCollector),
			server.WithGatewayDashboard(web.GatewayDashboardHTML),
		)
	}

	srv := server.NewServer(
		runner,
		evidenceStore,
		webhookHandler,
		policyEngine,
		pol,
		policyPath,
		secretsStore,
		adminKey,
		tenantKeys,
		opts...,
	)

	addr, err := resolveServeAddress(serveHost, servePort, serveProxyQuickstart, serveUnsafeListen)
	if err != nil {
		return err
	}
	if serveProxyQuickstart {
		if serveUnsafeListen {
			log.Warn().Msg("proxy quickstart exposed on non-loopback address; local/dev use only")
		}
		log.Info().
			Str("openai_base_url", "http://"+addr).
			Str("agent_chat_path", "/v1/agents/chat/completions").
			Str("mode", string(gatewayCfgForMode.Mode)).
			Str("pii_default", "redact").
			Str("auth_precedence", "client bearer > OPENAI_API_KEY > 401").
			Msg("proxy_quickstart_enabled")
	}
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      srv.Routes(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	log.Info().
		Str("addr", addr).
		Int("cron_entries", scheduler.Entries()).
		Str("agent", pol.Agent.Name).
		Bool("dashboard", serveDashboard).
		Bool("gateway_dashboard", metricsCollector != nil).
		Bool("mcp_proxy", proxyHandler != nil).
		Bool("gateway", gatewayHandler != nil).
		Msg("talon_serve_started")

	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info().Msg("shutdown_signal_received")
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info().Msg("server_stopped")
	return nil
}

func resolveServeAddress(host string, port int, quickstartEnabled, unsafeListen bool) (string, error) {
	cleanHost := strings.TrimSpace(host)
	if !quickstartEnabled {
		if cleanHost == "" {
			return fmt.Sprintf(":%d", port), nil
		}
		return net.JoinHostPort(cleanHost, fmt.Sprintf("%d", port)), nil
	}

	if cleanHost == "" {
		return net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)), nil
	}
	normalizedHost := strings.Trim(cleanHost, "[]")
	if isLoopbackHost(normalizedHost) {
		return net.JoinHostPort(normalizedHost, fmt.Sprintf("%d", port)), nil
	}
	if !unsafeListen {
		return "", fmt.Errorf("quickstart cannot bind to %s:%d: use --unsafe-listen to override", normalizedHost, port)
	}
	return net.JoinHostPort(normalizedHost, fmt.Sprintf("%d", port)), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func gatewayCostEstimator(providers map[string]llm.Provider) gateway.CostEstimator {
	return func(model string, inputTokens, outputTokens int) float64 {
		// Use the highest known estimate across configured providers so pre-call budget checks
		// stay conservative even when only model is known at this stage.
		maxEstimate := 0.0
		for _, provider := range providers {
			if provider == nil {
				continue
			}
			if estimate := provider.EstimateCost(model, inputTokens, outputTokens); estimate > maxEstimate {
				maxEstimate = estimate
			}
		}
		if maxEstimate > 0 {
			return maxEstimate
		}
		// Fallback when pricing is unavailable/unknown.
		return 0.01
	}
}

// validateServeModeFlags enforces mutual exclusivity between the quickstart
// facade and the full gateway. gatewayConfigExplicit should be true only when
// the user passed --gateway-config explicitly (detected via cobra's
// Flags().Changed), so the check does not depend on the default string value.
func validateServeModeFlags(proxyQuickstart, gatewayEnabled, gatewayConfigExplicit bool) error {
	if !proxyQuickstart {
		return nil
	}
	if gatewayEnabled || gatewayConfigExplicit {
		return fmt.Errorf("--proxy-quickstart cannot be combined with --gateway or --gateway-config")
	}
	return nil
}
