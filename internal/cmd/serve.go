package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/cache"
	"github.com/dativo-io/talon/internal/classifier"
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
	"github.com/dativo-io/talon/internal/trigger"
	"github.com/dativo-io/talon/web"
)

var (
	servePort          int
	serveProxyConfig   string
	serveDashboard     bool
	serveGateway       bool
	serveGatewayConfig string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Talon server with cron triggers and webhook endpoints",
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", 8080, "HTTP server port")
	serveCmd.Flags().StringVar(&serveProxyConfig, "proxy-config", "", "Path to MCP proxy config YAML (optional)")
	serveCmd.Flags().BoolVar(&serveDashboard, "dashboard", true, "Serve embedded dashboard at / and /dashboard")
	serveCmd.Flags().BoolVar(&serveGateway, "gateway", false, "Enable LLM API gateway at /v1/proxy/*")
	serveCmd.Flags().StringVar(&serveGatewayConfig, "gateway-config", "talon.config.yaml", "Path to config file with gateway block (used when --gateway is set)")
	rootCmd.AddCommand(serveCmd)
}

//nolint:gocyclo // orchestration flow is inherently branched
func runServe(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(cfg.MaxAttachmentMB)

	providers := buildProviders(cfg)
	pricingTable := loadPricingTable(cfg, policyBaseDir)
	injectPricingInProviders(providers, pricingTable)
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

	var memStore *memory.Store
	memStore, err = memory.NewStore(cfg.MemoryDBPath())
	if err != nil {
		log.Warn().Err(err).Msg("memory store unavailable")
	} else {
		defer memStore.Close()
	}

	activeRunTracker := &agent.ActiveRunTracker{}

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
		CircuitBreaker:    circuitBreaker,
		ToolFailures:      toolFailureTracker,
		Memory:            memStore,
		Pricing:           pricingTable,
	}
	if serveCacheStore != nil && serveCachePolicy != nil {
		runnerCfg.CacheStore = serveCacheStore
		runnerCfg.CacheEmbedder = serveCacheEmbedder
		runnerCfg.CacheScrubber = serveCacheScrubber
		runnerCfg.CachePolicy = serveCachePolicy
		runnerCfg.CacheConfig = &agent.RunnerCacheConfig{
			Enabled:             cfg.Cache.Enabled,
			DefaultTTL:          cfg.Cache.DefaultTTL,
			SimilarityThreshold: cfg.Cache.SimilarityThreshold,
			MaxEntriesPerTenant: cfg.Cache.MaxEntriesPerTenant,
		}
	}
	runner := agent.NewRunner(runnerCfg)
	startPlanAutoDispatcher(ctx, planReviewStore, runner)

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

	opts := []server.Option{
		server.WithPlanReviewStore(planReviewStore),
		server.WithMemoryStore(memStore),
		server.WithSessionStore(sessionStore),
		server.WithCORSOrigins([]string{"*"}),
		server.WithActiveRunTracker(activeRunTracker),
	}
	if serveDashboard {
		opts = append(opts, server.WithDashboard(web.DashboardHTML))
	}

	mcpHandler := mcp.NewHandler(toolRegistry, policyEngine, evidenceStore)
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
	tenantKeys := map[string]string{}
	if serveGateway {
		gatewayCfg, err := gateway.LoadGatewayConfig(serveGatewayConfig)
		if err != nil {
			return fmt.Errorf("loading gateway config: %w", err)
		}
		tenantKeys = gatewayCfg.TenantKeyMap()
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
			gw, err := gateway.NewGateway(gatewayCfg, cls, evidenceStore, secretsStore, gatewayPolicy, nil)
			if err != nil {
				return fmt.Errorf("initializing gateway: %w", err)
			}
			if serveCacheStore != nil && serveCachePolicy != nil && cfg.Cache != nil {
				gw.SetCache(serveCacheStore, serveCacheEmbedder, serveCacheScrubber, serveCachePolicy,
					cfg.Cache.Enabled, cfg.Cache.DefaultTTL, cfg.Cache.SimilarityThreshold, cfg.Cache.MaxEntriesPerTenant)
			}
			gatewayHandler = gw
			opts = append(opts, server.WithGateway(gatewayHandler))
		}
	}

	// Gateway dashboard metrics collector
	var metricsCollector *metrics.Collector
	if gatewayHandler != nil {
		enforcementMode := "enforce"
		if serveGateway {
			if gwCfg, err := gateway.LoadGatewayConfig(serveGatewayConfig); err == nil {
				enforcementMode = string(gwCfg.Mode)
			}
		}

		collectorOpts := []metrics.CollectorOption{
			metrics.WithActiveRunsFn(func() int {
				return activeRunTracker.Count("default")
			}),
			metrics.WithTenantID("default"),
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

		if pol.Policies.CostLimits != nil {
			collectorOpts = append(collectorOpts,
				metrics.WithBudgetLimits(pol.Policies.CostLimits.Daily, pol.Policies.CostLimits.Monthly))
		}

		metricsCollector = metrics.NewCollector(enforcementMode, evidenceStore, collectorOpts...)
		defer metricsCollector.Close()

		if err := metricsCollector.BackfillFromStore(ctx, evidenceStore); err != nil {
			log.Warn().Err(err).Msg("dashboard backfill failed")
		}

		// Wire the collector as the gateway's metrics recorder via adapter
		if gw, ok := gatewayHandler.(*gateway.Gateway); ok {
			gw.SetMetricsRecorder(&metricsRecorderAdapter{collector: metricsCollector})
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

	addr := fmt.Sprintf(":%d", servePort)
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

// metricsRecorderAdapter bridges gateway.MetricsRecorder to metrics.Collector.
type metricsRecorderAdapter struct {
	collector *metrics.Collector
}

func (a *metricsRecorderAdapter) RecordGatewayEvent(event interface{}) {
	m, ok := event.(map[string]interface{})
	if !ok {
		return
	}

	e := mapToGatewayEvent(m)
	a.collector.Record(e)
}

func mapToGatewayEvent(m map[string]interface{}) metrics.GatewayEvent {
	e := metrics.GatewayEvent{}
	if v, ok := m["timestamp"].(time.Time); ok {
		e.Timestamp = v
	} else {
		e.Timestamp = time.Now()
	}
	mapStringFields(m, &e)
	mapSliceFields(m, &e)
	mapNumericFields(m, &e)
	mapBoolFields(m, &e)
	return e
}

func mapStringFields(m map[string]interface{}, e *metrics.GatewayEvent) {
	if v, ok := m["caller_id"].(string); ok {
		e.CallerID = v
	}
	if v, ok := m["model"].(string); ok {
		e.Model = v
	}
	if v, ok := m["pii_action"].(string); ok {
		e.PIIAction = v
	}
	if v, ok := m["enforcement_mode"].(string); ok {
		e.EnforcementMode = v
	}
}

func mapSliceFields(m map[string]interface{}, e *metrics.GatewayEvent) {
	if v, ok := m["pii_detected"].([]string); ok {
		e.PIIDetected = v
	}
	if v, ok := m["tools_requested"].([]string); ok {
		e.ToolsRequested = v
	}
	if v, ok := m["tools_filtered"].([]string); ok {
		e.ToolsFiltered = v
	}
	if v, ok := m["shadow_violations"].([]string); ok {
		e.ShadowViolations = v
	}
}

func mapNumericFields(m map[string]interface{}, e *metrics.GatewayEvent) {
	if v, ok := m["cost_eur"].(float64); ok {
		e.CostEUR = v
	}
	if v, ok := m["tokens_input"].(int); ok {
		e.TokensInput = v
	}
	if v, ok := m["tokens_output"].(int); ok {
		e.TokensOutput = v
	}
	if v, ok := m["latency_ms"].(int64); ok {
		e.LatencyMS = v
	}
	if v, ok := m["cost_saved"].(float64); ok {
		e.CostSaved = v
	}
	if v, ok := m["ttft_ms"].(int64); ok {
		e.TTFTMS = v
	}
	if v, ok := m["tpot_ms"].(float64); ok {
		e.TPOTMS = v
	}
}

func mapBoolFields(m map[string]interface{}, e *metrics.GatewayEvent) {
	if v, ok := m["blocked"].(bool); ok {
		e.Blocked = v
	}
	if v, ok := m["would_have_blocked"].(bool); ok {
		e.WouldHaveBlocked = v
	}
	if v, ok := m["has_error"].(bool); ok {
		e.HasError = v
	}
	if v, ok := m["timed_out"].(bool); ok {
		e.TimedOut = v
	}
	if v, ok := m["cache_hit"].(bool); ok {
		e.CacheHit = v
	}
}
