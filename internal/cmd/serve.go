package cmd

import (
	"context"
	"database/sql"
	"errors"
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
	"github.com/dativo-io/talon/internal/agentcatalog"
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
	"github.com/dativo-io/talon/internal/pricing"
	talonprompt "github.com/dativo-io/talon/internal/prompt"
	"github.com/dativo-io/talon/internal/scanner"
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
	polIsSynthetic := false
	pol, err := policy.LoadPolicy(ctx, policyPath, false, policyBaseDir)
	if err != nil {
		gatewayOnly := serveGateway || serveProxyQuickstart
		// agents_dir mode (#267): fleet membership comes from the directory
		// scan, so the default single file is optional — the minimal default
		// only backs the process-wide surfaces that remain single-policy
		// (MCP/graph interception, #114); native runs resolve the catalog.
		if (gatewayOnly || cfg.AgentsDir != "") && errors.Is(err, os.ErrNotExist) {
			pol = &policy.Policy{
				Agent: policy.AgentConfig{Name: "gateway", Version: "0.0.0"},
			}
			polIsSynthetic = true
			log.Warn().Str("path", policyPath).Msg("agent policy not found; using minimal default (gateway-only or agents_dir mode)")
		} else {
			return fmt.Errorf("loading policy: %w", err)
		}
	}
	policyPath = safePath
	policyBaseDir = filepath.Dir(safePath) // so pricing and other project paths resolve relative to policy directory

	policyEngine, err := policy.NewEngine(ctx, pol)
	if err != nil {
		return fmt.Errorf("policy engine: %w", err)
	}

	cls, err := scanner.Build(ctx, cfg, pol, policyEngine)
	if err != nil {
		return fmt.Errorf("initializing PII scanner: %w", err)
	}
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(cfg.MaxAttachmentMB)

	if serveGateway {
		if err := config.ResolveSovereigntyForGateway(cfg, serveGatewayConfig); err != nil {
			return fmt.Errorf("resolving sovereignty config: %w", err)
		}
	}

	var preloadedGatewayCfg *gateway.GatewayConfig
	if serveGateway {
		preloadedGatewayCfg, err = gateway.LoadGatewayConfig(serveGatewayConfig)
		if err != nil {
			return fmt.Errorf("loading gateway config for sovereignty: %w", err)
		}
	}
	sovereignty.ApplySovereigntyGate(cfg, preloadedGatewayCfg)

	providers := buildProviders(cfg)
	pricingTable := loadPricingTable(cfg, policyBaseDir)
	injectPricingInProviders(providers, pricingTable)
	gatewayEstimator := gatewayCostEstimator(pricingTable)
	// Reuse the policy already loaded above; re-loading here would parse and
	// re-validate the same file a second time, double-logging routing warnings.
	routing, costLimits := pol.Policies.ModelRouting, pol.Policies.CostLimits
	router := llm.NewRouter(routing, providers, costLimits)

	secretsStore, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	if err != nil {
		return fmt.Errorf("initializing secrets: %w", err)
	}
	defer secretsStore.Close()

	adminKey := os.Getenv("TALON_ADMIN_KEY")
	if adminKey == "" {
		log.Warn().Msg("TALON_ADMIN_KEY not set — admin-only endpoints will be unrestricted. Set for production.")
		if serveGateway || serveProxyQuickstart {
			// Native execution routes fail CLOSED in gateway mode without an
			// admin key (they bypass gateway.organization_policy, #266 round 6).
			log.Warn().Msg("gateway mode without TALON_ADMIN_KEY: native execution routes (/v1/agents/run, native /v1/chat/completions, /mcp, /mcp/proxy, /v1/graph/events) are DISABLED (401) — agent traffic goes through /v1/proxy; set TALON_ADMIN_KEY to enable operator-native execution")
		}
	}

	var identityRegistry *gateway.IdentityRegistry
	var fleetScan *agentcatalog.ScanResult
	if cfg.AgentsDir != "" && !serveProxyQuickstart {
		// agents_dir discovery (#267): the directory is authoritative for
		// fleet membership — every agent.talon.yaml found is one AI use case
		// with its own key. Scan or registry failures are terminal in every
		// serve mode (deliberate fleet configuration, no degrade affordance).
		identityRegistry, fleetScan, err = buildServeIdentityRegistryFromDir(ctx, cfg.AgentsDir, secretsStore, adminKey)
		if err != nil {
			return err
		}
		log.Info().
			Int("agents", len(fleetScan.Agents)).
			Str("generation", shortGeneration(fleetScan.Digest)).
			Str("agents_dir", cfg.AgentsDir).
			Msg("agents_dir_discovered")
	} else {
		identityRegistry, err = buildServeIdentityRegistry(ctx, pol, policyPath, secretsStore, adminKey, serveGateway, serveProxyQuickstart)
		if err != nil {
			return err
		}
	}
	// ONE fleet generation (#267): catalog + compiled per-agent bundles +
	// identity registry, published together behind ONE atomic pointer.
	// Every consumer — native execution, gateway auth, server agent-key
	// auth, dashboard caps, metrics scope — derives its view from this
	// holder, so a reload swap can never split authentication and execution
	// across two generations. Both membership modes run the IDENTICAL
	// catalog pipeline (same Source scanner, same digest algorithm — a
	// reload re-scan of unchanged files must reproduce the generation).
	// Bundles recompile the engine/scanner serve built above for its
	// process-wide surfaces — one extra Rego compile (and, for external
	// scanner engines, one extra health probe) at startup, in exchange for
	// one pipeline with no drift.
	deps := agentcatalog.BundleDeps{Config: cfg, Providers: providers}
	var runtimeSnapshot *agentcatalog.RuntimeSnapshot
	switch {
	case fleetScan != nil:
		bundles, bundleErr := agentcatalog.BuildRuntimeAgents(ctx, fleetScan, deps)
		if bundleErr != nil {
			return fmt.Errorf("compiling agent runtime bundles: %w", bundleErr)
		}
		runtimeSnapshot = agentcatalog.NewRuntimeSnapshot(fleetScan, bundles, identityRegistry, time.Now().UTC())
	case polIsSynthetic:
		// Gateway-only mode with no agent file at all: a minimal synthetic
		// one-agent snapshot backs the process-wide surfaces. Its digest can
		// never match a real scan, so the first real file is a new generation.
		ca := agentcatalog.CatalogAgent{
			Name: pol.Agent.Name, TenantID: pol.Agent.TenantID, Path: policyPath,
			PolicyDigest: pol.Hash, Enabled: true, Policy: pol,
		}
		singleScan := &agentcatalog.ScanResult{Source: policyPath, Digest: "synthetic:" + pol.Hash, Agents: []agentcatalog.CatalogAgent{ca}}
		single := &agentcatalog.RuntimeAgent{CatalogAgent: ca, Engine: policyEngine, Classifier: cls, Router: router}
		runtimeSnapshot = agentcatalog.NewRuntimeSnapshot(singleScan, []*agentcatalog.RuntimeAgent{single}, identityRegistry, time.Now().UTC())
	default:
		singleScan, scanErr := agentcatalog.Source{File: policyPath}.Scan(ctx)
		if scanErr != nil {
			return fmt.Errorf("scanning agent policy for the runtime catalog: %w", scanErr)
		}
		bundles, bundleErr := agentcatalog.BuildRuntimeAgents(ctx, singleScan, deps)
		if bundleErr != nil {
			return fmt.Errorf("compiling agent runtime bundle: %w", bundleErr)
		}
		runtimeSnapshot = agentcatalog.NewRuntimeSnapshot(singleScan, bundles, identityRegistry, time.Now().UTC())
	}
	runtimeHolder := agentcatalog.NewRuntimeHolder(runtimeSnapshot)
	// The gateway-facing registry view over the SAME holder (#267 review):
	// there is no independently swappable registry pointer.
	registrySource := runtimeHolder.RegistrySource()

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

	// Trackers carry process defaults only (#267 review): each run evaluates
	// under ITS agent's rate_limits thresholds, derived from the resolved
	// bundle policy — one agent's circuit-breaker config never governs
	// another's.
	circuitBreaker := agent.NewCircuitBreaker(0, 0)

	toolFailureTracker := agent.NewToolFailureTracker(0, 0)

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
		// The catalog is the ONE resolution source (#267): every run resolves
		// its agent's compiled bundle (policy + engine + scanner + router)
		// from the current generation — no per-process classifier/router.
		Catalog:          runtimeHolder,
		PolicyDir:        ".",
		AttScanner:       attScanner,
		Extractor:        extractor,
		Secrets:          secretsStore,
		Evidence:         evidenceStore,
		SessionStore:     sessionStore,
		PromptStore:      promptStore,
		PlanReview:       planReviewStore,
		ToolRegistry:     toolRegistry,
		ActiveRunTracker: activeRunTracker,
		RunRegistry:      runRegistry,
		Overrides:        overrideStore,
		ToolApprovals:    toolApprovalStore,
		CircuitBreaker:   circuitBreaker,
		ToolFailures:     toolFailureTracker,
		Memory:           memStore,
		Pricing:          pricingTable,
		Idempotency:      idempotencyStore,
	}
	if serveCacheStore != nil && serveCachePolicy != nil {
		runnerCfg.CacheStore = serveCacheStore
		runnerCfg.CacheEmbedder = serveCacheEmbedder
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

	// Memory retention is PER AGENT under THAT agent's policy (#267): in a
	// fleet, agent A's retention_days must never purge agent B's rows. The
	// loop re-reads the current generation each tick, so a reload's policy
	// edits govern the next sweep.
	if memStore != nil {
		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			sweep := func() {
				for _, ra := range runtimeHolder.Current().List() {
					tenant := ra.TenantID
					if tenant == "" {
						tenant = "default"
					}
					memory.RunRetentionForAgent(ctx, memStore, tenant, ra.Name, ra.Policy)
				}
			}
			sweep()
			for {
				select {
				case <-ticker.C:
					sweep()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Session rows follow audit.retention_days (#198, #214) PER AGENT (#267
	// review): each agent's own policy governs its rows — one agent's 30-day
	// data-minimisation window must be honored even while another retains for
	// a year. Re-read per tick (reload-aware).
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				for _, ra := range runtimeHolder.Current().List() {
					if ra.Policy.Audit == nil || ra.Policy.Audit.RetentionDays <= 0 {
						continue
					}
					tenant := ra.TenantID
					if tenant == "" {
						tenant = "default"
					}
					cutoff := time.Now().UTC().Add(-time.Duration(ra.Policy.Audit.RetentionDays) * 24 * time.Hour)
					if n, err := sessionStore.PurgeOlderThanForAgent(ctx, tenant, ra.Name, cutoff); err != nil {
						log.Warn().Err(err).Str("agent_id", ra.Name).Msg("session_retention_sweep_failed")
					} else if n > 0 {
						log.Info().Int64("purged", n).Str("agent_id", ra.Name).Int("retention_days", ra.Policy.Audit.RetentionDays).Msg("session_retention_sweep")
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Schedules and webhook routes register at startup for EVERY discovered
	// agent (#267); dispatch re-resolves the agent from the CURRENT
	// generation, so a reload's policy edits and enabled state govern the
	// next firing. Trigger DEFINITION changes stay restart-required (#297).
	scheduler := trigger.NewScheduler(runner)
	webhookHandler := trigger.NewWebhookHandler(runner)
	for _, ra := range runtimeHolder.Current().List() {
		if err := scheduler.RegisterSchedules(ra.Policy); err != nil {
			return fmt.Errorf("registering schedules for agent %q: %w", ra.Name, err)
		}
		if err := webhookHandler.Register(ra.Policy); err != nil {
			return fmt.Errorf("registering webhooks for agent %q: %w", ra.Name, err)
		}
	}
	scheduler.Start()
	defer scheduler.Stop()

	evidenceGen := evidence.NewGenerator(evidenceStore)

	opts := []server.Option{
		server.WithPlanReviewStore(planReviewStore),
		server.WithMemoryStore(memStore),
		server.WithSessionStore(sessionStore),
		server.WithCORSOrigins([]string{"*"}),
		// Apply the configured data-sovereignty routing mode to server-side
		// agent runs, matching the `talon run` CLI (previously the server
		// silently skipped compliance routing — the SovereigntyMode fix).
		server.WithSovereigntyMode(cfg.EffectiveSovereigntyMode()),
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
	// Server tenant-API auth resolves against the registry HOLDER — one
	// agent key works for /v1/proxy and the tenant-scoped APIs alike, and a
	// reload swap propagates to server auth without middleware rebuilds
	// (#289). The FULL identity (agent name, tenant, team) travels through
	// so native handlers bind attribution to the authenticated agent, not a
	// client-asserted name (#266 review). Auth openness stays governed by
	// the admin-key dev rule only.
	if identityRegistry != nil {
		log.Info().Int("agents", identityRegistry.Len()).Int("tenants", len(identityRegistry.TenantIDs())).Msg("agent_identity_registry_loaded")
	}
	opts = append(opts, server.WithAgentKeyResolver(holderKeyResolver{holder: registrySource}))
	if serveGateway {
		gatewayCfg := preloadedGatewayCfg
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
		// Agent identity (#266): gateway mode with zero keyed agents is a
		// startup error — such a gateway would reject every request, which is
		// never what an operator meant.
		if identityRegistry == nil || identityRegistry.Len() == 0 {
			if cfg.AgentsDir != "" {
				return fmt.Errorf("gateway mode requires at least one keyed agent: no agent.talon.yaml found under agents_dir %s (#267)", cfg.AgentsDir)
			}
			return fmt.Errorf("gateway mode requires at least one keyed agent: add agent.key.secret_name to %s and run `talon secrets set <name> <key>` (#266)", policyPath)
		}
		// --gateway flag explicitly opts in; override config's enabled field
		if !gatewayCfg.Enabled {
			log.Info().Msg("--gateway flag set; enabling gateway (config had enabled: false)")
			gatewayCfg.Enabled = true
		}
		gatewayCfg.EffectiveSovereigntyMode = cfg.EffectiveSovereigntyMode()
		{
			gatewayPolicy, err := policy.NewGatewayEngine(ctx)
			if err != nil {
				return fmt.Errorf("gateway policy engine: %w", err)
			}
			gw, err := gateway.NewGateway(gatewayCfg, registrySource, cls, evidenceStore, secretsStore, gatewayPolicy, gatewayEstimator)
			if err != nil {
				return fmt.Errorf("initializing gateway: %w", err)
			}
			gw.SetPricingCurrency(pricingTable.CurrencyCode())
			if serveCacheStore != nil && serveCachePolicy != nil && cfg.Cache != nil {
				gw.SetCache(serveCacheStore, serveCacheEmbedder, serveCacheScrubber, serveCachePolicy,
					cfg.Cache.Enabled, cfg.Cache.DefaultTTL, cfg.Cache.TTLByTier, cfg.Cache.SimilarityThreshold, cfg.Cache.MaxEntriesPerTenant)
			}
			gatewayHandler = gw
			gatewayCfgForMode = gatewayCfg
			opts = append(opts, server.WithGateway(gatewayHandler))
			// Dashboard budget view reads per-agent caps through the same
			// effective-policy computation enforcement uses (#266), against
			// the CURRENT registry snapshot (#289).
			opts = append(opts, server.WithAgentCapsLookup(agentCapsLookupFor(registrySource, gatewayCfg.OrganizationPolicy)))
		}
	} else if serveProxyQuickstart {
		quickstartCfg, err := gateway.QuickstartConfig(gateway.QuickstartOptions{
			UnsafeListen: serveUnsafeListen,
		})
		if err != nil {
			return fmt.Errorf("building quickstart gateway config: %w", err)
		}
		if err := sovereignty.ValidateAirGap(cfg, quickstartCfg); err != nil {
			return fmt.Errorf("air-gap validation: %w", err)
		}
		guard, err := sovereignty.ApplyAirGapPreset(cfg, quickstartCfg)
		if err != nil {
			return fmt.Errorf("air-gap preset: %w", err)
		}
		if guard != nil {
			quickstartCfg.UpstreamTransport = guard
		}
		quickstartCfg.EffectiveSovereigntyMode = cfg.EffectiveSovereigntyMode()
		gatewayPolicy, err := policy.NewGatewayEngine(ctx)
		if err != nil {
			return fmt.Errorf("gateway policy engine: %w", err)
		}
		gw, err := gateway.NewGateway(quickstartCfg, registrySource, cls, evidenceStore, secretsStore, gatewayPolicy, gatewayEstimator)
		if err != nil {
			return fmt.Errorf("initializing quickstart gateway: %w", err)
		}
		gw.SetPricingCurrency(pricingTable.CurrencyCode())
		if serveCacheStore != nil && serveCachePolicy != nil && cfg.Cache != nil {
			gw.SetCache(serveCacheStore, serveCacheEmbedder, serveCacheScrubber, serveCachePolicy,
				cfg.Cache.Enabled, cfg.Cache.DefaultTTL, cfg.Cache.TTLByTier, cfg.Cache.SimilarityThreshold, cfg.Cache.MaxEntriesPerTenant)
		}
		gatewayHandler = gw
		gatewayCfgForMode = quickstartCfg
		opts = append(opts,
			server.WithGateway(gatewayHandler),
			server.WithQuickstartEnabled(true),
			server.WithProxyQuickstart(server.NewQuickstartFacade(gw, quickstartCfg.ListenPrefix, gateway.NewQuickstartIdentity())),
		)
		// Intentionally do NOT register a synthetic agent key here. Quickstart is
		// a host-root OpenAI-compatibility facade backed by a synthetic in-process
		// identity; it must not silently unlock the tenant-auth surface. Tenant
		// agent chat is not mounted in quickstart at all — govern real agents
		// with `talon serve --gateway` (#285).
	}

	// Gateway dashboard metrics collector
	var metricsCollector *metrics.Collector
	if gatewayHandler != nil {
		enforcementMode := "enforce"
		if gatewayCfgForMode != nil {
			enforcementMode = string(gatewayCfgForMode.Mode)
		}

		// Metrics scope derives from the identity registry — the same source
		// as gateway auth and cache scoping — read through the holder on
		// every snapshot so a reload re-scopes the dashboard (#289).
		// Quickstart mode (nil registry) scopes to its synthetic tenant.
		// ONE scope function for the aggregate fills (#291 review round 2):
		// tenant filter AND budget denominators derive from a SINGLE
		// registry-holder read per snapshot, so a reload (#269) can never
		// mix one registry generation's limits with another's spend scope.
		// The budget half: what enforcement actually gates on (#288) — in
		// gateway mode, the SUM of per-agent BINDING effective caps
		// (registry + ResolveEffectivePolicy, the enforcement path; with
		// #266's single loaded agent, exactly that agent's cap; agents with
		// no positive cap contribute nothing — per-agent refinement is the
		// fleet view #270). Quickstart resolves its synthetic identity the
		// same way. Native mode uses the agent policy's own cost_limits —
		// what the runner enforces. The default agent FILE is never
		// consulted first anymore. The org policy is captured by value:
		// config has no reload seam yet (#269).
		var orgPolForScope gateway.OrganizationPolicy
		if gatewayCfgForMode != nil {
			orgPolForScope = gatewayCfgForMode.OrganizationPolicy
		}
		metricsScope := func() metrics.Scope {
			reg := registrySource.Current() // the ONE snapshot this scope derives from
			scope := metrics.Scope{TenantID: "default"}
			idents := reg.Identities()
			if len(idents) > 0 {
				scope.TenantID = reg.MetricsTenantScope()
			} else if serveProxyQuickstart {
				scope.TenantID = gateway.NewQuickstartIdentity().TenantID
			}
			switch {
			case gatewayCfgForMode != nil:
				if len(idents) == 0 && serveProxyQuickstart {
					idents = []*gateway.ResolvedIdentity{gateway.NewQuickstartIdentity()}
				}
				for _, id := range idents {
					eff := gateway.ResolveEffectivePolicy(orgPolForScope, gateway.ProviderConfig{}, id.Override)
					scope.BudgetDaily += eff.BindingDailyCap()
					scope.BudgetMonthly += eff.BindingMonthlyCap()
				}
			case pol.Policies.CostLimits != nil:
				scope.BudgetDaily = pol.Policies.CostLimits.Daily
				scope.BudgetMonthly = pol.Policies.CostLimits.Monthly
			}
			return scope
		}
		collectorOpts := []metrics.CollectorOption{
			metrics.WithActiveRunsFn(func() int {
				return activeRunTracker.Count(metricsScope().TenantID)
			}),
			metrics.WithScopeFn(metricsScope),
			metrics.WithCurrency(pricingTable.CurrencyCode()),
			// Sessions panel (#199): re-derived from evidence at snapshot
			// time via the same aggregation as `talon audit --session`.
			metrics.WithSessionQuerier(evidenceStore),
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
		nil, // agent-key auth resolves through the registry holder (#289)
		opts...,
	)
	srv.SetClassifier(cls)

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

// agentCapsLookupFor builds the per-agent effective-cap lookup the dashboard
// budget endpoint consumes: registry (through the shared holder, #289) +
// ResolveEffectivePolicy — the same path enforcement uses, so the displayed
// denominator can never disagree with the cap the runtime gated on (#288).
// Caps are provider-independent, so the destination constraints are empty.
// The org policy is captured by value: config (unlike identity) has no
// reload seam yet — #269 revisits. An empty agentID resolves the tenant's
// SINGLE registered agent when exactly one exists; ambiguity reports false
// rather than guessing.
func agentCapsLookupFor(holder gateway.RegistrySource, orgPolicy gateway.OrganizationPolicy) func(tenantID, agentID string) (float64, float64, bool) {
	return func(tenantID, agentID string) (float64, float64, bool) {
		var match *gateway.ResolvedIdentity
		for _, id := range holder.Current().Identities() {
			if id.TenantID != tenantID {
				continue
			}
			if agentID != "" {
				if id.Name == agentID {
					match = id
					break
				}
				continue
			}
			if match != nil {
				return 0, 0, false // ambiguous: two agents, no name
			}
			match = id
		}
		if match == nil {
			return 0, 0, false
		}
		eff := gateway.ResolveEffectivePolicy(orgPolicy, gateway.ProviderConfig{}, match.Override)
		// Binding caps, not the agent-resolved values: an org ceiling
		// (constraints.max_*) tighter than the agent's own cap is what
		// enforcement gates on (#287).
		daily, monthly := eff.BindingDailyCap(), eff.BindingMonthlyCap()
		return daily, monthly, daily > 0 || monthly > 0
	}
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

// gatewayCostEstimator prices a gateway request against the routed provider's
// entry in the pricing table, cache-aware (#196). Provider is the gateway
// provider name; when it isn't in the pricing table (e.g. an aliased endpoint),
// the estimate falls back to a flat default and pricing_known is false so the
// signed evidence records that the cost is an estimate, not a table figure.
func gatewayCostEstimator(pricingTable *pricing.PricingTable) gateway.CostEstimator {
	return func(provider, model string, usage gateway.Usage) gateway.CostResult {
		cost, known, cacheFallback := pricingTable.EstimateCached(
			provider, model, usage.Input, usage.CacheRead, usage.CacheWrite, usage.Output)
		if !known {
			// Unknown provider/model: conservative flat estimate, marked unknown.
			n := float64(usage.Input+usage.CacheRead+usage.CacheWrite+usage.Output) / 1000
			if n < 0.01 {
				n = 0.01
			}
			return gateway.CostResult{Amount: n * 0.002, PricingKnown: false, PricingBasis: gateway.PricingBasisDefault}
		}
		basis := gateway.PricingBasisTable
		if cacheFallback {
			basis = gateway.PricingBasisCacheFalling
		}
		return gateway.CostResult{Amount: cost, PricingKnown: true, PricingBasis: basis}
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
