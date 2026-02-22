package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/mcp"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/server"
	"github.com/dativo-io/talon/internal/trigger"
	"github.com/dativo-io/talon/web"
)

var (
	servePort        int
	serveProxyConfig string
	serveDashboard   bool
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
	rootCmd.AddCommand(serveCmd)
}

// parseAPIKeys returns a map of key -> tenant_id from TALON_API_KEYS (comma-separated; each entry key or key:tenant_id).
func parseAPIKeys(env string) map[string]string {
	m := make(map[string]string)
	if env == "" {
		return m
	}
	for _, part := range strings.Split(env, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tenantID := "default"
		if idx := strings.Index(part, ":"); idx > 0 {
			tenantID = strings.TrimSpace(part[idx+1:])
			part = strings.TrimSpace(part[:idx])
		}
		m[part] = tenantID
	}
	return m
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

	policyEngine, err := policy.NewEngine(ctx, pol)
	if err != nil {
		return fmt.Errorf("policy engine: %w", err)
	}

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(cfg.MaxAttachmentMB)

	providers := buildProviders(cfg)
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
	toolRegistry := tools.NewRegistry()
	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:         ".",
		DefaultPolicyPath: policyPath,
		Classifier:        cls,
		AttScanner:        attScanner,
		Extractor:         extractor,
		Router:            router,
		Secrets:           secretsStore,
		Evidence:          evidenceStore,
		PlanReview:        planReviewStore,
		ToolRegistry:      toolRegistry,
		ActiveRunTracker:  activeRunTracker,
		Memory:            memStore,
	})

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

	apiKeys := parseAPIKeys(os.Getenv("TALON_API_KEYS"))
	if len(apiKeys) == 0 {
		log.Warn().Msg("TALON_API_KEYS not set — all API endpoints will return 401. Set for production.")
	}

	opts := []server.Option{
		server.WithPlanReviewStore(planReviewStore),
		server.WithMemoryStore(memStore),
		server.WithCORSOrigins([]string{"*"}),
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

	srv := server.NewServer(
		runner,
		evidenceStore,
		webhookHandler,
		policyEngine,
		pol,
		policyPath,
		secretsStore,
		apiKeys,
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
		Bool("mcp_proxy", proxyHandler != nil).
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
