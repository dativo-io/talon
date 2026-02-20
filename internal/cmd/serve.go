package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/trigger"
)

var servePort int

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Talon server with cron triggers and webhook endpoints",
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", 8080, "HTTP server port")
	rootCmd.AddCommand(serveCmd)
}

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

	policyPath := cfg.DefaultPolicy
	pol, err := policy.LoadPolicy(ctx, policyPath, false)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(cfg.MaxAttachmentMB)

	providers := buildProviders(cfg)
	routing, costLimits := loadRoutingAndCostLimits(ctx, policyPath)
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

	var memStore *memory.Store
	memStore, err = memory.NewStore(cfg.MemoryDBPath())
	if err != nil {
		log.Warn().Err(err).Msg("memory store unavailable")
	} else {
		defer memStore.Close()
	}

	activeRunTracker := &agent.ActiveRunTracker{}
	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:         ".",
		DefaultPolicyPath: policyPath,
		Classifier:        cls,
		AttScanner:        attScanner,
		Extractor:         extractor,
		Router:            router,
		Secrets:           secretsStore,
		Evidence:          evidenceStore,
		ToolRegistry:      tools.NewRegistry(),
		ActiveRunTracker:  activeRunTracker,
		Memory:            memStore,
	})

	// Start memory retention loop (daily purge of expired entries + max_entries enforcement)
	if memStore != nil && pol.Memory != nil && pol.Memory.Enabled {
		stopRetention := memory.StartRetentionLoop(ctx, memStore, pol, 24*time.Hour)
		defer stopRetention()
	}

	// Register cron triggers
	scheduler := trigger.NewScheduler(runner)
	if err := scheduler.RegisterSchedules(pol); err != nil {
		return fmt.Errorf("registering schedules: %w", err)
	}
	scheduler.Start()
	defer scheduler.Stop()

	// Set up HTTP with webhook triggers
	webhookHandler := trigger.NewWebhookHandler(runner, pol)
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	// Minimal status page: key SMB metrics (evidence count, cost today, active runs) for monitoring.
	r.Get("/status", newStatusHandler(evidenceStore, activeRunTracker, "default"))
	r.Post("/v1/triggers/{name}", webhookHandler.HandleWebhook)

	addr := fmt.Sprintf(":%d", servePort)
	server := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	log.Info().
		Str("addr", addr).
		Int("cron_entries", scheduler.Entries()).
		Str("agent", pol.Agent.Name).
		Msg("talon_serve_started")

	// Start HTTP in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for shutdown signal
	select {
	case <-ctx.Done():
		log.Info().Msg("shutdown_signal_received")
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

// statusResponse is the JSON shape for GET /status (minimal dashboard metrics).
// Metric fields have no omitempty so zero values are always present for reliable monitoring.
type statusResponse struct {
	Status             string  `json:"status"`
	EvidenceCountToday int     `json:"evidence_count_today"`
	CostEURToday       float64 `json:"cost_eur_today"`
	ActiveRuns         int     `json:"active_runs"`
}

func newStatusHandler(store *evidence.Store, tracker *agent.ActiveRunTracker, defaultTenantID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.URL.Query().Get("tenant_id")
		if tenantID == "" {
			tenantID = defaultTenantID
		}
		resp := statusResponse{Status: "ok"}
		if store != nil {
			ctx := r.Context()
			now := time.Now().UTC()
			dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
			dayEnd := dayStart.Add(24 * time.Hour)
			if n, err := store.CountInRange(ctx, tenantID, "", dayStart, dayEnd); err == nil {
				resp.EvidenceCountToday = n
			}
			if cost, err := store.CostTotal(ctx, tenantID, "", dayStart, dayEnd); err == nil {
				resp.CostEURToday = cost
			}
		}
		if tracker != nil {
			resp.ActiveRuns = tracker.Count(tenantID)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}
