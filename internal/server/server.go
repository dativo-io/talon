package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/tenant"
	"github.com/dativo-io/talon/internal/trigger"
)

const defaultTimeout = 60 * time.Second

// Server holds all dependencies for the HTTP API and MCP endpoints.
type Server struct {
	router           *chi.Mux
	runner           *agent.Runner
	evidenceStore    *evidence.Store
	mcpServer        http.Handler // native MCP at POST /mcp
	mcpProxy         http.Handler // optional MCP proxy at POST /mcp/proxy
	gateway          http.Handler // optional LLM API gateway at /v1/proxy/*
	tenantManager    *tenant.Manager
	webhookHandler   *trigger.WebhookHandler
	planReviewStore  *agent.PlanReviewStore
	memoryStore      *memory.Store
	policyEngine     *policy.Engine
	secretsStore     *secrets.SecretStore
	policy           *policy.Policy
	dashboardHTML    string
	apiKeys          map[string]string
	corsOrigins      []string
	policyPath       string
	startTime        time.Time
	activeRunTracker *agent.ActiveRunTracker
}

// Option configures the Server.
type Option func(*Server)

// WithMCPServer sets the native MCP handler.
func WithMCPServer(h http.Handler) Option {
	return func(s *Server) { s.mcpServer = h }
}

// WithMCPProxy sets the MCP proxy handler (optional).
func WithMCPProxy(h http.Handler) Option {
	return func(s *Server) { s.mcpProxy = h }
}

// WithTenantManager sets the tenant manager for rate limiting and budgets.
func WithTenantManager(tm *tenant.Manager) Option {
	return func(s *Server) { s.tenantManager = tm }
}

// WithPlanReviewStore sets the plan review store for EU AI Act Art. 14.
func WithPlanReviewStore(pr *agent.PlanReviewStore) Option {
	return func(s *Server) { s.planReviewStore = pr }
}

// WithMemoryStore sets the memory store (optional).
func WithMemoryStore(m *memory.Store) Option {
	return func(s *Server) { s.memoryStore = m }
}

// WithDashboard sets the embedded dashboard HTML.
func WithDashboard(html string) Option {
	return func(s *Server) { s.dashboardHTML = html }
}

// WithCORSOrigins sets allowed CORS origins (e.g. ["*"] for MVP).
func WithCORSOrigins(origins []string) Option {
	return func(s *Server) { s.corsOrigins = origins }
}

// WithActiveRunTracker sets the in-flight run tracker for status/dashboard active_runs.
func WithActiveRunTracker(tracker *agent.ActiveRunTracker) Option {
	return func(s *Server) { s.activeRunTracker = tracker }
}

// WithGateway sets the LLM API gateway handler (optional). Mounted at /v1/proxy/* with its own caller auth.
func WithGateway(h http.Handler) Option {
	return func(s *Server) { s.gateway = h }
}

// NewServer builds a Server with the required dependencies and optional Option(s).
func NewServer(
	runner *agent.Runner,
	evidenceStore *evidence.Store,
	webhookHandler *trigger.WebhookHandler,
	policyEngine *policy.Engine,
	policy *policy.Policy,
	policyPath string,
	secretsStore *secrets.SecretStore,
	apiKeys map[string]string,
	opts ...Option,
) *Server {
	s := &Server{
		router:         chi.NewRouter(),
		runner:         runner,
		evidenceStore:  evidenceStore,
		webhookHandler: webhookHandler,
		policyEngine:   policyEngine,
		policy:         policy,
		policyPath:     policyPath,
		secretsStore:   secretsStore,
		apiKeys:        apiKeys,
		corsOrigins:    []string{"*"},
		startTime:      time.Now(),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.apiKeys == nil {
		s.apiKeys = make(map[string]string)
	}
	return s
}

// Routes returns the configured http.Handler (chi router with all middleware and routes).
// Long-running routes (/v1/agents/run, /v1/chat/completions) are registered without
// the default request timeout so handler-level 30-minute timeouts take effect.
func (s *Server) Routes() http.Handler {
	r := s.router
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(otel.MiddlewareWithStatus())
	r.Use(CORSMiddleware(s.corsOrigins))

	// Unauthenticated
	r.Get("/health", s.handleHealth)
	r.Get("/v1/health", s.handleHealth)

	// Webhooks (no auth; signature validation can be added later)
	r.Post("/v1/triggers/{name}", s.webhookHandler.HandleWebhook)

	// LLM API Gateway (caller identification via API key or source IP; no Talon auth middleware)
	if s.gateway != nil {
		r.Route("/v1/proxy", func(r chi.Router) {
			r.Handle("/*", s.gateway)
		})
	}

	// Authenticated API group
	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(s.apiKeys))
		r.Use(RateLimitMiddleware(s.tenantManager))

		// Long-running: no request timeout so handler 30min deadline applies (middleware.Timeout would override)
		r.Post("/v1/agents/run", s.handleAgentRun)
		r.Post("/v1/chat/completions", s.handleChatCompletions)

		// Short routes: 60s request timeout
		r.Group(func(r chi.Router) {
			r.Use(middleware.Timeout(defaultTimeout))
			r.Get("/v1/evidence", s.handleEvidenceList)
			r.Get("/v1/evidence/timeline", s.handleEvidenceTimeline)
			r.Get("/v1/evidence/{id}", s.handleEvidenceGet)
			r.Get("/v1/evidence/{id}/verify", s.handleEvidenceVerify)
			r.Post("/v1/evidence/export", s.handleEvidenceExport)

			r.Get("/v1/status", s.handleStatus)
			r.Get("/v1/costs", s.handleCosts)
			r.Get("/v1/costs/budget", s.handleCostsBudget)

			r.Get("/v1/secrets", s.handleSecretsList)
			r.Get("/v1/secrets/audit", s.handleSecretsAudit)

			r.Get("/v1/memory", s.handleMemoryList)
			r.Get("/v1/memory/search", s.handleMemorySearch)
			r.Get("/v1/memory/{id}", s.handleMemoryGet)
			r.Get("/v1/memory/{agent_id}/review", s.handleMemoryReview)
			r.Post("/v1/memory/{agent_id}/approve", s.handleMemoryApprove)

			r.Get("/v1/triggers", s.handleTriggersList)
			r.Get("/v1/triggers/{name}/history", s.handleTriggerHistory)

			r.Get("/v1/plans/pending", s.handlePlansPending)
			r.Get("/v1/plans/{id}", s.handlePlanGet)
			r.Post("/v1/plans/{id}/approve", s.handlePlanApprove)
			r.Post("/v1/plans/{id}/reject", s.handlePlanReject)
			r.Post("/v1/plans/{id}/modify", s.handlePlanModify)

			r.Get("/v1/policies", s.handlePoliciesList)
			r.Post("/v1/policies/evaluate", s.handlePoliciesEvaluate)
		})
	})

	// MCP (authenticated by same group in plan; but MCP clients often use separate auth — we apply auth to /mcp too)
	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(s.apiKeys))
		r.Use(RateLimitMiddleware(s.tenantManager))
		if s.mcpServer != nil {
			r.Post("/mcp", s.mcpServer.ServeHTTP)
		}
		if s.mcpProxy != nil {
			r.Post("/mcp/proxy", s.mcpProxy.ServeHTTP)
		}
	})

	// Dashboard (no auth for same-origin MVP; optional to protect later)
	r.Get("/", s.handleDashboard)
	r.Get("/dashboard", s.handleDashboard)

	return r
}
