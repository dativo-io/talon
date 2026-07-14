package server

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/agent/graphadapter"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/compliance"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/metrics"
	"github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/session"
	"github.com/dativo-io/talon/internal/tenant"
	"github.com/dativo-io/talon/internal/trigger"
)

const defaultTimeout = 60 * time.Second

// Server holds all dependencies for the HTTP API and MCP endpoints.
type Server struct {
	router               *chi.Mux
	runner               *agent.Runner
	evidenceStore        *evidence.Store
	mcpServer            http.Handler // native MCP at POST /mcp
	mcpProxy             http.Handler // optional MCP proxy at POST /mcp/proxy
	gateway              http.Handler // optional LLM API gateway at /v1/proxy/*
	tenantManager        *tenant.Manager
	webhookHandler       *trigger.WebhookHandler
	planReviewStore      *agent.PlanReviewStore
	memoryStore          *memory.Store
	sessionStore         *session.Store
	policyEngine         *policy.Engine
	secretsStore         *secrets.SecretStore
	policy               *policy.Policy
	dashboardHTML        string
	gatewayDashboardHTML string
	metricsCollector     *metrics.Collector
	adminKey             string
	// agentKeys resolves presented agent keys against the CURRENT identity
	// snapshot (#289) — serve injects a registry-holder-backed resolver so a
	// reload propagates to server auth; static maps serve tests and the
	// native-only path.
	agentKeys            AgentKeyResolver
	corsOrigins          []string
	policyPath           string
	startTime            time.Time
	activeRunTracker     *agent.ActiveRunTracker
	runRegistryRef       *agent.RunRegistry
	overrideStoreRef     *agent.OverrideStore
	toolApprovalStoreRef *agent.ToolApprovalStore
	graphEventsHandler   http.Handler
	proxyQuickstart      http.Handler
	quickstartEnabled    bool
	eventsStreamMaxConn  int
	eventsReplayBacklog  int
	eventsRecentMaxLimit int
	eventsPollInterval   time.Duration
	declarationsLoader   DeclarationsLoader
	classifier           classifier.Facade
	// sovereigntyMode is the configured data-sovereignty routing mode
	// (eu_strict | eu_preferred | global). It is threaded into every
	// server-side RunRequest so the agent runner applies compliance-aware
	// routing consistently with the `talon run` CLI (#server-sovereignty).
	sovereigntyMode string
	// agentCapsLookup returns the effective daily/monthly caps for one agent,
	// computed by the shared ResolveEffectivePolicy over the identity registry
	// and injected by serve — the dashboard never re-derives caps (#266).
	agentCapsLookup func(tenantID, agentID string) (daily, monthly float64, ok bool)
	// fleetView backs GET /v1/agents/fleet (#269): ONE coherent read of the
	// active runtime generation and the reloader's accept/reject state.
	fleetView func() agentcatalog.FleetView
	// fleetCurrency is the ISO-4217 unit the attention-queue COST column and
	// budget caps are denominated in (#270), resolved once from the pricing
	// table at serve time.
	fleetCurrency string
	// fleetOrg and fleetProviders are the organization baseline and configured
	// providers the fleet endpoint resolves caps and deny-all against, BOUND to
	// the captured snapshot per request (#270 review round 3) — not a live-holder
	// lookup. Captured by value from serve (config has no reload seam yet).
	fleetOrg       gateway.OrganizationPolicy
	fleetProviders map[string]gateway.ProviderConfig
	// fleetEnforcing gates the attention queue's BLOCKED state (#270 review
	// round 2): budget exhaustion and agent-wide policy invalidity only prevent
	// new work in enforce mode (or native execution). Defaults to true — the
	// safe default is to surface BLOCKED unless serve knows the gateway is in
	// shadow/log_only.
	fleetEnforcing bool
}

// SetClassifier attaches the process-wide scanner engine. Call after
// NewServer; when set to an external engine it is used for tool-approval
// remediation instead of a per-policy regex scanner.
func (s *Server) SetClassifier(cls classifier.Facade) {
	s.classifier = cls
}

// DeclarationsLoader returns the declared compliance facts (controller
// identity, processing/system declarations) used by the auditor-document
// endpoints. Loaded per request so config edits are picked up without restart.
type DeclarationsLoader func(ctx context.Context) compliance.Declarations

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

// WithSessionStore sets the session store (optional).
func WithSessionStore(ss *session.Store) Option {
	return func(s *Server) { s.sessionStore = ss }
}

// WithActiveRunTracker sets the in-flight run tracker for status/dashboard active_runs.
func WithActiveRunTracker(tracker *agent.ActiveRunTracker) Option {
	return func(s *Server) { s.activeRunTracker = tracker }
}

// WithSovereigntyMode sets the configured data-sovereignty routing mode applied
// to every server-side agent run, so the HTTP runner path enforces the same
// compliance-aware routing as the `talon run` CLI. Empty disables it.
func WithSovereigntyMode(mode string) Option {
	return func(s *Server) { s.sovereigntyMode = mode }
}

// WithGraphEventsHandler sets the handler for external graph runtime governance events.
func WithGraphEventsHandler(pe *policy.Engine, eg *evidence.Generator, es *evidence.Store) Option {
	return func(s *Server) {
		adapter := graphadapter.NewAdapter(pe, eg, es)
		s.graphEventsHandler = graphadapter.NewHandler(adapter)
	}
}

// WithRunRegistry sets the run registry for lifecycle tracking and control endpoints.
func WithRunRegistry(rr *agent.RunRegistry) Option {
	return func(s *Server) { s.runRegistryRef = rr }
}

// WithOverrideStore sets the override store for runtime policy overrides and tenant lockdown.
func WithOverrideStore(os *agent.OverrideStore) Option {
	return func(s *Server) { s.overrideStoreRef = os }
}

// WithToolApprovalStore sets the tool approval store for pre-tool human-in-the-loop gates.
func WithToolApprovalStore(tas *agent.ToolApprovalStore) Option {
	return func(s *Server) { s.toolApprovalStoreRef = tas }
}

// WithGateway sets the LLM API gateway handler (optional). Mounted at /v1/proxy/* with its own agent-key auth.
func WithGateway(h http.Handler) Option {
	return func(s *Server) { s.gateway = h }
}

// WithProxyQuickstart sets the OpenAI-compatible host-root quickstart proxy facade.
func WithProxyQuickstart(h http.Handler) Option {
	return func(s *Server) { s.proxyQuickstart = h }
}

// WithAgentCapsLookup injects the per-agent effective-cap lookup (identity
// registry + ResolveEffectivePolicy), keeping the dashboard budget view on the
// same calculation path as enforcement (#266).
func WithAgentCapsLookup(fn func(tenantID, agentID string) (daily, monthly float64, ok bool)) Option {
	return func(s *Server) { s.agentCapsLookup = fn }
}

// WithAgentIdentities supplies the FULL key → identity projection (agent
// name, tenant, team) from the identity registry, so native handlers bind
// attribution to the authenticated agent rather than a client-asserted name
// (#266 review round 4). It replaces the tenant-only map derived from
// NewServer's tenantKeys argument. serve passes this; tests that only exercise
// tenant scoping can omit it.
func WithAgentIdentities(agentKeys map[string]requestctx.AgentIdentity) Option {
	return func(s *Server) {
		if agentKeys != nil {
			s.agentKeys = StaticAgentKeys(agentKeys)
		}
	}
}

// WithAgentKeyResolver sets a LIVE agent-key resolver (#289): serve wires a
// registry-holder-backed implementation so one reload swap (#269) propagates
// to server auth, unlike the static snapshot maps above.
func WithAgentKeyResolver(r AgentKeyResolver) Option {
	return func(s *Server) {
		if r != nil {
			s.agentKeys = r
		}
	}
}

// tenantKeysToIdentities converts a key → tenant map into a key → identity
// map with tenant-only entries (no agent name). Used when a caller supplies
// only tenant scoping; WithAgentIdentities overrides with the full identity.
func tenantKeysToIdentities(tenantKeys map[string]string) map[string]requestctx.AgentIdentity {
	out := make(map[string]requestctx.AgentIdentity, len(tenantKeys))
	for k, t := range tenantKeys {
		out[k] = requestctx.AgentIdentity{TenantID: t}
	}
	return out
}

// WithQuickstartEnabled toggles quickstart route behavior.
func WithQuickstartEnabled(enabled bool) Option {
	return func(s *Server) { s.quickstartEnabled = enabled }
}

// WithGatewayDashboard sets the embedded gateway dashboard HTML.
func WithGatewayDashboard(html string) Option {
	return func(s *Server) { s.gatewayDashboardHTML = html }
}

// WithMetricsCollector sets the metrics collector for the gateway dashboard API.
func WithMetricsCollector(c *metrics.Collector) Option {
	return func(s *Server) { s.metricsCollector = c }
}

// WithComplianceDeclarations sets the loader for declared compliance facts
// used by the /v1/compliance/* auditor-document endpoints.
func WithComplianceDeclarations(loader DeclarationsLoader) Option {
	return func(s *Server) { s.declarationsLoader = loader }
}

// WithEventStreamLimits configures SSE stream limits and polling behavior.
func WithEventStreamLimits(maxConn, replayBacklog, recentMaxLimit int, pollInterval time.Duration) Option {
	return func(s *Server) {
		if maxConn > 0 {
			s.eventsStreamMaxConn = maxConn
		}
		if replayBacklog > 0 {
			s.eventsReplayBacklog = replayBacklog
		}
		if recentMaxLimit > 0 {
			s.eventsRecentMaxLimit = recentMaxLimit
		}
		if pollInterval > 0 {
			s.eventsPollInterval = pollInterval
		}
	}
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
	adminKey string,
	tenantKeys map[string]string,
	opts ...Option,
) *Server {
	s := &Server{
		router:               chi.NewRouter(),
		runner:               runner,
		evidenceStore:        evidenceStore,
		webhookHandler:       webhookHandler,
		policyEngine:         policyEngine,
		policy:               policy,
		policyPath:           policyPath,
		secretsStore:         secretsStore,
		adminKey:             adminKey,
		agentKeys:            StaticAgentKeys(tenantKeysToIdentities(tenantKeys)),
		corsOrigins:          []string{"*"},
		startTime:            time.Now(),
		eventsStreamMaxConn:  256,
		eventsReplayBacklog:  1000,
		eventsRecentMaxLimit: 500,
		eventsPollInterval:   1 * time.Second,
		// Safe default: surface BLOCKED unless serve tells us the gateway runs in
		// shadow/log_only (WithFleetEnforcing(false)).
		fleetEnforcing: true,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.agentKeys == nil {
		s.agentKeys = StaticAgentKeys(nil)
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

	// Unauthenticated. HEAD is registered explicitly: chi's Get() answers 405
	// to HEAD, and `wget --spider` (the healthcheck in every example compose
	// stack) probes with HEAD — without this, containerized Talon reports
	// permanently unhealthy while serving fine.
	r.Get("/health", s.handleHealth)
	r.Head("/health", s.handleHealth)
	r.Get("/v1/health", s.handleHealth)
	r.Head("/v1/health", s.handleHealth)

	// Webhooks (no auth; signature validation can be added later)
	r.Post("/v1/triggers/{name}", s.webhookHandler.HandleWebhook)

	// LLM API Gateway (agent-key identification via the identity registry; no Talon auth middleware)
	if s.gateway != nil {
		r.Route("/v1/proxy", func(r chi.Router) {
			r.Handle("/*", s.gateway)
		})
	}
	// OpenAI-compatible quickstart facade (must be above tenant middleware routes).
	if s.quickstartEnabled && s.proxyQuickstart != nil {
		r.Post("/v1/chat/completions", s.proxyQuickstart.ServeHTTP)
		r.Post("/v1/responses", s.proxyQuickstart.ServeHTTP)
	}

	// Native EXECUTION routes. In a native-only deployment the agent key IS
	// the governed path — the runner applies the agent's policy. But when the
	// gateway is ALSO serving traffic, these routes run the agent's policy
	// WITHOUT gateway.organization_policy, provider constraints, or the
	// resolved effective policy — so an agent key could pick a native route
	// to bypass org governance it cannot bypass through /v1/proxy. Require
	// operator (admin) authority in that case; agent keys must use /v1/proxy
	// (#266 review round 5). The requirement is STRICT: with no admin key
	// configured these routes deny rather than falling into the dev-open rule,
	// otherwise a gateway deployment without TALON_ADMIN_KEY would expose
	// ungoverned execution to unauthenticated clients (#266 review round 6).
	// Session completion is accounting, not LLM execution, so it stays
	// agent-key in both configurations.
	execAuth := TenantKeyMiddleware(s.agentKeys, s.adminKey)
	if s.gateway != nil {
		execAuth = RequireAdminKeyMiddleware(s.adminKey)
	}
	r.Group(func(r chi.Router) {
		r.Use(execAuth)
		r.Use(RateLimitMiddleware(s.tenantManager))

		// Long-running: no request timeout so handler 30min deadline applies (middleware.Timeout would override).
		r.Post("/v1/agents/run", s.handleAgentRun)
		// Quickstart serves ONLY the host-root facade — tenant agent chat is
		// not mounted at all (#285).
		if !s.quickstartEnabled {
			r.Post("/v1/chat/completions", s.handleChatCompletions)
		}
		if s.mcpServer != nil {
			r.Post("/mcp", s.mcpServer.ServeHTTP)
		}
		if s.mcpProxy != nil {
			r.Post("/mcp/proxy", s.mcpProxy.ServeHTTP)
		}
		if s.graphEventsHandler != nil {
			r.Post("/v1/graph/events", s.graphEventsHandler.ServeHTTP)
		}
	})
	r.Group(func(r chi.Router) {
		r.Use(TenantKeyMiddleware(s.agentKeys, s.adminKey))
		r.Use(RateLimitMiddleware(s.tenantManager))
		r.Post("/v1/sessions/{id}/complete", s.handleSessionComplete)
	})

	// Tenant or admin API group (mostly read paths).
	r.Group(func(r chi.Router) {
		r.Use(TenantOrAdminMiddleware(s.agentKeys, s.adminKey))
		r.Use(RateLimitMiddleware(s.tenantManager))
		r.Use(middleware.Timeout(defaultTimeout))

		r.Get("/v1/evidence", s.handleEvidenceList)
		r.Get("/v1/evidence/timeline", s.handleEvidenceTimeline)
		r.Get("/v1/evidence/{id}", s.handleEvidenceGet)
		r.Get("/v1/evidence/{id}/trace", s.handleEvidenceTrace)
		r.Get("/v1/evidence/{id}/verify", s.handleEvidenceVerify)
		r.Post("/v1/evidence/export", s.handleEvidenceExport)
		r.Get("/api/v1/events/recent", s.handleEventsRecent)
		r.Get("/api/v1/events/stream", s.handleEventsStream)

		r.Get("/v1/status", s.handleStatus)
		r.Get("/v1/costs", s.handleCosts)
		r.Get("/v1/costs/budget", s.handleCostsBudget)
		r.Get("/v1/costs/report", s.handleCostsReport)
		r.Post("/v1/costs/export", s.handleCostsExport)

		r.Get("/v1/memory", s.handleMemoryList)
		r.Get("/v1/memory/as-of", s.handleMemoryAsOf)
		r.Get("/v1/memory/search", s.handleMemorySearch)
		r.Get("/v1/memory/{id}", s.handleMemoryGet)
		r.Get("/v1/memory/{agent_id}/review", s.handleMemoryReview)

		r.Get("/v1/triggers", s.handleTriggersList)
		r.Get("/v1/triggers/{name}/history", s.handleTriggerHistory)

		r.Get("/v1/sessions/{id}", s.handleSessionGet)
		r.Get("/v1/sessions", s.handleSessionList)

		r.Get("/v1/plans/pending", s.handlePlansPending)
		r.Get("/v1/plans/{id}", s.handlePlanGet)
	})

	// Admin-only API group.
	r.Group(func(r chi.Router) {
		r.Use(AdminKeyMiddleware(s.adminKey))
		r.Use(middleware.Timeout(defaultTimeout))

		r.Post("/v1/plans/{id}/approve", s.handlePlanApprove)
		r.Post("/v1/plans/{id}/reject", s.handlePlanReject)
		r.Post("/v1/plans/{id}/modify", s.handlePlanModify)
		r.Post("/v1/memory/{agent_id}/approve", s.handleMemoryApprove)

		r.Get("/v1/secrets", s.handleSecretsList)
		r.Get("/v1/secrets/audit", s.handleSecretsAudit)
		r.Get("/v1/policies", s.handlePoliciesList)
		r.Post("/v1/policies/evaluate", s.handlePoliciesEvaluate)

		// Operational control plane: run lifecycle management
		r.Get("/v1/runs", s.handleRunsList)
		r.Get("/v1/runs/{id}", s.handleRunGet)
		r.Post("/v1/runs/{id}/kill", s.handleRunKill)
		r.Post("/v1/runs/kill-all", s.handleRunKillAll)
		r.Post("/v1/runs/{id}/pause", s.handleRunPause)
		r.Post("/v1/runs/{id}/resume", s.handleRunResume)

		// Operational overrides: tenant lockdown, tool disable, policy tightening
		r.Get("/v1/overrides", s.handleOverridesList)
		r.Get("/v1/overrides/{tenant_id}", s.handleOverrideGet)
		r.Post("/v1/overrides/{tenant_id}/lockdown", s.handleTenantLockdown)
		r.Delete("/v1/overrides/{tenant_id}/lockdown", s.handleTenantUnlock)
		r.Post("/v1/overrides/{tenant_id}/tools/disable", s.handleToolsDisable)
		r.Post("/v1/overrides/{tenant_id}/tools/enable", s.handleToolsEnable)
		r.Post("/v1/overrides/{tenant_id}/policy", s.handlePolicyOverride)
		r.Delete("/v1/overrides/{tenant_id}", s.handleOverrideClear)

		// Tool approval gates: list pending, get, approve/deny
		r.Get("/v1/tool-approvals", s.handleToolApprovalsList)
		r.Get("/v1/tool-approvals/{id}", s.handleToolApprovalGet)
		r.Post("/v1/tool-approvals/{id}/decide", s.handleToolApprovalDecide)

		// Fleet runtime state (#269): the running server is the operational
		// source of truth — generation, membership, reload accept/reject.
		r.Get("/v1/agents/fleet", s.handleAgentsFleet)

		r.Get("/v1/dashboard/tenants-summary", s.handleTenantsSummary)
		r.Get("/v1/dashboard/agent-health", s.handleAgentHealth)
		r.Get("/v1/dashboard/drift-signals", s.handleDriftSignals)
		r.Get("/v1/dashboard/denials-by-reason", s.handleDenialsByReason)
		r.Get("/v1/dashboard/governance-alerts", s.handleGovernanceAlerts)
		r.Get("/v1/dashboard/audit-pack", s.handleAuditPack)
		r.Get("/v1/dashboard/review-history", s.handleReviewHistory)

		// CoPaw dashboard: stats and alerts for CoPaw-tagged gateway agents.
		r.Get("/v1/copaw/stats", s.handleCoPawStats)
		r.Get("/v1/copaw/alerts", s.handleCoPawAlerts)

		// Compliance: framework coverage and one-click auditor exports
		// (RoPA, Annex IV, framework report) around internal/compliance.
		r.Get("/v1/compliance/coverage", s.handleComplianceCoverage)
		r.Get("/v1/compliance/ropa", s.handleComplianceRoPA)
		r.Get("/v1/compliance/annex-iv", s.handleComplianceAnnexIV)
		r.Get("/v1/compliance/report", s.handleComplianceReport)
	})

	// Dashboard (no auth for same-origin MVP; optional to protect later).
	// HEAD supported so curl -I and health checks get 200 + Content-Type without body.
	r.Get("/", s.handleDashboard)
	r.Get("/dashboard", s.handleDashboard)
	r.Head("/", s.handleDashboard)
	r.Head("/dashboard", s.handleDashboard)

	// Gateway dashboard and metrics.
	if s.metricsCollector != nil && s.gatewayDashboardHTML != "" {
		r.Group(func(r chi.Router) {
			r.Use(AdminKeyMiddleware(s.adminKey))
			r.Get("/gateway/dashboard", s.handleGatewayDashboard)
			r.Get("/api/v1/metrics", s.handleMetricsJSON)
			r.Get("/api/v1/metrics/stream", s.handleMetricsStream)
		})
	}

	return r
}
