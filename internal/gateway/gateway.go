package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/cache"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/failover"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/metrics"
	"github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/session"
)

// PolicyEvaluator evaluates gateway-specific policy (model allowlist, cost, data tier).
// Required: NewGateway rejects a nil evaluator (#442).
//
//revive:disable-next-line:exported
type GatewayPolicyEvaluator interface {
	EvaluateGateway(ctx context.Context, input map[string]interface{}) (allowed bool, reasons []string, err error)
}

// Usage is the token breakdown a CostEstimator prices. Input excludes cache
// tokens; CacheRead/CacheWrite are prompt-cache read/write counts.
type Usage struct {
	Input, CacheRead, CacheWrite, Output int
}

// CostResult is the outcome of a cost estimate. PricingBasis records HOW the
// number was derived so a signed evidence cost is never silently a fallback.
type CostResult struct {
	Amount       float64
	PricingKnown bool
	PricingBasis string // "table" | "cache_fallback_input_rate" | "default_estimate"
}

// Cost-basis constants recorded in evidence.
const (
	PricingBasisTable        = "table"
	PricingBasisCacheFalling = "cache_fallback_input_rate"
	PricingBasisDefault      = "default_estimate"
)

// CostEstimator returns the estimated cost for a request, keyed on the routed
// provider and model plus a full token breakdown (cache-aware). Provider is
// threaded through so the routed provider's pricing is used, not a
// max-across-providers guess.
type CostEstimator func(provider, model string, usage Usage) CostResult

// MetricsRecorder receives gateway events for dashboard aggregation.
// Implemented by *metrics.Collector via an adapter to avoid import cycles.
type MetricsRecorder interface {
	RecordGatewayEvent(event interface{})
}

type gatewayContextKey string

const (
	gatewayAgentReasoningKey gatewayContextKey = "agent_reasoning"
	gatewaySessionIDKey      gatewayContextKey = "session_id"
	gatewayRetryAttemptKey   gatewayContextKey = "retry_attempt"
	gatewayStageKey          gatewayContextKey = "stage"
	gatewayCandidateIndexKey gatewayContextKey = "candidate_index"
	gatewayUpstreamAuthMode  gatewayContextKey = "upstream_auth_mode"
	gatewayUpstreamKeySource gatewayContextKey = "upstream_key_source"
	gatewayUpstreamKeyFP     gatewayContextKey = "upstream_key_fingerprint"
	gatewayOrchestrationKey  gatewayContextKey = "orchestration"
	gatewaySessionSourceKey  gatewayContextKey = "session_source"
)

// Gateway is the LLM API gateway handler.
type Gateway struct {
	config *GatewayConfig
	// registry yields the CURRENT identity registry per request (#289/#267):
	// in production it is the view over the ONE runtime holder, so a reload
	// swap propagates here without reconstructing the gateway and can never
	// split a request across generations.
	registry      RegistrySource
	classifier    classifier.Facade
	evidenceStore *evidence.Store
	secretsStore  *secrets.SecretStore
	policy        GatewayPolicyEvaluator
	costEstimate  CostEstimator
	timeouts      ParsedTimeouts
	client        *http.Client
	rateLimiter   *RateLimiter
	attExtractor  *attachment.Extractor
	attInjScanner *attachment.Scanner
	// Optional semantic cache (when nil or disabled, cache is skipped)
	cacheStore      *cache.Store
	cacheEmbedder   *cache.BM25
	cacheScrubber   *cache.PIIScrubber
	cachePolicy     *cache.Evaluator
	cacheConfig     *gatewayCacheConfig
	metricsRecorder MetricsRecorder
	sessionStore    *session.Store
	// pricingCurrency is the ISO-4217 code of the pricing table backing
	// costEstimate; stamped into evidence so records stay self-describing
	// if the operator later changes the table (#216).
	pricingCurrency string
	// budgetEventFired is the in-memory half of the once-per-crossing budget
	// contract (#144): keys (tenant|agent|period|threshold|window) whose signed
	// budget_threshold record exists. Claimed before I/O, released on write
	// failure, rebuilt lazily from the evidence store after a restart.
	budgetEventMu    sync.Mutex
	budgetEventFired map[string]bool
}

type gatewayCacheConfig struct {
	Enabled             bool
	DefaultTTL          int
	TTLByTier           map[string]int
	SimilarityThreshold float64
	MaxEntriesPerTenant int
}

// canonicalTenantIDForCache returns the tenant ID for cache key scope from
// config-derived values — the CURRENT registry snapshot (#289), so a reload
// re-scopes cache keys without gateway reconstruction. Used so the value
// passed to cache.DeriveEntryKey originates from config (not from the
// request path), satisfying static analysis.
func (g *Gateway) canonicalTenantIDForCache(reg *IdentityRegistry, fromAgent string) string {
	if fromAgent == quickstartTenantID {
		return quickstartTenantID
	}
	if canonical, ok := reg.CanonicalTenantID(fromAgent); ok {
		return canonical
	}
	return fromAgent
}

// SetMetricsRecorder attaches a dashboard metrics collector. Call after NewGateway.
func (g *Gateway) SetMetricsRecorder(mr MetricsRecorder) {
	g.metricsRecorder = mr
}

// SetSessionStore attaches a session store for lifecycle tracking. Call after NewGateway.
func (g *Gateway) SetSessionStore(ss *session.Store) {
	g.sessionStore = ss
}

// SetPricingCurrency records the ISO-4217 code of the pricing table backing
// the cost estimator so evidence records carry their cost unit (#216). Call
// after NewGateway.
func (g *Gateway) SetPricingCurrency(code string) {
	g.pricingCurrency = code
}

// SetCache wires the optional semantic cache into the gateway. Call after NewGateway when cache is enabled.
func (g *Gateway) SetCache(store *cache.Store, embedder *cache.BM25, scrubber *cache.PIIScrubber, policy *cache.Evaluator, enabled bool, defaultTTL int, ttlByTier map[string]int, similarityThreshold float64, maxEntriesPerTenant int) {
	if store == nil || embedder == nil || policy == nil || !enabled {
		return
	}
	g.cacheStore = store
	g.cacheEmbedder = embedder
	g.cacheScrubber = scrubber
	g.cachePolicy = policy
	g.cacheConfig = &gatewayCacheConfig{
		Enabled:             enabled,
		DefaultTTL:          defaultTTL,
		TTLByTier:           ttlByTier,
		SimilarityThreshold: similarityThreshold,
		MaxEntriesPerTenant: maxEntriesPerTenant,
	}
}

// NewGateway creates a new Gateway. The registry holder is the shared atomic
// snapshot holder (#289): its Current() registry is the immutable key → agent
// identity set built by BuildIdentityRegistry, and a reload (#269) swaps it
// for every consumer at once. A holder over a nil/empty registry means no
// agent can authenticate (quickstart mode injects its synthetic identity via
// request context instead).
func NewGateway(
	config *GatewayConfig,
	registry RegistrySource,
	classifier classifier.Facade,
	evidenceStore *evidence.Store,
	secretsStore *secrets.SecretStore,
	policy GatewayPolicyEvaluator,
	costEstimate CostEstimator,
) (*Gateway, error) {
	if costEstimate == nil {
		costEstimate = defaultCostEstimator
	}
	// The policy evaluator is REQUIRED (#442): a governed dispatch path without
	// policy evaluation was the removed log_only posture. Test fakes that never
	// dispatch must still supply an evaluator.
	if policy == nil {
		return nil, fmt.Errorf("gateway policy evaluator is required: active policy is always enforced (#442)")
	}
	timeouts, err := config.ParseTimeouts()
	if err != nil {
		return nil, err
	}
	client := HTTPClientForGateway(timeouts, config.UpstreamTransport)
	rl := NewRateLimiter(
		config.RateLimits.GlobalRequestsPerMin,
		config.RateLimits.PerAgentRequestsPerMin,
	)

	maxMB := DefaultAttachmentMaxFileSizeMB
	if p := config.OrganizationPolicy.Defaults.AttachmentPolicy; p != nil && p.MaxFileSizeMB > 0 {
		maxMB = p.MaxFileSizeMB
	}
	ext := attachment.NewExtractor(maxMB)
	injScan, err := attachment.NewScanner()
	if err != nil {
		return nil, fmt.Errorf("creating attachment injection scanner: %w", err)
	}

	if registry == nil {
		// Normalize so every read goes through one nil-safe holder — a
		// keyless gateway (quickstart) is a holder over a nil registry.
		registry = NewRegistryHolder(nil)
	}
	return &Gateway{
		config:        config,
		registry:      registry,
		classifier:    classifier,
		evidenceStore: evidenceStore,
		secretsStore:  secretsStore,
		policy:        policy,
		costEstimate:  costEstimate,
		timeouts:      timeouts,
		client:        client,
		rateLimiter:   rl,
		attExtractor:  ext,
		attInjScanner: injScan,
	}, nil
}

// ServeHTTP implements the 10-step gateway pipeline.
//
//nolint:gocyclo // pipeline steps are sequential; branching is required
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()
	correlationID := r.Header.Get("X-Correlation-ID")
	if correlationID == "" {
		correlationID = "gw_" + uuid.New().String()[:12]
	}
	sessionID := r.Header.Get("X-Talon-Session-ID")
	if sessionID == "" {
		sessionID = "sess_" + correlationID
	}
	w.Header().Set("X-Talon-Session-ID", sessionID)
	ctx = context.WithValue(ctx, gatewayAgentReasoningKey, r.Header.Get("X-Talon-Reasoning"))
	ctx = context.WithValue(ctx, gatewaySessionIDKey, sessionID)
	ctx = context.WithValue(ctx, gatewayRetryAttemptKey, r.Header.Get("X-Talon-Retry-Attempt"))
	// Only the known orchestration stages are accepted; any other value is
	// dropped so unbounded junk never accumulates session_stage_counts (#194).
	ctx = context.WithValue(ctx, gatewayStageKey, normalizeStage(r.Header.Get("X-Talon-Stage")))
	if ciStr := r.Header.Get("X-Talon-Candidate-Index"); ciStr != "" {
		if ci, err := strconv.Atoi(ciStr); err == nil {
			ctx = context.WithValue(ctx, gatewayCandidateIndexKey, ci)
		}
	}

	// Step 1: Route
	route, err := g.config.RouteRequest(r)
	if err != nil {
		RecordGatewayRequest(ctx, "unknown", "", "openai", "error")
		RecordGatewayError(ctx, "route_error")
		log.Warn().Err(err).Str("path", r.URL.Path).Msg("gateway_route_failed")
		WriteProviderError(w, "openai", http.StatusBadRequest, err.Error())
		return
	}
	// Wire format (api_family) of the routed provider: drives request
	// parsing, PII redaction, tool filtering, attachment extraction, and
	// provider-native error shape. Governance parsing must never depend on
	// the provider map key -- an aliased Anthropic-compatible endpoint gets
	// Anthropic parsing, not the OpenAI default.
	wire := g.config.providerAPIFamily(route.Provider)

	// count_tokens is governed like any request (the body egresses) but is
	// free at the provider and returns a count, not a completion: cost and
	// budget input must be zero or signed evidence records fabricated spend.
	isCountTokens := wire == "anthropic" && strings.HasSuffix(route.Path, "/count_tokens")

	// Step 2: Identify — a presented key resolves to exactly one agent or the
	// request is rejected; the quickstart synthetic identity (injected via
	// context by the in-process facade) is the only exception (#266).
	// ONE registry generation is captured here and used through the whole
	// request (#267): a reload swap mid-flight never splits this request
	// across two generations (auth from gen A, cache scope from gen B).
	requestRegistry := g.registry.Current()
	agent, err := resolveIdentityFrom(requestRegistry, r)
	if err != nil {
		RecordGatewayError(ctx, "auth")
		RecordGatewayRequest(ctx, "unknown", "", route.Provider, "error")
		WriteProviderError(w, wire, http.StatusUnauthorized, "invalid_agent_key: Invalid or missing agent key")
		return
	}

	// Operational kill switch (#268): enabled: false denies NEW work. Like
	// authentication and eu_strict, this is a hard PLATFORM boundary — an
	// explicit operator decision. The key
	// resolved first (resolve-then-deny) so the denial is attributed to the
	// agent in signed evidence; in-flight requests already past this gate
	// finish untouched. The config path stays in logs/evidence, never the
	// client body.
	if !agent.Enabled {
		RecordGatewayError(ctx, "agent_disabled")
		log.Warn().Str("agent", agent.Name).Str("config_path", agent.ConfigPath).Msg("gateway_agent_disabled_denied")
		durationMS := time.Since(start).Milliseconds()
		WriteProviderError(w, wire, http.StatusForbidden, "agent_disabled: agent \""+agent.Name+"\" is disabled by its Talon agent config (enabled: false) — new work is denied; ask your Talon operator to re-enable it")
		persisted, err := g.recordEvidence(ctx, correlationID, agent, route.Provider, "", start, "", &classifier.Classification{}, nil, 0, durationMS, "", false, []string{"agent disabled (enabled: false in agent config)"}, false, nil, nil, nil, false, "", 0, 0, false, 0, 0, 0)
		if err != nil {
			g.handleEvidenceWriteFailure(ctx, err)
			return
		}
		g.emitMetrics(ctx, agent, route.Provider, "", nil, nil, nil, 0, durationMS, false, true, "", false, 0, 0, 0, persisted)
		return
	}

	// Effective policy for this request: organization baseline → the agent's
	// one override → the routed provider's destination constraints. Computed
	// once here; failover candidates recompute per candidate provider through
	// buildPolicyInputForRequest (same function, no drift).
	prov, _ := g.config.Provider(route.Provider)
	eff := ResolveEffectivePolicy(g.config.OrganizationPolicy, prov, agent.Override)
	if span := trace.SpanFromContext(ctx); span.IsRecording() && agent.HasTag("copaw") {
		span.SetAttributes(
			attribute.String("copaw.agent", agent.Name),
			attribute.String("copaw.channel", "gateway"),
		)
	}

	// Orchestration metadata (#194): ingest client-asserted session/subagent
	// identity from the neutral X-Talon-* headers or a vendor adapter (Claude
	// Code, Codex). Evidence-only; never a policy input. A hygiene violation
	// (oversized/invalid header) is rejected here so it never reaches evidence.
	orch, resolvedSessionID, sessionSource, orchErr := resolveOrchestration(r, agent.AcceptsClientMetadata(), sessionID)
	if orchErr != nil {
		RecordGatewayError(ctx, "orchestration_header_invalid")
		RecordGatewayRequest(ctx, "unknown", "", route.Provider, "error")
		WriteProviderError(w, wire, http.StatusBadRequest, "Invalid orchestration header: "+orchErr.Error())
		return
	}
	if resolvedSessionID != sessionID {
		// A client-asserted session id (generic or vendor) overrides the
		// synthetic one for the evidence session spine and the echoed header.
		sessionID = resolvedSessionID
		ctx = context.WithValue(ctx, gatewaySessionIDKey, sessionID)
		w.Header().Set("X-Talon-Session-ID", sessionID)
	}
	// Session source gates all session-store state (#198): only asserted
	// sessions may read or create session rows; synthetic ids are evidence-only.
	ctx = context.WithValue(ctx, gatewaySessionSourceKey, sessionSource)
	if orch != nil {
		ctx = context.WithValue(ctx, gatewayOrchestrationKey, orch)
	}

	// Rate limit check (after agent identification, before any work).
	if g.rateLimiter != nil && !g.rateLimiter.Allow(agent.Name) {
		log.Warn().Str("agent", agent.Name).Msg("gateway_rate_limited")
		durationMS := time.Since(start).Milliseconds()
		WriteProviderError(w, wire, http.StatusTooManyRequests, "rate_limited: Rate limit exceeded")
		persisted, err := g.recordEvidence(ctx, correlationID, agent, route.Provider, "", start, "", &classifier.Classification{}, nil, 0, durationMS, "", false, []string{"rate limit exceeded"}, false, nil, nil, nil, false, "", 0, 0, false, 0, 0, 0)
		if err != nil {
			g.handleEvidenceWriteFailure(ctx, err)
			return
		}
		g.emitMetrics(ctx, agent, route.Provider, "", nil, nil, nil, 0, durationMS, false, true, "", false, 0, 0, 0, persisted)
		return
	}

	// Only POST
	if r.Method != http.MethodPost {
		RecordGatewayRequest(ctx, agent.Name, "", route.Provider, "error")
		RecordGatewayError(ctx, "invalid_method")
		WriteProviderError(w, wire, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		RecordGatewayRequest(ctx, agent.Name, "", route.Provider, "error")
		RecordGatewayError(ctx, "read_body")
		WriteProviderError(w, wire, http.StatusBadRequest, "Failed to read request body")
		return
	}
	_ = r.Body.Close()

	// Steps 3–7: the shared pre-dispatch decision (extract, attachments,
	// PII, provider/sovereignty eligibility, budget/session admission,
	// compiled policy, tool governance, redaction). ONE implementation for
	// this HTTP path and the delegated external-runtime path (#432/#482).
	outcome := g.decidePreDispatch(ctx, decisionInput{
		Wire: wire, Provider: route.Provider, Agent: agent, Eff: eff, Body: body,
		SessionID: sessionID, SessionSource: sessionSource, IsCountTokens: isCountTokens, CorrelationID: correlationID,
	})
	ctx = outcome.Ctx
	if outcome.SessReservation != nil {
		// The deferred release covers every non-settling exit (deny, tool
		// block, upstream failure, panic); a successful settle in
		// trackSessionUsage consumes the reservation first, making it a no-op.
		defer g.releaseSessionReservation(outcome.SessReservation)
	}
	if outcome.Deny != nil {
		g.writeDeny(ctx, w, wire, route, agent, start, correlationID, outcome.Deny)
		return
	}
	dec := outcome.Allow
	extracted, classification, tier := dec.Extracted, dec.Classification, dec.Tier
	attSummary, toolContentScan, toolResult := dec.AttSummary, dec.ToolContentScan, dec.ToolResult
	forwardBody, inputPIIRedacted, piiAction := dec.ForwardBody, dec.InputPIIRedacted, dec.PIIAction
	estimatedCost, estTokensIn, estTokensOut := dec.EstimatedCost, dec.EstTokensIn, dec.EstTokensOut
	dailyCost, monthlyCost := dec.DailyCost, dec.MonthlyCost
	sessionBudgetUnavailable, sessView, retryS := dec.SessionBudgetUnavailable, dec.SessView, dec.RetryS
	sessReservation := outcome.SessReservation

	// Step 7b: Apply the provider's Responses API store mode. Default is
	// "preserve" — an explicit client store:false is a data-retention decision
	// the gateway must not silently reverse (#213). Clients that reference
	// previous_response_id across turns (e.g. OpenClaw) opt into
	// force_if_absent; force_true records any override of explicit client
	// intent in signed evidence.
	responsesStoreOverridden := false
	if wire == "openai" && isResponsesAPIPath(route.Path) {
		forwardBody, responsesStoreOverridden = applyResponsesStoreMode(forwardBody, g.config.Providers[route.Provider].ResponsesStoreMode)
	}

	// Step 7c: Inject stream_options.include_usage on OpenAI chat-completions
	// streaming requests so the upstream emits a final usage chunk — otherwise
	// streamed chat cost is estimate-only (#196). Config-gated per provider;
	// default on. Never touches Responses API (usage rides response.completed).
	if wire == "openai" && g.config.Providers[route.Provider].InjectsStreamUsage() &&
		!isResponsesAPIPath(route.Path) && isChatCompletionsPath(route.Path) {
		forwardBody = ensureStreamUsage(forwardBody)
	}

	// Step 8: Reroute (same-provider model override) — MVP: no model change, just forward

	// Step 8b: Semantic cache lookup (skip for tool calls and when disabled)
	var cacheAllowLookup, cacheAllowStore bool
	if g.cacheStore != nil && g.cacheConfig != nil && g.cacheConfig.Enabled && g.cachePolicy != nil && g.cacheEmbedder != nil && len(extracted.ToolNames) == 0 {
		dataTierStr := cache.TierLabel(tier)
		piiSev := "none"
		if classification.HasPII {
			if tier == 2 {
				piiSev = "high"
			} else {
				piiSev = "low"
			}
		}
		cin := &cache.PolicyInput{
			TenantID: agent.TenantID, DataTier: dataTierStr, PIIDetected: classification.HasPII,
			PIISeverity: piiSev, Model: extracted.Model, RequestType: "completion", CacheEnabled: true,
		}
		if cres, err := g.cachePolicy.Evaluate(ctx, cin); err == nil && cres != nil {
			cacheAllowLookup = cres.AllowLookup
			cacheAllowStore = cres.AllowStore
		}
		if cacheAllowLookup && extracted.Text != "" {
			queryBlob, err := g.cacheEmbedder.Embed(extracted.Text)
			if err == nil {
				threshold := g.cacheConfig.SimilarityThreshold
				if threshold <= 0 {
					threshold = 0.92
				}
				maxCand := 1000
				if g.cacheConfig.MaxEntriesPerTenant > 0 && g.cacheConfig.MaxEntriesPerTenant < maxCand {
					maxCand = g.cacheConfig.MaxEntriesPerTenant
				}
				// Scope the lookup to this exact AI use case: agent, model,
				// provider, effective policy, and data tier. An entry produced
				// under any different scope (e.g. a failover model, a changed
				// policy) has a different scope_key and cannot be returned, so
				// a hit can never falsify provenance (#266 review round 5).
				lookupScopeKey := cache.ScopeKey(agent.Name, extracted.Model, route.Provider, g.policyDigests(agent, route.Provider).Effective, dataTierStr)
				lookupResult, err := g.cacheStore.Lookup(ctx, agent.TenantID, lookupScopeKey, queryBlob, threshold, maxCand, g.cacheEmbedder.SimilarityFunc())
				if err == nil && lookupResult != nil {
					hit := lookupResult.Entry
					_ = g.cacheStore.IncrementHitCount(ctx, hit.ID)
					// Evidence for a cache hit describes the SOURCE entry that
					// actually produced the response — its model and provider,
					// not the current request's — and points back to the source
					// generation's evidence via cache_source_correlation_id.
					costSaved := g.costEstimate(hit.Provider, hit.Model, Usage{Input: 300, Output: 300}).Amount
					durationMS := time.Since(start).Milliseconds()
					persisted, err := g.recordEvidence(ctx, correlationID, agent, hit.Provider, hit.Model, start, extracted.Text, classification, nil, 0, durationMS, "", true, nil, inputPIIRedacted, nil, attSummary, toolResult, true, hit.ID, lookupResult.Similarity, costSaved, false, 0, 0, estimatedCost, func(p *RecordGatewayEvidenceParams) {
						p.CacheSourceCorrelationID = hit.SourceCorrelationID
					})
					if err != nil {
						g.handleEvidenceWriteFailure(ctx, err)
						return
					}
					g.emitMetrics(ctx, agent, hit.Provider, hit.Model, classification, toolResult, nil, 0, durationMS, false, false, piiAction, true, costSaved, 0, 0, persisted)
					writeCachedCompletion(w, wire, hit.Model, hit.ResponseText)
					return
				}
			}
		}
	}

	// Step 9: Forward — get provider key and proxy
	originalAuthorization := r.Header.Get("Authorization")
	headers := make(map[string]string)
	for k, v := range r.Header {
		switch k {
		case "Authorization", "X-Api-Key", "X-Request-Id":
			continue
		case "Accept-Encoding":
			// Never forward Accept-Encoding: Go's http.Transport adds it
			// automatically and transparently decompresses. If we forward
			// the client's value, Go treats compression as user-managed and
			// hands us raw gzip bytes, which causes binary garbage in
			// error responses (and breaks PII scanning on success responses).
			continue
		case "Content-Length":
			// Stale after request-body modifications (PII redaction); let
			// the HTTP stack recalculate from ForwardParams.Body.
			continue
		}
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	if g.config.providerAPIFamily(route.Provider) == "anthropic" {
		if v := r.Header.Get("anthropic-version"); v != "" {
			headers["anthropic-version"] = v
		} else {
			headers["anthropic-version"] = "2023-06-01"
		}
	}
	upstreamAuthMode := strings.TrimSpace(prov.UpstreamAuthMode)
	if upstreamAuthMode == "" {
		upstreamAuthMode = DefaultUpstreamAuthMode
	}
	switch upstreamAuthMode {
	case "client_bearer":
		clientKey := ""
		if strings.HasPrefix(originalAuthorization, "Bearer ") {
			clientKey = strings.TrimSpace(strings.TrimPrefix(originalAuthorization, "Bearer "))
		}
		source := "client"
		if clientKey == "" {
			clientKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
			source = "env"
		}
		if clientKey == "" {
			RecordGatewayError(ctx, "missing_upstream_key")
			RecordGatewayRequest(ctx, agent.Name, extracted.Model, route.Provider, "error")
			WriteProviderError(w, wire, http.StatusUnauthorized,
				"no upstream credential: set OPENAI_API_KEY or send Authorization: Bearer ...")
			return
		}
		headers["Authorization"] = "Bearer " + clientKey
		ctx = context.WithValue(ctx, gatewayUpstreamAuthMode, upstreamAuthMode)
		ctx = context.WithValue(ctx, gatewayUpstreamKeySource, source)
		ctx = context.WithValue(ctx, gatewayUpstreamKeyFP, fingerprintKey(clientKey))
	default:
		if prov.SecretName != "" {
			secret, err := g.secretsStore.Get(ctx, prov.SecretName, agent.TenantID, agent.Name)
			if err != nil {
				durationMS := time.Since(start).Milliseconds()
				log.Warn().Err(err).Str("secret", prov.SecretName).Msg("gateway_secret_get_failed")
				WriteProviderError(w, wire, http.StatusInternalServerError, "Service configuration error")
				persisted, err := g.recordEvidence(ctx, correlationID, agent, route.Provider, extracted.Model, start, extracted.Text, classification, nil, 0, durationMS, "", false, []string{"secret retrieval error"}, false, nil, attSummary, toolResult, false, "", 0, 0, false, 0, 0, estimatedCost)
				if err != nil {
					g.handleEvidenceWriteFailure(ctx, err)
					return
				}
				g.emitMetrics(ctx, agent, route.Provider, extracted.Model, classification, toolResult, nil, 0, durationMS, true, true, piiAction, false, 0, 0, 0, persisted)
				return
			}
			if g.config.providerAPIFamily(route.Provider) == "anthropic" {
				headers["x-api-key"] = string(secret.Value)
			} else {
				headers["Authorization"] = "Bearer " + string(secret.Value)
			}
		}
		ctx = context.WithValue(ctx, gatewayUpstreamAuthMode, upstreamAuthMode)
	}

	// Response-side PII action comes straight from the effective policy. The
	// four actions have different delivery semantics (#476):
	//
	//   allow   no response scan; streams pass straight through
	//   warn    observation only: a stream is delivered as it arrives and
	//           scanned after it terminates (post-delivery observation); a
	//           non-streaming body is scanned before the write but never
	//           altered
	//   redact  preventive: the response is held until the verdict and
	//           rewritten — a stream is buffered before release
	//   block   preventive: the response is held and withheld on PII — a
	//           stream is buffered before the decision
	//
	// Only the preventive actions may delay or change what the client gets.
	responsePIIAction := eff.ResponsePIIAction
	isStreaming := isStreamingRequest(forwardBody)

	var tokenUsage TokenUsage
	var responsePII *ResponsePIIScanResult
	needsResponseScan := responsePIIAction != "allow" && responsePIIAction != ""
	observeStream := isStreaming && responsePIIAction == "warn"
	preventiveStream := isStreaming && (responsePIIAction == "redact" || responsePIIAction == "block")
	var forwardErr error
	cacheStored := false

	var streamingMetrics StreamingMetrics
	streamFlavor := streamFlavorChat
	switch {
	case wire == "anthropic":
		streamFlavor = streamFlavorAnthropic
	case isResponsesAPIPath(route.Path):
		streamFlavor = streamFlavorResponses
	}
	fwdParams := ForwardParams{
		Context:          ctx,
		Client:           g.client,
		UpstreamURL:      route.UpstreamURL,
		Method:           r.Method,
		Body:             forwardBody,
		Headers:          headers,
		Timeouts:         g.timeouts,
		TokenUsage:       &tokenUsage,
		StreamingMetrics: &streamingMetrics,
		StreamFlavor:     streamFlavor,
	}

	// Error-driven provider failover (issue #138): the primary attempt plus
	// the provider's ordered fallback chain, sovereignty-filtered. Failed
	// attempts are recorded as separate signed evidence facts, each with its
	// own data-flow section (the prompt did egress to the failed provider).
	recordAttempt := func(aCtx context.Context, rec failoverAttemptRecord) string {
		attemptFlow := g.buildDataFlow(dataFlowInputs{
			CorrelationID:    correlationID,
			TenantID:         agent.TenantID,
			AgentName:        agent.Name,
			Provider:         rec.Provider,
			Model:            rec.Model,
			Allowed:          true,
			InputPIIRedacted: inputPIIRedacted,
			InputText:        extracted.Text,
			Classification:   classification,
		})
		return g.recordFailoverAttemptEvidence(aCtx, correlationID, agent, g.config.EffectiveSovereigntyMode, tier, rec, attemptFlow)
	}
	// Fallback candidates must pass the same gates the primary passed:
	// provider allowlist, tool policy, the full gateway policy re-evaluated
	// for the candidate, and the sovereignty filter inside the failover
	// pipeline (under eu_strict Talon never dispatches outside EU/LOCAL).
	checkCandidate := func(cCtx context.Context, candProvider, candModel string) (failover.FilterResult, []byte) {
		candProv, _ := g.config.Provider(candProvider)
		candEff := ResolveEffectivePolicy(g.config.OrganizationPolicy, candProv, agent.Override)
		if denySrc := candEff.ProviderDenySource(candProvider); denySrc != "" {
			// The filter names the layer that denied (#279 review):
			// organization_provider_allowlist or agent_provider_allowlist.
			return failover.FilterResult{Filter: denySrc, Reason: fmt.Sprintf("agent %s not allowed for provider %s (%s)", agent.Name, candProvider, denySrc)}, nil
		}
		var candBody []byte
		// Provider-level tool governance of the TARGET provider: a fallback
		// must not deliver tools the target's policy forbids. The body was
		// filtered against the primary's tool policy only. When the target
		// action is `filter`, strip the forbidden tools and PROCEED (matching
		// the primary path); only `block` skips the candidate (#266 review r4).
		if len(extracted.ToolNames) > 0 {
			if hasToolGovernance(&candEff) {
				forwarded := extracted.ToolNames
				if toolResult != nil {
					forwarded = toolResult.Kept
				}
				if tr := evaluateToolPolicyFor(forwarded, &candEff); len(tr.Removed) > 0 {
					switch candEff.ToolPolicyAction {
					case "block":
						return failover.FilterResult{Filter: "tool_policy", Reason: fmt.Sprintf("target provider %s blocks tools %v", candProvider, tr.Removed)}, nil
					default:
						// filter: re-filter the body for this candidate's wire
						// format and dispatch, rather than exhausting the chain.
						candWire := g.config.providerAPIFamily(candProvider)
						filtered, filterErr := FilterRequestBodyTools(candWire, forwardBody, tr.Kept)
						if filterErr != nil {
							return failover.FilterResult{Filter: "tool_policy", Reason: fmt.Sprintf("target provider %s tool re-filter failed: %v", candProvider, filterErr)}, nil
						}
						candBody = filtered
					}
				}
			}
		}
		// Full gateway policy with the CANDIDATE's provider, model,
		// recomputed cost estimate, and destination region — built by the
		// same function as the primary's input (session context included).
		{
			candEstimate := g.costEstimate(candProvider, candModel, Usage{Input: estTokensIn, Output: estTokensOut}).Amount
			candInput, _ := g.buildPolicyInputForRequest(cCtx, agent, candProvider, candModel, tier, candEstimate, dailyCost, monthlyCost, sessView)
			allowed, reasons, policyErr := g.policy.EvaluateGateway(cCtx, candInput)
			switch {
			case policyErr != nil:
				return failover.FilterResult{Filter: "gateway_policy", Reason: "policy evaluation error: " + policyErr.Error()}, nil
			case !allowed:
				return failover.FilterResult{Filter: "gateway_policy", Reason: preferredDenyReason(reasons)}, nil
			}
		}
		return failover.FilterResult{Allowed: true}, candBody
	}
	var failoverOut *failoverOutcome

	switch {
	case needsResponseScan && !isStreaming:
		// Non-streaming: capture response, scan, then write
		capture := &responseCapture{ResponseWriter: w}
		failoverOut, forwardErr = g.forwardWithFailover(ctx, capture, fwdParams, route, agent, extracted.Model, originalAuthorization, retryS, recordAttempt, checkCandidate)
		if forwardErr == nil {
			scannedBody, scanResult := scanResponseForPII(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), wire, capture.body.Bytes(), responsePIIAction, g.classifier)
			responsePII = scanResult
			status := capture.statusCode
			if scanResult != nil && scanResult.Blocked {
				// A blocked response must not masquerade as the upstream 200:
				// clients and monitors need to see the denial.
				w.Header().Set("Content-Type", "application/json")
				if scanResult.ScannerFailure != "" {
					status = http.StatusBadGateway
				} else {
					status = http.StatusUnavailableForLegalReasons
				}
			}
			if status != 0 {
				w.WriteHeader(status)
			}
			//nolint:gosec // G705: LLM API response body (JSON), not HTML; PII-scanned/redacted before write
			_, _ = w.Write(scannedBody)
			// Store in semantic cache when allowed (non-streaming path; content already PII-scrubbed)
			if cacheAllowStore && g.cacheStore != nil && g.cacheEmbedder != nil && g.cacheConfig != nil && extracted.Text != "" && capture.statusCode == 200 {
				if content := extractContentFromOpenAIResponse(scannedBody); content != "" {
					emb, err := g.cacheEmbedder.Embed(extracted.Text)
					if err == nil {
						// The response must be cached under the model AND provider
						// that actually produced it: a failover rewrite makes the
						// fallback-selected provider/model the truth, not what the
						// client asked for. The scope_key binds the entry to that
						// exact (agent, model, provider, effective policy, tier)
						// so a future hit cannot cross the boundary (#266 r5).
						cachedModel := extracted.Model
						cachedProvider := route.Provider
						if failoverOut != nil && failoverOut.SelectedProvider != "" && failoverOut.SelectedModel != "" {
							cachedModel = failoverOut.SelectedModel
							cachedProvider = failoverOut.SelectedProvider
						}
						// Use canonical tenant ID from config-derived map so cache key is not tainted by request path (CodeQL go/weak-sensitive-data-hashing).
						scopeTenantID := g.canonicalTenantIDForCache(requestRegistry, agent.TenantID)
						keyHash := cache.DeriveEntryKey(scopeTenantID, cachedModel, extracted.Text)
						tierLabel := cache.TierLabel(tier)
						storeScopeKey := cache.ScopeKey(agent.Name, cachedModel, cachedProvider, g.policyDigests(agent, cachedProvider).Effective, tierLabel)
						ttl := cache.TTLForTier(tierLabel, g.cacheConfig.TTLByTier, g.cacheConfig.DefaultTTL)
						now := time.Now().UTC()
						entry := &cache.Entry{
							TenantID: agent.TenantID, CacheKey: keyHash, EmbeddingData: emb, ResponseText: content,
							Model: cachedModel, DataTier: tierLabel, PIIScrubbed: true,
							AgentID: agent.Name, Provider: cachedProvider, ScopeKey: storeScopeKey,
							SourceCorrelationID: correlationID,
							CreatedAt:           now, ExpiresAt: now.Add(ttl),
						}
						if insertErr := g.cacheStore.Insert(ctx, entry); insertErr == nil {
							cacheStored = true
						} else {
							// Never silent (#266 review round 6): a persistent
							// insert failure would otherwise read as an
							// eternally cold cache with no operator signal.
							log.Warn().Err(insertErr).Str("correlation_id", correlationID).
								Str("agent", agent.Name).Str("provider", cachedProvider).Str("model", cachedModel).
								Msg("cache_store_failed")
						}
					}
				}
			}
		} else {
			capture.flushTo(w)
		}

	case observeStream:
		// Streaming + warn: deliver the stream as it arrives (the observing
		// writer forwards every write and flush to the client first) and
		// scan the bounded capture only after the stream has terminated.
		// This is post-delivery observation, not prevention: it cannot
		// change or recall a byte, and it must not — so it never blocks
		// after delivery, never rewrites the stream, and records any gap
		// (truncation, cancel, capture bound, scanner failure) as an
		// incomplete observation rather than a clean scan (#476).
		obs := newObservingStreamWriter(w)
		failoverOut, forwardErr = g.forwardWithFailover(ctx, obs, fwdParams, route, agent, extracted.Model, originalAuthorization, retryS, recordAttempt, checkCandidate)
		responsePII = observeStreamedResponse(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), obs, responsePIIAction, g.classifier, forwardErr, ctx)

	case preventiveStream:
		// Streaming + redact/block (preventive): buffer the entire SSE
		// stream, extract text, scan for PII. If clean, forward the original
		// buffered events. If PII found, return the redacted content wrapped
		// in SSE format, or withhold it. Buffering is the price of prevention:
		// time-to-first-token becomes total generation time (documented).
		// A forward error (upstream death, idle abort) goes through the SAME
		// scan: the truncated buffer may already contain PII-bearing deltas,
		// and flushing it raw would bypass the enforced response control
		// (#392). handleStreamingPIIScan accumulates delta content when no
		// completed frame exists, so partial streams scan correctly; empty
		// buffers and buffered error envelopes pass through unchanged.
		capture := &responseCapture{ResponseWriter: w}
		failoverOut, forwardErr = g.forwardWithFailover(ctx, capture, fwdParams, route, agent, extracted.Model, originalAuthorization, retryS, recordAttempt, checkCandidate)
		responsePII = handleStreamingPIIScan(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), w, capture, wire, responsePIIAction, g.classifier)
		// A scan over a truncated stream covered only what arrived.
		markStreamIncomplete(responsePII, forwardErr, ctx)

	default:
		failoverOut, forwardErr = g.forwardWithFailover(ctx, w, fwdParams, route, agent, extracted.Model, originalAuthorization, retryS, recordAttempt, checkCandidate)
	}

	durationMS := time.Since(start).Milliseconds()

	// From here on the provider has been reached (or definitively not): the
	// evidence write, session accounting and metrics are local bookkeeping of
	// what already happened and must not be dropped because the client went
	// away mid-stream. A cancelled stream records an incomplete observation
	// instead of no record at all (#476). Values (trace span, identity) are
	// kept; only the client's cancellation is detached.
	ctx = context.WithoutCancel(ctx)

	// Provider/model actually used (may differ from the route when failover
	// dispatched a fallback candidate). Evidence must record the truth.
	selectedProvider, selectedModel := route.Provider, extracted.Model
	if failoverOut != nil && failoverOut.SelectedProvider != "" {
		selectedProvider, selectedModel = failoverOut.SelectedProvider, failoverOut.SelectedModel
	}
	failoverEvCtx := g.buildFailoverDecisionContext(failoverOut, g.config.EffectiveSovereigntyMode)
	if failoverEvCtx != nil {
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.SetAttributes(
				otel.TalonProviderOriginal.String(route.Provider),
				otel.TalonProviderSelected.String(selectedProvider),
				otel.TalonProviderFallbackReason.String(failoverOut.FailedAttempts[0].Class.Class),
				otel.TalonFallbackChainPosition.Int(failoverOut.ChainPosition),
				otel.TalonFallbackFailedAttempts.Int(len(failoverOut.FailedAttempts)),
				otel.TalonFallbackFailClosed.Bool(failoverOut.FailClosed),
			)
		}
		if !failoverOut.FailClosed {
			llm.RecordFailover(ctx, extracted.Model, selectedModel, failoverOut.FailedAttempts[0].Class.Class)
		}
	}

	costResult := g.costEstimate(selectedProvider, selectedModel, Usage{
		Input:      tokenUsage.Input,
		CacheRead:  tokenUsage.CacheRead,
		CacheWrite: tokenUsage.CacheWrite,
		Output:     tokenUsage.Output,
	})
	cost := costResult.Amount
	pricingBasis := costResult.PricingBasis
	pricingKnown := costResult.PricingKnown
	if tokenUsage.Input == 0 && tokenUsage.Output == 0 && tokenUsage.CacheRead == 0 && tokenUsage.CacheWrite == 0 {
		cost = estimatedCost
	}
	if isCountTokens {
		// tokenUsage.Input holds the count *result*, not consumed tokens; the
		// endpoint is free. Cost stays zero so CostByAgent budget sums (which
		// have no invocation-type filter) remain truthful (#218).
		cost = 0
	}

	// Streaming metrics: TTFT and TPOT for GenAI SemConv
	var ttftMS int64
	var tpotMS float64
	if streamingMetrics.TTFT > 0 {
		ttftMS = streamingMetrics.TTFT.Milliseconds()
		if tokenUsage.Output > 0 && durationMS > ttftMS {
			tpotMS = float64(durationMS-ttftMS) / float64(tokenUsage.Output)
		}
	}

	// Step 10: Evidence. A response blocked by the output PII scan (or by a
	// scanner failure) is a denial: evidence must say so, never allowed=true
	// for a request whose agent received a blocked body.
	var forwardErrStr string
	if forwardErr != nil {
		forwardErrStr = forwardErr.Error()
	}
	responseBlocked := responsePII != nil && responsePII.Blocked
	evAllowed := !responseBlocked
	var evReasons []string
	if responseBlocked {
		reason := responsePII.BlockReason
		if reason == "" {
			reason = "output_pii_blocked"
		}
		evReasons = []string{reason}
		RecordGatewayError(ctx, reason)
	}
	persisted, recordErr := g.recordEvidence(ctx, correlationID, agent, selectedProvider, selectedModel, start, extracted.Text, classification, &tokenUsage, cost, durationMS, forwardErrStr, evAllowed, evReasons, inputPIIRedacted, responsePII, attSummary, toolResult, false, "", 0, 0, cacheStored, ttftMS, tpotMS, estimatedCost, func(p *RecordGatewayEvidenceParams) {
		p.Failover = failoverEvCtx
		if failoverOut != nil && failoverOut.FailClosed {
			p.Status = "failed"
			p.FailureReason = evidence.FailureReasonNoValidFallbackCandidate
		}
		if isCountTokens {
			p.InvocationType = "gateway_count_tokens"
		}
		p.ToolContent = toolContentScan
		if responsesStoreOverridden {
			// force_true reversed an explicit client store:false — that
			// retention decision must be visible in signed evidence.
			p.GatewayAnnotations = append(p.GatewayAnnotations, "responses_store_overridden")
		}
		if sessionBudgetUnavailable {
			// Session-store read failed: the budget check fails open (#198),
			// and that gap must be visible in signed evidence.
			p.GatewayAnnotations = append(p.GatewayAnnotations, "session_budget_unavailable")
		}
		if !isCountTokens {
			p.PricingBasis = pricingBasis
			p.PricingKnown = pricingKnown
		}
	})
	if recordErr != nil {
		g.handleEvidenceWriteFailure(ctx, recordErr)
		return
	}
	if !isCountTokens {
		// count_tokens neither spends nor consumes: keep session cost/token
		// accumulation and stage counts free of count-only traffic.
		g.trackSessionUsage(ctx, sessReservation, sessionID, sessionSource, agent.TenantID, agent.Name, cost, tokenUsage.Input+tokenUsage.Output)
	}

	// Emit OTel + dashboard metrics
	g.emitMetrics(ctx, agent, selectedProvider, selectedModel, classification, toolResult,
		&tokenUsage, cost, durationMS, forwardErr != nil, responseBlocked, piiAction, false, 0, ttftMS, tpotMS, persisted)
	if forwardErr != nil {
		log.Warn().Err(forwardErr).Msg("gateway_forward_error")
	}
}

//nolint:gocyclo // evidence assembly branches on optional subsystems (cache, egress, attachments, tools)
func (g *Gateway) recordEvidence(ctx context.Context, correlationID string, agent *ResolvedIdentity, provider, model string, start time.Time, inputText string, classification *classifier.Classification, usage *TokenUsage, cost float64, durationMS int64, executionError string, allowed bool, reasons []string, inputPIIRedacted bool, responsePII *ResponsePIIScanResult, attSummary *AttachmentsScanSummary, toolResult *ToolGovernanceResult, cacheHit bool, cacheEntryID string, cacheSimilarity float64, costSaved float64, cacheStored bool, ttftMS int64, tpotMS float64, estimatedCost float64, opts ...func(*RecordGatewayEvidenceParams)) (*evidence.Evidence, error) {
	if classification == nil {
		classification = &classifier.Classification{}
	}
	inputTokens, outputTokens := 0, 0
	cacheReadTokens, cacheWriteTokens := 0, 0
	if usage != nil {
		inputTokens, outputTokens = usage.Input, usage.Output
		cacheReadTokens, cacheWriteTokens = usage.CacheRead, usage.CacheWrite
	}
	secretsAccessed := []string{}
	// On the delegated path the runtime injects the provider credential and
	// Talon never touches the vault binding — the record must not say it did.
	if prov, ok := g.config.Provider(provider); ok && prov.SecretName != "" && upstreamAuthModeFromContext(ctx) != UpstreamAuthModeExternalRuntime {
		secretsAccessed = append(secretsAccessed, prov.SecretName)
	}
	piiDetected := []string{}
	for _, e := range classification.Entities {
		piiDetected = append(piiDetected, e.Type)
	}
	var outputPIIDetected bool
	var outputPIITypes []string
	// Output tier defaults to the input tier (pre-response-scan behavior);
	// when the response was scanned and PII found, the response content's own
	// tier is the truth — a clean tier-0 prompt whose response leaked an IBAN
	// must record output_tier 2, not 0.
	outputTier := classification.Tier
	if responsePII != nil {
		outputPIIDetected = responsePII.PIIDetected
		outputPIITypes = responsePII.PIITypes
		if responsePII.PIIDetected {
			outputTier = responsePII.Tier
		}
	}
	execErr := resolveExecutionError(executionError, reasons)

	egressDecision := g.buildEgressDecisionEvidence(agent, provider, classification.Tier, allowed, reasons)
	if egressDecision != nil {
		RecordEgressDecision(ctx, agent.TenantID, egressDecision.Tier, egressDecision.Provider, egressDecision.Region, egressDecision.Decision)
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.SetAttributes(
				attribute.String("tenant_id", agent.TenantID),
				attribute.String("talon.egress.agent", agent.Name),
				attribute.String("talon.egress.correlation_id", correlationID),
				attribute.Int("talon.egress.data_tier", egressDecision.Tier),
				attribute.String("talon.egress.destination_provider", egressDecision.Provider),
				attribute.String("talon.egress.destination_region", egressDecision.Region),
				attribute.String("talon.egress.decision", egressDecision.Decision),
				attribute.String("talon.egress.reason", egressDecision.Reason),
			)
		}
	}

	dataFlow := g.buildDataFlow(dataFlowInputs{
		CorrelationID:    correlationID,
		TenantID:         agent.TenantID,
		AgentName:        agent.Name,
		Provider:         provider,
		Model:            model,
		Allowed:          allowed,
		InputPIIRedacted: inputPIIRedacted,
		InputText:        inputText,
		Classification:   classification,
		AttSummary:       attSummary,
		ResponsePII:      responsePII,
		CacheHit:         cacheHit,
		CacheEntryID:     cacheEntryID,
		CacheStored:      cacheStored,
	})
	g.emitDataFlowTelemetry(ctx, correlationID, agent, dataFlow)

	var attScan *evidence.AttachmentScan
	if attSummary != nil && attSummary.FilesScanned > 0 {
		var blocked []string
		for _, r := range attSummary.Results {
			if r.ActionTaken == "blocked" || r.ActionTaken == "stripped" {
				blocked = append(blocked, r.Filename)
			}
		}
		attScan = &evidence.AttachmentScan{
			FilesProcessed:           attSummary.FilesScanned,
			InjectionsDetected:       attSummary.InjectionsFound,
			ActionTaken:              attSummary.ActionTaken,
			BlockedFiles:             blocked,
			PIIDetectedInAttachments: attSummary.PIITypes,
		}
	}

	params := RecordGatewayEvidenceParams{
		CorrelationID:     correlationID,
		SessionID:         sessionIDFromContext(ctx),
		TenantID:          agent.TenantID,
		AgentName:         agent.Name,
		Team:              agent.Team,
		Provider:          provider,
		Model:             model,
		PolicyAllowed:     allowed,
		PolicyReasons:     reasons,
		PolicyVersion:     agent.PolicyDigest,
		PolicyDigests:     g.policyDigests(agent, provider),
		InputTier:         classification.Tier,
		OutputTier:        outputTier,
		PIIDetected:       piiDetected,
		PIIRedacted:       inputPIIRedacted,
		InputPIIRedacted:  inputPIIRedacted,
		OutputPIIDetected: outputPIIDetected,
		OutputPIITypes:    outputPIITypes,
		Cost:              cost,
		EstimatedCost:     estimatedCost,
		Currency:          g.pricingCurrency,
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		CacheReadTokens:   cacheReadTokens,
		CacheWriteTokens:  cacheWriteTokens,
		DurationMS:        durationMS,
		Error:             execErr,
		SecretsAccessed:   secretsAccessed,
		AttachmentScan:    attScan,
		AgentReasoning:    agentReasoningFromContext(ctx),
		RetryAttempt:      retryAttemptFromContext(ctx),
		Stage:             stageFromContext(ctx),
		CandidateIndex:    candidateIndexFromContext(ctx),
		ExplanationFacts:  buildGatewayExplanationFacts(allowed, reasons, responsePII),
		DataFlow:          dataFlow,
		EgressDecision:    egressDecision,
		Orchestration:     orchestrationFromContext(ctx),
	}
	if toolResult != nil {
		params.ToolsRequested = toolResult.Requested
		params.ToolsFiltered = toolResult.Removed
		params.ToolsForwarded = toolResult.Kept
	}
	params.CacheHit = cacheHit
	params.CacheEntryID = cacheEntryID
	params.CacheSimilarity = cacheSimilarity
	params.CostSaved = costSaved
	params.UpstreamAuthMode = upstreamAuthModeFromContext(ctx)
	params.UpstreamKeySource = upstreamKeySourceFromContext(ctx)
	params.UpstreamKeyFingerprint = upstreamKeyFingerprintFromContext(ctx)
	params.GatewayAnnotations = gatewayAnnotationsForEvidence(ctx, g, agent)
	params.TTFTMS = ttftMS
	params.TPOTMS = tpotMS
	params.Scanner = g.buildScannerEvidence(ctx, reasons, responsePII)
	params.ResponseScan = responseScanEvidence(responsePII)
	for _, opt := range opts {
		opt(&params)
	}
	ev, err := RecordGatewayEvidence(ctx, g.evidenceStore, params)
	if err != nil {
		return nil, err
	}
	return ev, nil
}

// buildScannerEvidence describes the scan engine for evidence, including the
// scan duration (when measured on this request) and whether a scanner failure
// drove the outcome.
func (g *Gateway) buildScannerEvidence(ctx context.Context, reasons []string, responsePII *ResponsePIIScanResult) *evidence.ScannerInfo {
	info := evidence.NewScannerInfo(g.classifier)
	if info == nil {
		return nil
	}
	info.ScanDurationMS = scanDurationFromContext(ctx)
	for _, r := range reasons {
		if r == "scanner unavailable" || r == "request redaction failed" {
			info.Failure = "scanner_unavailable"
		}
	}
	if responsePII != nil && responsePII.ScannerFailure != "" {
		info.Failure = responsePII.ScannerFailure
	}
	return info
}

type scanDurationKey struct{}

// withScanDuration stores the request PII scan duration for evidence.
func withScanDuration(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, scanDurationKey{}, d.Milliseconds())
}

func scanDurationFromContext(ctx context.Context) int64 {
	if v, ok := ctx.Value(scanDurationKey{}).(int64); ok {
		return v
	}
	return 0
}

func (g *Gateway) handleEvidenceWriteFailure(ctx context.Context, err error) {
	RecordGatewayError(ctx, "evidence_store")
	log.Error().Err(err).Msg("gateway_evidence_store_failed")
}

// resolveExecutionError returns the explicit execution error when set, otherwise
// the first policy reason that looks like an error (legacy behavior preserved
// so blocked/error invariants still surface in evidence).
func resolveExecutionError(explicit string, reasons []string) string {
	if explicit != "" {
		return explicit
	}
	for _, reason := range reasons {
		if strings.Contains(strings.ToLower(reason), "error") {
			return reason
		}
	}
	return ""
}

// buildGatewayExplanationFacts renders the policy-evaluation facts plus, when
// response PII was detected, one output-validation fact that says what
// actually happened to the response: withheld (deny), redacted before
// release (modify) or observed with the response delivered unchanged
// (allow). A warn observation must never be explained as a denial (#476).
func buildGatewayExplanationFacts(allowed bool, reasons []string, responsePII *ResponsePIIScanResult) []explanation.Fact {
	facts := explanation.BuildLegacyFacts(allowed, decisionAction(allowed), reasons, explanation.StagePolicyEvaluation, "", "")
	if responsePII == nil || !responsePII.PIIDetected {
		return facts
	}
	disposition := outputPIIObserved
	switch {
	case responsePII.Blocked:
		disposition = outputPIIBlocked
	case responsePII.Redacted:
		disposition = outputPIIRedacted
	}
	return append(facts, outputPIIFact(responsePII.PIITypes, disposition, "", ""))
}

func decisionAction(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

func agentReasoningFromContext(ctx context.Context) string {
	v := ctx.Value(gatewayAgentReasoningKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func sessionIDFromContext(ctx context.Context) string {
	v := ctx.Value(gatewaySessionIDKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func retryAttemptFromContext(ctx context.Context) string {
	v := ctx.Value(gatewayRetryAttemptKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func orchestrationFromContext(ctx context.Context) *evidence.OrchestrationContext {
	if v, ok := ctx.Value(gatewayOrchestrationKey).(*evidence.OrchestrationContext); ok {
		return v
	}
	return nil
}

func stageFromContext(ctx context.Context) string {
	v := ctx.Value(gatewayStageKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func candidateIndexFromContext(ctx context.Context) int {
	v := ctx.Value(gatewayCandidateIndexKey)
	if i, ok := v.(int); ok {
		return i
	}
	return 0
}

func upstreamAuthModeFromContext(ctx context.Context) string {
	v := ctx.Value(gatewayUpstreamAuthMode)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func upstreamKeySourceFromContext(ctx context.Context) string {
	v := ctx.Value(gatewayUpstreamKeySource)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func upstreamKeyFingerprintFromContext(ctx context.Context) string {
	v := ctx.Value(gatewayUpstreamKeyFP)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func fingerprintKey(raw string) string {
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	hexSum := hex.EncodeToString(sum[:])
	if len(hexSum) < 12 {
		return hexSum
	}
	return hexSum[:12]
}

// ctxKeyBudgetUnavailable marks a request whose agent spend read failed, so
// the signed evidence carries an agent_budget_unavailable annotation instead
// of silently gating on a false zero (#266 review round 4). Named-type key —
// distinct from every other context key.
type ctxKeyBudgetUnavailable struct{}

func withBudgetUnavailable(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyBudgetUnavailable{}, true)
}

func budgetUnavailableFromCtx(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyBudgetUnavailable{}).(bool)
	return v
}

func gatewayAnnotationsForEvidence(ctx context.Context, g *Gateway, agent *ResolvedIdentity) []string {
	var out []string
	if budgetUnavailableFromCtx(ctx) {
		out = append(out, "agent_budget_unavailable")
	}
	if agent == nil || !agent.HasTag("quickstart") {
		return out
	}
	out = append(out, "quickstart_mode")
	if g != nil && g.config != nil {
		if openai, ok := g.config.Provider("openai"); ok && len(openai.AllowedModels) == 0 {
			out = append(out, "quickstart_model_allowlist_disabled")
		}
		if g.config.QuickstartUnsafeListen {
			out = append(out, "quickstart_unsafe_listen")
		}
	}
	return out
}

// trackSessionUsage accumulates cost/tokens onto the agent-scoped session row
// (#198). Only client- or vendor-asserted session ids create-if-absent under
// the (tenant, agent, external id) tuple; synthetic ids NEVER create session
// rows — evidence keeps the synthetic id, and the pre-#198 orphan-row-per-
// request growth (#214) is gone. Callers that reject client metadata assert
// no session identity, so no row either.
//
// When the request holds a reservation (#144), settle converts it to settled
// spend atomically — the estimate leaves reserved_cost, the ACTUAL cost lands
// on the totals — and the deferred release becomes a no-op. Requests without
// a reservation (zero estimate, reservation-time store failure) keep the
// plain accumulate path.
func (g *Gateway) trackSessionUsage(ctx context.Context, res *sessionReservation, sessionID, sessionSource, tenantID, callerName string, cost float64, tokens int) {
	if g.sessionStore == nil || sessionID == "" || !isAssertedSessionSource(sessionSource) {
		return
	}
	var rowID string
	if res != nil && !res.done {
		res.done = true
		rowID = res.rowID
		if err := g.sessionStore.SettleSessionUsage(ctx, res.rowID, res.estimate, cost, tokens); err != nil {
			log.Warn().Err(err).Str("session_id", res.rowID).Msg("gateway_session_usage_failed")
			return
		}
	} else {
		sess, err := g.sessionStore.GetOrCreateExternal(ctx, tenantID, callerName, sessionID, sessionSource)
		if err != nil {
			log.Warn().Err(err).Str("session_id", sessionID).Msg("gateway_session_create_failed")
			return
		}
		rowID = sess.ID
		if usageErr := g.sessionStore.AddUsage(ctx, sess.ID, cost, tokens); usageErr != nil {
			// AddUsage is also what refreshes updated_at (retention liveness);
			// don't record stage counts for a request whose usage was lost.
			log.Warn().Err(usageErr).Str("session_id", sess.ID).Msg("gateway_session_usage_failed")
			return
		}
	}
	if stage := stageFromContext(ctx); stage != "" {
		if err := g.sessionStore.IncrementStageCount(ctx, rowID, stage); err != nil {
			log.Warn().Err(err).Str("session_id", rowID).Str("stage", stage).Msg("stage count increment failed")
		}
	}
}

// isAssertedSessionSource reports whether the session id was asserted by the
// client (generic header) or a vendor adapter — the only sources allowed to
// materialize session-store state (#198).
func isAssertedSessionSource(source string) bool {
	return source == orchSourceClientAsserted || source == orchSourceVendorAsserted
}

// buildPolicyInputForRequest builds the gateway policy input for a
// (provider, model) pair with the full request context — destination region
// and session budget/stage included. The primary request and every fallback
// candidate MUST go through this same function so the two policy surfaces
// cannot drift apart (see TestPolicyInputParity_PrimaryVsCandidate).
//
// Session state arrives as the precomputed sessView (#144): the reservation
// in reserveSessionBudget happens ONCE per request, and the identical view is
// evaluated by the primary and every failover candidate — a per-call store
// read would both drift the candidates' spend and double-reserve. A nil view
// means no asserted session. sessionUnavailable reports a session-store
// failure: the check fails open (request proceeds without session budget
// input) and the agent must record the "session_budget_unavailable" evidence
// annotation.
func (g *Gateway) buildPolicyInputForRequest(ctx context.Context, agent *ResolvedIdentity, provider, model string, tier int, estimatedCost, dailyCost, monthlyCost float64, sessView *sessionView) (input map[string]interface{}, sessionUnavailable bool) {
	// The effective policy is recomputed for THIS provider — organization
	// baseline → the agent's one override → the provider's destination
	// constraints — so a failover candidate is evaluated against its own
	// provider's constraints through the exact same code path as the primary.
	prov, _ := g.config.Provider(provider)
	eff := ResolveEffectivePolicy(g.config.OrganizationPolicy, prov, agent.Override)
	input = buildGatewayPolicyInput(agent, eff, provider, model, tier, estimatedCost, dailyCost, monthlyCost, g.providerRegion(provider))
	if sessView != nil {
		switch {
		case sessView.unavailable:
			sessionUnavailable = true
		case sessView.ok:
			input["session_cost_total"] = sessView.costTotal
			if sc := sessView.stageCounts; sc != nil {
				input["session_stage_counts"] = map[string]int{
					"generation": sc.Generation,
					"judge":      sc.Judge,
					"commit":     sc.Commit,
				}
			}
		}
	}
	input["session_stage"] = stageFromContext(ctx)
	return input, sessionUnavailable
}

func buildGatewayPolicyInput(agent *ResolvedIdentity, eff EffectivePolicy, provider, model string, dataTier int, estimatedCost, dailyCost, monthlyCost float64, destinationRegion string) map[string]interface{} {
	input := map[string]interface{}{
		"provider":           provider,
		"model":              model,
		"data_tier":          dataTier,
		"estimated_cost":     estimatedCost,
		"daily_cost":         dailyCost,
		"monthly_cost":       monthlyCost,
		"agent_name":         agent.Name,
		"tenant_id":          agent.TenantID,
		"destination_region": destinationRegion,
	}
	if eff.Egress != nil {
		input["egress_rules"] = egressRulesForPolicyInput(eff.Egress)
		input["egress_default_action"] = eff.Egress.DefaultAction
	}
	// The agent egress is a SECOND, independent boundary: the rego denies when
	// EITHER the org OR the agent policy denies, so egress is a logical
	// intersection, not org-wins (#266 review round 5).
	if eff.AgentEgress != nil {
		input["agent_egress_rules"] = egressRulesForPolicyInput(eff.AgentEgress)
		input["agent_egress_default_action"] = eff.AgentEgress.DefaultAction
	}
	emitBudgetPolicyInput(input, &eff)
	if len(eff.AllowedModels) > 0 {
		input["agent_allowed_models"] = eff.AllowedModels
	}
	if len(eff.BlockedModels) > 0 {
		input["agent_blocked_models"] = eff.BlockedModels
	}
	// Organization model lists are HARD constraints — separate input keys so
	// an agent override can never satisfy them away (#266).
	if len(eff.OrgAllowedModels) > 0 {
		input["org_allowed_models"] = eff.OrgAllowedModels
	}
	if len(eff.OrgBlockedModels) > 0 {
		input["org_blocked_models"] = eff.OrgBlockedModels
	}
	// Provider (destination) model lists ride the SAME shared policy input so
	// the PRIMARY route enforces them through Rego, not just fallback
	// candidates via a standalone check (#266 review round 4, closes #278).
	if len(eff.ProviderAllowedModels) > 0 {
		input["provider_allowed_models"] = eff.ProviderAllowedModels
	}
	if len(eff.ProviderBlockedModels) > 0 {
		input["provider_blocked_models"] = eff.ProviderBlockedModels
	}
	// Tier caps ride per-layer keys so the deny reason names WHICH layer's
	// restriction fired (#279 review) — the effective minimum still gates
	// (each rule denies independently; the stricter one always fires).
	if eff.AgentMaxDataTier != nil {
		input["agent_max_data_tier"] = int(*eff.AgentMaxDataTier)
	}
	if eff.OrgMaxDataTier != nil {
		input["org_max_data_tier"] = int(*eff.OrgMaxDataTier)
	}
	return input
}

// emitBudgetPolicyInput adds the budget keys to the shared policy input.
// Effective caps: organization baseline overlaid by the agent's override —
// the same resolution feeds budget-utilization metrics/alerts so the
// dashboard and the enforcement decision agree on the denominator (#216).
// The session cap rides the same builder so the primary request and every
// fallback candidate see it identically (#198). Org budget ceilings
// (constraints.max_*, #287/#283) ride separate keys with their own deny
// rules, so an agent-declared budget above the org line still denies at the
// ceiling — and the signed deny reason names the ORGANIZATION, not the agent
// (same layer-attribution contract as the data-tier rules).
func emitBudgetPolicyInput(input map[string]interface{}, eff *EffectivePolicy) {
	if eff.MaxDailyCost > 0 {
		input["agent_max_daily_cost"] = eff.MaxDailyCost
	}
	if eff.MaxMonthlyCost > 0 {
		input["agent_max_monthly_cost"] = eff.MaxMonthlyCost
	}
	if eff.MaxSessionCost > 0 {
		input["agent_max_session_cost"] = eff.MaxSessionCost
	}
	if eff.OrgMaxDailyCost > 0 {
		input["org_max_daily_cost"] = eff.OrgMaxDailyCost
	}
	if eff.OrgMaxMonthlyCost > 0 {
		input["org_max_monthly_cost"] = eff.OrgMaxMonthlyCost
	}
	if eff.OrgMaxSessionCost > 0 {
		input["org_max_session_cost"] = eff.OrgMaxSessionCost
	}
}

// sessionBudgetDetail extracts the structured {limit, spent, estimate} session
// budget detail when a session_budget_exceeded deny fired, from the same
// policy input the rule evaluated — the signed record carries the numbers the
// decision was made on, not a re-read.
func sessionBudgetDetail(reasons []string, policyInput map[string]interface{}, estimatedCost float64) *evidence.SessionBudget {
	fired := false
	for _, r := range reasons {
		if strings.HasPrefix(r, "session_budget_exceeded:") {
			fired = true
			break
		}
	}
	if !fired {
		return nil
	}
	// Two session rules can fire (agent cap #198, org ceiling #283) — the
	// recorded limit is the BINDING one: the tightest positive bound is the
	// first to be exceeded, so it is the number the decision was made on.
	agentLimit, _ := policyInput["agent_max_session_cost"].(float64)
	orgLimit, _ := policyInput["org_max_session_cost"].(float64)
	limit := tightestPositive(agentLimit, orgLimit)
	spent, _ := policyInput["session_cost_total"].(float64)
	return &evidence.SessionBudget{Limit: limit, Spent: spent, Estimate: estimatedCost}
}

// policyDigests computes the component + effective policy digests recorded in
// signed evidence (#266 review round 4), so a decision names the exact policy
// state it was made against. The effective digest is over the RESOLVED
// snapshot, not file paths or timestamps.
func (g *Gateway) policyDigests(agent *ResolvedIdentity, provider string) *evidence.PolicyDigests {
	prov, _ := g.config.Provider(provider)
	eff := ResolveEffectivePolicy(g.config.OrganizationPolicy, prov, agent.Override)
	d := &evidence.PolicyDigests{
		Organization: hashJSONDigest(g.config.OrganizationPolicy),
		Provider:     hashJSONDigest(prov),
		Effective:    hashJSONDigest(eff),
		Agent:        agent.PolicyDigest,
	}
	if d.Agent == "" && agent.Override != nil {
		// Test/registry-built identities may lack the loader's policy hash;
		// fall back to a digest of the override so the field is never blank
		// when an override exists.
		d.Agent = hashJSONDigest(agent.Override)
	}
	return d
}

// hashJSONDigest returns the hex SHA-256 of a value's JSON encoding. Go's
// json.Marshal is deterministic for these structs (fields in declaration
// order, map keys sorted), so the digest is stable across runs.
func hashJSONDigest(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// agentCostTotals returns the agent's accumulated daily/monthly spend. The
// third return is true when an evidence-store read FAILED: the caller then
// treats the caps as unenforceable-this-request and records an
// "agent_budget_unavailable" annotation on the signed record, so a silent
// zero (fail-open) never looks like genuine zero spend (#266 review round 4).
func (g *Gateway) agentCostTotals(ctx context.Context, agent *ResolvedIdentity) (daily, monthly float64, unavailable bool) {
	// Day/month windows are computed in UTC so budget enforcement agrees with
	// `talon costs` reporting, which also uses UTC. Server-local windows made the
	// two disagree for the UTC-offset hours around midnight on non-UTC hosts (#216).
	now := time.Now().UTC()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	byAgent, err := g.evidenceStore.CostByAgent(ctx, agent.TenantID, todayStart, now)
	if err != nil {
		log.Warn().Err(err).Str("agent", agent.Name).Msg("gateway_agent_budget_read_failed")
		return 0, 0, true
	}
	daily = byAgent[agent.Name]
	byAgent, err = g.evidenceStore.CostByAgent(ctx, agent.TenantID, monthStart, now)
	if err != nil {
		log.Warn().Err(err).Str("agent", agent.Name).Msg("gateway_agent_budget_read_failed")
		return daily, 0, true
	}
	monthly = byAgent[agent.Name]
	return daily, monthly, false
}

func defaultCostEstimator(_, _ string, usage Usage) CostResult {
	// Rough per-1k-token approximation when no pricing table is wired.
	n := float64(usage.Input+usage.CacheRead+usage.CacheWrite+usage.Output) / 1000
	if n < 0.01 {
		n = 0.01
	}
	return CostResult{Amount: n * 0.002, PricingKnown: false, PricingBasis: PricingBasisDefault}
}

func extractContentFromOpenAIResponse(body []byte) string {
	var v struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &v); err != nil || len(v.Choices) == 0 {
		return ""
	}
	return v.Choices[0].Message.Content
}

// emitMetrics records OTel counters and optionally fires a dashboard event.
//
//nolint:gocyclo // sequential metric recording
func (g *Gateway) emitMetrics(ctx context.Context, agent *ResolvedIdentity, provider, model string,
	classification *classifier.Classification, toolResult *ToolGovernanceResult,
	usage *TokenUsage,
	cost float64, durationMS int64, hasError, blocked bool, piiAction string,
	cacheHit bool, costSaved float64, ttftMS int64, tpotMS float64, persistedEvidence *evidence.Evidence,
) {
	status := "ok"
	if hasError {
		status = "error"
	} else if blocked {
		status = "blocked"
	}
	RecordGatewayRequest(ctx, agent.Name, model, provider, status)
	if hasError {
		RecordGatewayError(ctx, "upstream_error")
	}
	if classification != nil {
		RecordDataTier(ctx, classification.Tier, agent.Name)
	}

	if toolResult != nil {
		for _, tool := range toolResult.Kept {
			RecordToolGovernance(ctx, tool, "allowed")
		}
		for _, tool := range toolResult.Removed {
			RecordToolGovernance(ctx, tool, "filtered")
		}
	}

	RecordCacheResult(ctx, agent.TenantID, cacheHit)

	// GenAI SemConv: token usage and operation duration
	tokIn, tokOut := 0, 0
	if usage != nil {
		tokIn, tokOut = usage.Input, usage.Output
	}
	if tokIn > 0 || tokOut > 0 {
		llm.RecordTokenUsage(ctx, tokIn, tokOut, model, provider)
	}
	if cost > 0 {
		llm.RecordCostMetrics(ctx, cost, agent.Name, model, false)
	}
	if durationMS > 0 {
		llm.RecordOperationDuration(ctx, float64(durationMS)/1000.0, model, provider)
	}
	if ttftMS > 0 {
		llm.RecordTimeToFirstToken(ctx, float64(ttftMS)/1000.0, model, provider)
	}
	if tpotMS > 0 {
		llm.RecordTimePerOutputToken(ctx, tpotMS/1000.0, model, provider)
	}
	llm.RecordProviderAvailability(ctx, provider, !hasError)

	if g.metricsRecorder != nil {
		if persistedEvidence == nil {
			log.Warn().Msg("skipping_metrics_recorder_emit_without_persisted_evidence")
			return
		}
		g.metricsRecorder.RecordGatewayEvent(metrics.GatewayEventFromEvidence(persistedEvidence))
	}
}

// writeCachedCompletion writes a minimal provider-native completion body with
// the cached content: an Anthropic Messages object on anthropic-family routes,
// an OpenAI chat completion otherwise (#195 — previously always OpenAI shape).
func writeCachedCompletion(w http.ResponseWriter, apiFamily, model string, content string) {
	w.Header().Set("Content-Type", "application/json")
	id := "cache-" + fmt.Sprintf("%d", time.Now().UnixNano())
	if apiFamily == "anthropic" {
		resp := map[string]interface{}{
			"id":            id,
			"type":          "message",
			"role":          "assistant",
			"model":         model,
			"content":       []map[string]interface{}{{"type": "text", "text": content}},
			"stop_reason":   "end_turn",
			"stop_sequence": nil,
			"usage":         map[string]interface{}{"input_tokens": 0, "output_tokens": 0},
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	resp := map[string]interface{}{
		"id":     id,
		"object": "chat.completion",
		"model":  model,
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": content,
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]interface{}{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// uniqueEntityTypes returns the sorted unique entity types from PII entities
// (for the observation-only tool-content scan evidence).
func uniqueEntityTypes(entities []classifier.PIIEntity) []string {
	if len(entities) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(entities))
	var out []string
	for _, e := range entities {
		if _, ok := seen[e.Type]; ok {
			continue
		}
		seen[e.Type] = struct{}{}
		out = append(out, e.Type)
	}
	sort.Strings(out)
	return out
}
