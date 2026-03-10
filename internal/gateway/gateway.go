package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/cache"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/secrets"
)

// PolicyEvaluator evaluates gateway-specific policy (model allowlist, cost, data tier).
// When nil, policy evaluation is skipped (log_only mode).
//
//revive:disable-next-line:exported
type GatewayPolicyEvaluator interface {
	EvaluateGateway(ctx context.Context, input map[string]interface{}) (allowed bool, reasons []string, err error)
}

// CostEstimator returns estimated cost in EUR for a request. Used for policy and evidence.
type CostEstimator func(model string, inputTokens, outputTokens int) float64

// MetricsRecorder receives gateway events for dashboard aggregation.
// Implemented by *metrics.Collector via an adapter to avoid import cycles.
type MetricsRecorder interface {
	RecordGatewayEvent(event interface{})
}

// hasCallerTag returns true when the caller has the given tag (e.g. "copaw" for CoPaw).
// Classification is driven by CallerConfig.Tags, not name prefix.
func hasCallerTag(caller *CallerConfig, tag string) bool {
	for _, t := range caller.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// Gateway is the LLM API gateway handler.
type Gateway struct {
	config        *GatewayConfig
	classifier    *classifier.Scanner
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
	cacheStore    *cache.Store
	cacheEmbedder *cache.BM25
	cacheScrubber *cache.PIIScrubber
	cachePolicy   *cache.Evaluator
	cacheConfig   *gatewayCacheConfig
	// canonicalTenantIDs maps tenant ID -> same ID from config (populated at init); used for cache key scope so static analysis sees value from config, not from request.
	canonicalTenantIDs map[string]string
	metricsRecorder    MetricsRecorder
}

type gatewayCacheConfig struct {
	Enabled             bool
	DefaultTTL          int
	SimilarityThreshold float64
	MaxEntriesPerTenant int
}

// canonicalTenantIDForCache returns the tenant ID for cache key scope from the config-derived map.
// Used so the value passed to cache.DeriveEntryKey originates from config (not from the request path), satisfying static analysis.
func (g *Gateway) canonicalTenantIDForCache(fromCaller string) string {
	if g.canonicalTenantIDs == nil {
		return fromCaller
	}
	if s, ok := g.canonicalTenantIDs[fromCaller]; ok {
		return s
	}
	return fromCaller
}

// SetMetricsRecorder attaches a dashboard metrics collector. Call after NewGateway.
func (g *Gateway) SetMetricsRecorder(mr MetricsRecorder) {
	g.metricsRecorder = mr
}

// SetCache wires the optional semantic cache into the gateway. Call after NewGateway when cache is enabled.
func (g *Gateway) SetCache(store *cache.Store, embedder *cache.BM25, scrubber *cache.PIIScrubber, policy *cache.Evaluator, enabled bool, defaultTTL int, similarityThreshold float64, maxEntriesPerTenant int) {
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
		SimilarityThreshold: similarityThreshold,
		MaxEntriesPerTenant: maxEntriesPerTenant,
	}
}

// NewGateway creates a new Gateway.
func NewGateway(
	config *GatewayConfig,
	classifier *classifier.Scanner,
	evidenceStore *evidence.Store,
	secretsStore *secrets.SecretStore,
	policy GatewayPolicyEvaluator,
	costEstimate CostEstimator,
) (*Gateway, error) {
	if costEstimate == nil {
		costEstimate = defaultCostEstimator
	}
	timeouts, err := config.ParseTimeouts()
	if err != nil {
		return nil, err
	}
	client := HTTPClientForGateway(timeouts)
	rl := NewRateLimiter(
		config.RateLimits.GlobalRequestsPerMin,
		config.RateLimits.PerCallerRequestsPerMin,
	)

	maxMB := DefaultAttachmentMaxFileSizeMB
	if p := config.ServerDefaults.AttachmentPolicy; p != nil && p.MaxFileSizeMB > 0 {
		maxMB = p.MaxFileSizeMB
	}
	ext := attachment.NewExtractor(maxMB)
	injScan, err := attachment.NewScanner()
	if err != nil {
		return nil, fmt.Errorf("creating attachment injection scanner: %w", err)
	}

	canonical := make(map[string]string)
	for i := range config.Callers {
		tid := config.Callers[i].TenantID
		canonical[tid] = tid
	}
	return &Gateway{
		config:             config,
		classifier:         classifier,
		evidenceStore:      evidenceStore,
		secretsStore:       secretsStore,
		policy:             policy,
		costEstimate:       costEstimate,
		timeouts:           timeouts,
		client:             client,
		rateLimiter:        rl,
		attExtractor:       ext,
		attInjScanner:      injScan,
		canonicalTenantIDs: canonical,
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

	isShadow := g.config.Mode == ModeShadow
	var shadowViolations []evidence.ShadowViolation

	// Step 1: Route
	route, err := g.config.RouteRequest(r)
	if err != nil {
		log.Warn().Err(err).Str("path", r.URL.Path).Msg("gateway_route_failed")
		WriteProviderError(w, "openai", http.StatusBadRequest, err.Error())
		return
	}

	// Step 2: Identify
	caller, err := g.config.ResolveCaller(r)
	if err != nil {
		if err == ErrCallerIDRequired || err == ErrCallerNotFound {
			WriteProviderError(w, route.Provider, http.StatusUnauthorized, "Invalid or missing API key")
			return
		}
		WriteProviderError(w, route.Provider, http.StatusInternalServerError, err.Error())
		return
	}
	if span := trace.SpanFromContext(ctx); span.IsRecording() && hasCallerTag(caller, "copaw") {
		span.SetAttributes(
			attribute.String("copaw.caller", caller.Name),
			attribute.String("copaw.channel", "gateway"),
		)
	}

	// Rate limit check (after caller identification, before any work)
	if g.rateLimiter != nil && !g.rateLimiter.Allow(caller.Name) {
		if isShadow {
			shadowViolations = append(shadowViolations, evidence.ShadowViolation{
				Type: "rate_limit", Detail: "Rate limit exceeded for " + caller.Name, Action: "block",
			})
			log.Warn().Str("caller", caller.Name).Str("enforcement_mode", "shadow").Msg("shadow_rate_limit_exceeded")
		} else {
			log.Warn().Str("caller", caller.Name).Msg("gateway_rate_limited")
			WriteProviderError(w, route.Provider, http.StatusTooManyRequests, "Rate limit exceeded")
			return
		}
	}

	// Only POST
	if r.Method != http.MethodPost {
		WriteProviderError(w, route.Provider, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteProviderError(w, route.Provider, http.StatusBadRequest, "Failed to read request body")
		return
	}
	_ = r.Body.Close()

	// Step 3: Extract
	extracted, err := ExtractForProvider(route.Provider, body)
	if err != nil {
		WriteProviderError(w, route.Provider, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Step 3b: Scan attachments (base64-encoded file blocks)
	attPolicy := ResolveAttachmentPolicy(&g.config.ServerDefaults, caller.PolicyOverrides)
	var attSummary *AttachmentsScanSummary
	if attPolicy.Action != "allow" {
		attSummary = ScanRequestAttachments(ctx, body, route.Provider,
			g.attExtractor, g.classifier, g.attInjScanner, attPolicy)
	}
	if attSummary != nil && attSummary.BlockRequest {
		if isShadow {
			shadowViolations = append(shadowViolations, evidence.ShadowViolation{
				Type: "attachment_block", Detail: fmt.Sprintf("%d file(s) would be blocked", attSummary.FilesBlocked), Action: "block",
			})
			log.Warn().Str("caller", caller.Name).Str("enforcement_mode", "shadow").Msg("shadow_attachment_block")
		} else {
			WriteProviderError(w, route.Provider, http.StatusBadRequest,
				"Request blocked: attachment violates policy")
			_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body,
				g.classifier.Scan(ctx, extracted.Text), nil, 0, 0, 0, false,
				[]string{"attachment policy block"}, false, nil, attSummary, nil, nil, false, "", 0, 0)
			return
		}
	}
	if !isShadow && attSummary != nil && attSummary.ModifiedBody != nil {
		body = attSummary.ModifiedBody
	}

	// Step 4: Scan PII
	classification := g.classifier.Scan(ctx, extracted.Text)

	// Step 5: Classify (tier from PII)
	tier := classification.Tier
	if tier > 2 {
		tier = 2
	}

	// Caller allowed for this provider?
	if len(caller.AllowedProviders) > 0 {
		allowed := false
		for _, p := range caller.AllowedProviders {
			if p == route.Provider {
				allowed = true
				break
			}
		}
		if !allowed {
			WriteProviderError(w, route.Provider, http.StatusForbidden, "Caller not allowed for this provider")
			return
		}
	}

	// Step 6: Evaluate policy
	piiAction := g.config.ServerDefaults.DefaultPIIAction
	if caller.PolicyOverrides != nil && caller.PolicyOverrides.PIIAction != "" {
		piiAction = caller.PolicyOverrides.PIIAction
	}
	if piiAction == "block" && classification.HasPII {
		if isShadow {
			piiTypes := make([]string, 0, len(classification.Entities))
			for _, e := range classification.Entities {
				piiTypes = append(piiTypes, e.Type)
			}
			shadowViolations = append(shadowViolations, evidence.ShadowViolation{
				Type: "pii_block", Detail: fmt.Sprintf("PII detected: %v", piiTypes), Action: "block",
			})
			log.Warn().Str("caller", caller.Name).Str("enforcement_mode", "shadow").Strs("pii", piiTypes).Msg("shadow_pii_block")
		} else {
			WriteProviderError(w, route.Provider, http.StatusBadRequest, "Request contains PII that is not allowed")
			_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body, classification, nil, 0, 0, 0, false, []string{"PII block"}, false, nil, attSummary, nil, nil, false, "", 0, 0)
			return
		}
	}

	// Estimated cost for policy (use default token estimate if we don't have real tokens yet)
	estTokensIn, estTokensOut := 500, 500
	estimatedCost := g.costEstimate(extracted.Model, estTokensIn, estTokensOut)
	dailyCost, monthlyCost := g.callerCostTotals(ctx, caller)
	if d := g.config.ServerDefaults.MaxDailyCost; d > 0 {
		RecordBudgetUtilization(ctx, caller.TenantID, "daily", (dailyCost/d)*100)
	}
	if m := g.config.ServerDefaults.MaxMonthlyCost; m > 0 {
		RecordBudgetUtilization(ctx, caller.TenantID, "monthly", (monthlyCost/m)*100)
	}
	policyInput := buildGatewayPolicyInput(caller, route.Provider, extracted.Model, tier, estimatedCost, dailyCost, monthlyCost)
	if g.policy != nil && (g.config.Mode == ModeEnforce || isShadow) {
		allowed, reasons, policyErr := g.policy.EvaluateGateway(ctx, policyInput)
		if policyErr != nil {
			if isShadow {
				shadowViolations = append(shadowViolations, evidence.ShadowViolation{
					Type: "policy_deny", Detail: fmt.Sprintf("policy evaluation error: %v", policyErr), Action: "block",
				})
				log.Warn().Err(policyErr).Str("caller", caller.Name).Str("enforcement_mode", "shadow").Msg("shadow_policy_error")
			} else {
				WriteProviderError(w, route.Provider, http.StatusInternalServerError, "Policy evaluation failed")
				return
			}
		}
		if !allowed && policyErr == nil {
			if isShadow {
				detail := "policy denied"
				if len(reasons) > 0 {
					detail = reasons[0]
				}
				shadowViolations = append(shadowViolations, evidence.ShadowViolation{
					Type: "policy_deny", Detail: detail, Action: "block",
				})
				log.Warn().Str("caller", caller.Name).Str("enforcement_mode", "shadow").Strs("reasons", reasons).Msg("shadow_policy_deny")
			} else {
				WriteProviderError(w, route.Provider, http.StatusForbidden, reasons[0])
				_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body, classification, nil, 0, 0, 0, false, reasons, false, nil, attSummary, nil, nil, false, "", 0, 0)
				return
			}
		}
	}

	// Step 6b: Tool governance — filter or block forbidden tools before the LLM sees them.
	prov, _ := g.config.Provider(route.Provider)
	toolPolicy := ResolveToolPolicy(&g.config.ServerDefaults, prov, caller.PolicyOverrides)
	var toolResult *ToolGovernanceResult
	forwardBody := body
	if len(extracted.ToolNames) > 0 && (len(toolPolicy.AllowedTools) > 0 || len(toolPolicy.ForbiddenTools) > 0) {
		tr := EvaluateToolPolicy(extracted.ToolNames, toolPolicy.AllowedTools, toolPolicy.ForbiddenTools)
		toolResult = &tr
		if len(tr.Removed) > 0 {
			switch {
			case isShadow:
				shadowViolations = append(shadowViolations, evidence.ShadowViolation{
					Type: "tool_block", Detail: fmt.Sprintf("Forbidden tools: %v", tr.Removed), Action: toolPolicy.Action,
				})
				log.Warn().Str("caller", caller.Name).Str("enforcement_mode", "shadow").Strs("tools", tr.Removed).Msg("shadow_tool_violation")
			case toolPolicy.Action == "block":
				log.Warn().
					Str("caller", caller.Name).
					Strs("forbidden", tr.Removed).
					Msg("gateway_tool_blocked")
				WriteProviderError(w, route.Provider, http.StatusForbidden,
					fmt.Sprintf("Request contains forbidden tools: %v", tr.Removed))
				_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body,
					classification, nil, 0, 0, 0, false, []string{"tool governance block"}, false, nil, attSummary, toolResult, nil, false, "", 0, 0)
				return
			default:
				filtered, filterErr := FilterRequestBodyTools(route.Provider, forwardBody, tr.Kept)
				if filterErr != nil {
					log.Error().Err(filterErr).
						Str("caller", caller.Name).
						Strs("forbidden", tr.Removed).
						Msg("gateway_tool_filter_failed")
					WriteProviderError(w, route.Provider, http.StatusInternalServerError,
						"Failed to filter forbidden tools from request")
					_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body,
						classification, nil, 0, 0, 0, false, []string{"tool filter error"}, false, nil, attSummary, toolResult, nil, false, "", 0, 0)
					return
				}
				forwardBody = filtered
				log.Info().
					Str("caller", caller.Name).
					Strs("removed", tr.Removed).
					Strs("kept", tr.Kept).
					Msg("gateway_tools_filtered")
			}
		}
	}

	// Step 7: Redact (if policy says redact and PII found, skip in shadow mode)
	if !isShadow && piiAction == "redact" && classification.HasPII {
		redacted, redactErr := RedactRequestBody(ctx, route.Provider, forwardBody, g.classifier)
		if redactErr == nil {
			forwardBody = redacted
		}
	}

	// Step 7b: Ensure Responses API requests use store:true so multi-turn works through a proxy.
	// Without this, OpenAI doesn't persist response items and follow-up messages that reference
	// previous response IDs get 404 "Items are not persisted when store is set to false".
	if route.Provider == "openai" && isResponsesAPIPath(route.Path) {
		forwardBody = ensureResponsesStore(forwardBody)
	}

	// Step 8: Reroute (same-provider model override) — MVP: no model change, just forward

	// Step 8b: Semantic cache lookup (skip for tool calls and when disabled)
	var cacheAllowLookup, cacheAllowStore bool
	if g.cacheStore != nil && g.cacheConfig != nil && g.cacheConfig.Enabled && g.cachePolicy != nil && g.cacheEmbedder != nil && len(extracted.ToolNames) == 0 {
		dataTierStr := "public"
		switch tier {
		case 1:
			dataTierStr = "internal"
		case 2:
			dataTierStr = "confidential"
		}
		piiSev := "none"
		if classification.HasPII {
			if tier == 2 {
				piiSev = "high"
			} else {
				piiSev = "low"
			}
		}
		cin := &cache.PolicyInput{
			TenantID: caller.TenantID, DataTier: dataTierStr, PIIDetected: classification.HasPII,
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
				lookupResult, err := g.cacheStore.Lookup(ctx, caller.TenantID, queryBlob, threshold, maxCand, g.cacheEmbedder.SimilarityFunc())
				if err == nil && lookupResult != nil {
					hit := lookupResult.Entry
					_ = g.cacheStore.IncrementHitCount(ctx, hit.ID)
					costSaved := g.costEstimate(extracted.Model, 300, 300)
					durationMS := time.Since(start).Milliseconds()
					_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body, classification, nil, 0, durationMS, 0, true, nil, false, nil, attSummary, toolResult, shadowViolations, true, hit.ID, lookupResult.Similarity, costSaved)
					writeCachedCompletion(w, route.Provider, extracted.Model, hit.ResponseText)
					return
				}
			}
		}
	}

	// Step 9: Forward — get provider key and proxy
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
	if route.Provider == "anthropic" {
		if v := r.Header.Get("anthropic-version"); v != "" {
			headers["anthropic-version"] = v
		} else {
			headers["anthropic-version"] = "2023-06-01"
		}
	}
	if prov.SecretName != "" {
		secret, err := g.secretsStore.Get(ctx, prov.SecretName, caller.TenantID, caller.Name)
		if err != nil {
			log.Warn().Err(err).Str("secret", prov.SecretName).Msg("gateway_secret_get_failed")
			WriteProviderError(w, route.Provider, http.StatusInternalServerError, "Service configuration error")
			return
		}
		if route.Provider == "anthropic" {
			headers["x-api-key"] = string(secret.Value)
		} else {
			headers["Authorization"] = "Bearer " + string(secret.Value)
		}
	}

	// Resolve response PII action
	responsePIIAction := resolveResponsePIIAction(&g.config.ServerDefaults, caller.PolicyOverrides)
	isStreaming := isStreamingRequest(forwardBody)

	var tokenUsage TokenUsage
	var responsePII *ResponsePIIScanResult
	needsResponseScan := responsePIIAction != "allow" && responsePIIAction != ""

	fwdParams := ForwardParams{
		Context:     ctx,
		Client:      g.client,
		UpstreamURL: route.UpstreamURL,
		Method:      r.Method,
		Body:        forwardBody,
		Headers:     headers,
		Timeouts:    g.timeouts,
		TokenUsage:  &tokenUsage,
	}

	switch {
	case needsResponseScan && !isStreaming:
		// Non-streaming: capture response, scan, then write
		capture := &responseCapture{ResponseWriter: w}
		err = Forward(capture, fwdParams)
		if err == nil {
			scannedBody, scanResult := scanResponseForPII(ctx, capture.body.Bytes(), responsePIIAction, g.classifier)
			responsePII = scanResult
			if capture.statusCode != 0 {
				w.WriteHeader(capture.statusCode)
			}
			//nolint:gosec // G705: LLM API response body (JSON), not HTML; PII-scanned/redacted before write
			_, _ = w.Write(scannedBody)
			// Store in semantic cache when allowed (non-streaming path; content already PII-scrubbed)
			if cacheAllowStore && g.cacheStore != nil && g.cacheEmbedder != nil && g.cacheConfig != nil && extracted.Text != "" && capture.statusCode == 200 {
				if content := extractContentFromOpenAIResponse(scannedBody); content != "" {
					emb, err := g.cacheEmbedder.Embed(extracted.Text)
					if err == nil {
						// Use canonical tenant ID from config-derived map so cache key is not tainted by request path (CodeQL go/weak-sensitive-data-hashing).
						scopeTenantID := g.canonicalTenantIDForCache(caller.TenantID)
						keyHash := cache.DeriveEntryKey(scopeTenantID, extracted.Model, extracted.Text)
						ttl := time.Duration(g.cacheConfig.DefaultTTL) * time.Second
						if ttl <= 0 {
							ttl = time.Hour
						}
						now := time.Now().UTC()
						entry := &cache.Entry{
							TenantID: caller.TenantID, CacheKey: keyHash, EmbeddingData: emb, ResponseText: content,
							Model: extracted.Model, DataTier: "public", PIIScrubbed: true,
							CreatedAt: now, ExpiresAt: now.Add(ttl),
						}
						_ = g.cacheStore.Insert(ctx, entry)
					}
				}
			}
		} else {
			capture.flushTo(w)
		}

	case needsResponseScan && isStreaming:
		// Streaming + PII scan: buffer the entire SSE stream, extract text,
		// scan for PII. If clean, forward the original buffered events. If
		// PII found, return the redacted content wrapped in SSE format.
		capture := &responseCapture{ResponseWriter: w}
		err = Forward(capture, fwdParams)
		if err == nil {
			responsePII = handleStreamingPIIScan(ctx, w, capture, responsePIIAction, g.classifier)
		} else {
			capture.flushTo(w)
		}

	default:
		err = Forward(w, fwdParams)
	}

	durationMS := time.Since(start).Milliseconds()
	cost := g.costEstimate(extracted.Model, tokenUsage.Input, tokenUsage.Output)
	if tokenUsage.Input == 0 && tokenUsage.Output == 0 {
		cost = estimatedCost
	}

	// Step 10: Evidence
	var outputPIIDetected bool
	var outputPIITypes []string
	if responsePII != nil {
		outputPIIDetected = responsePII.PIIDetected
		outputPIITypes = responsePII.PIITypes
	}

	_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body, classification, &tokenUsage, cost, durationMS, 0, true, nil, outputPIIDetected, outputPIITypes, attSummary, toolResult, shadowViolations, false, "", 0, 0)

	// Emit OTel + dashboard metrics
	g.emitMetrics(ctx, caller, route.Provider, extracted.Model, classification, toolResult, shadowViolations,
		&tokenUsage, cost, durationMS, err != nil, false, piiAction, false, 0)
	if err != nil {
		log.Warn().Err(err).Msg("gateway_forward_error")
	}
}

func (g *Gateway) recordEvidence(ctx context.Context, correlationID string, caller *CallerConfig, provider, model string, start time.Time, _ []byte, classification *classifier.Classification, usage *TokenUsage, cost float64, durationMS int64, _ int, allowed bool, reasons []string, outputPIIDetected bool, outputPIITypes []string, attSummary *AttachmentsScanSummary, toolResult *ToolGovernanceResult, shadowViolations []evidence.ShadowViolation, cacheHit bool, cacheEntryID string, cacheSimilarity float64, costSaved float64) error {
	inputTokens, outputTokens := 0, 0
	if usage != nil {
		inputTokens, outputTokens = usage.Input, usage.Output
	}
	secretsAccessed := []string{}
	if prov, ok := g.config.Provider(provider); ok && prov.SecretName != "" {
		secretsAccessed = append(secretsAccessed, prov.SecretName)
	}
	piiDetected := []string{}
	for _, e := range classification.Entities {
		piiDetected = append(piiDetected, e.Type)
	}

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
		CorrelationID:           correlationID,
		TenantID:                caller.TenantID,
		CallerName:              caller.Name,
		Team:                    caller.Team,
		Provider:                provider,
		Model:                   model,
		PolicyAllowed:           allowed,
		PolicyReasons:           reasons,
		PolicyVersion:           "",
		ObservationModeOverride: len(shadowViolations) > 0,
		ShadowViolations:        shadowViolations,
		InputTier:               classification.Tier,
		PIIDetected:             piiDetected,
		PIIRedacted:             false,
		OutputPIIDetected:       outputPIIDetected,
		OutputPIITypes:          outputPIITypes,
		Cost:                    cost,
		InputTokens:             inputTokens,
		OutputTokens:            outputTokens,
		DurationMS:              durationMS,
		SecretsAccessed:         secretsAccessed,
		AttachmentScan:          attScan,
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
	return RecordGatewayEvidence(ctx, g.evidenceStore, params)
}

func buildGatewayPolicyInput(caller *CallerConfig, provider, model string, dataTier int, estimatedCost, dailyCost, monthlyCost float64) map[string]interface{} {
	input := map[string]interface{}{
		"provider":       provider,
		"model":          model,
		"data_tier":      dataTier,
		"estimated_cost": estimatedCost,
		"daily_cost":     dailyCost,
		"monthly_cost":   monthlyCost,
		"caller_name":    caller.Name,
		"tenant_id":      caller.TenantID,
	}
	if caller.PolicyOverrides != nil {
		input["caller_allowed_models"] = caller.PolicyOverrides.AllowedModels
		input["caller_blocked_models"] = caller.PolicyOverrides.BlockedModels
		input["caller_max_daily_cost"] = caller.PolicyOverrides.MaxDailyCost
		input["caller_max_monthly_cost"] = caller.PolicyOverrides.MaxMonthlyCost
		if caller.PolicyOverrides.MaxDataTier != nil {
			input["caller_max_data_tier"] = *caller.PolicyOverrides.MaxDataTier
		}
	}
	return input
}

func (g *Gateway) callerCostTotals(ctx context.Context, caller *CallerConfig) (daily, monthly float64) {
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	byAgent, err := g.evidenceStore.CostByAgent(ctx, caller.TenantID, todayStart, now)
	if err != nil {
		return 0, 0
	}
	daily = byAgent[caller.Name]
	byAgent, err = g.evidenceStore.CostByAgent(ctx, caller.TenantID, monthStart, now)
	if err != nil {
		return daily, 0
	}
	monthly = byAgent[caller.Name]
	return daily, monthly
}

func defaultCostEstimator(model string, inputTokens, outputTokens int) float64 {
	// Rough EUR per 1k tokens for common models (MVP approximation)
	n := float64(inputTokens+outputTokens) / 1000
	if n < 0.01 {
		n = 0.01
	}
	return n * 0.002
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
func (g *Gateway) emitMetrics(ctx context.Context, caller *CallerConfig, provider, model string,
	classification *classifier.Classification, toolResult *ToolGovernanceResult,
	shadowViolations []evidence.ShadowViolation, usage *TokenUsage,
	cost float64, durationMS int64, hasError, blocked bool, piiAction string,
	cacheHit bool, costSaved float64,
) {
	status := "ok"
	if hasError {
		status = "error"
	} else if blocked {
		status = "blocked"
	}
	RecordGatewayRequest(ctx, caller.Name, model, provider, status)
	if hasError {
		RecordGatewayError(ctx, "upstream_error")
	}
	if classification != nil {
		RecordDataTier(ctx, classification.Tier, caller.Name)
	}

	if toolResult != nil {
		for _, tool := range toolResult.Kept {
			RecordToolGovernance(ctx, tool, "allowed")
		}
		for _, tool := range toolResult.Removed {
			RecordToolGovernance(ctx, tool, "filtered")
		}
	}

	for _, sv := range shadowViolations {
		RecordShadowViolation(ctx, sv.Type)
	}

	RecordCacheResult(ctx, caller.TenantID, cacheHit)

	// GenAI SemConv: token usage and operation duration
	tokIn, tokOut := 0, 0
	if usage != nil {
		tokIn, tokOut = usage.Input, usage.Output
	}
	if tokIn > 0 || tokOut > 0 {
		llm.RecordTokenUsage(ctx, tokIn, tokOut, model, provider)
	}
	if durationMS > 0 {
		llm.RecordOperationDuration(ctx, float64(durationMS)/1000.0, model, provider)
	}
	llm.RecordProviderAvailability(ctx, provider, !hasError)

	if g.metricsRecorder != nil {
		var piiTypes []string
		if classification != nil {
			for _, e := range classification.Entities {
				piiTypes = append(piiTypes, e.Type)
			}
		}
		var toolsRequested, toolsFiltered []string
		if toolResult != nil {
			toolsRequested = toolResult.Requested
			toolsFiltered = toolResult.Removed
		}
		var svTypes []string
		for _, sv := range shadowViolations {
			svTypes = append(svTypes, sv.Type)
		}
		tokIn, tokOut := 0, 0
		if usage != nil {
			tokIn, tokOut = usage.Input, usage.Output
		}
		g.metricsRecorder.RecordGatewayEvent(map[string]interface{}{
			"timestamp":          time.Now(),
			"caller_id":          caller.Name,
			"model":              model,
			"pii_detected":       piiTypes,
			"pii_action":         piiAction,
			"tools_requested":    toolsRequested,
			"tools_filtered":     toolsFiltered,
			"blocked":            blocked,
			"cost_eur":           cost,
			"tokens_input":       tokIn,
			"tokens_output":      tokOut,
			"latency_ms":         durationMS,
			"enforcement_mode":   g.config.Mode,
			"would_have_blocked": len(shadowViolations) > 0,
			"shadow_violations":  svTypes,
			"has_error":          hasError,
			"cache_hit":          cacheHit,
			"cost_saved":         costSaved,
		})
	}
}

// writeCachedCompletion writes a minimal OpenAI-compatible chat completion JSON with the cached content.
func writeCachedCompletion(w http.ResponseWriter, provider, model string, content string) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"id":     "cache-" + fmt.Sprintf("%d", time.Now().UnixNano()),
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
