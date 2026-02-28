package gateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
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

	return &Gateway{
		config:        config,
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
				[]string{"attachment policy block"}, false, nil, attSummary, nil, nil)
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
			_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body, classification, nil, 0, 0, 0, false, []string{"PII block"}, false, nil, attSummary, nil, nil)
			return
		}
	}

	// Estimated cost for policy (use default token estimate if we don't have real tokens yet)
	estTokensIn, estTokensOut := 500, 500
	estimatedCost := g.costEstimate(extracted.Model, estTokensIn, estTokensOut)
	dailyCost, monthlyCost := g.callerCostTotals(ctx, caller)
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
				_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body, classification, nil, 0, 0, 0, false, reasons, false, nil, attSummary, nil, nil)
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
					classification, nil, 0, 0, 0, false, []string{"tool governance block"}, false, nil, attSummary, toolResult, nil)
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
						classification, nil, 0, 0, 0, false, []string{"tool filter error"}, false, nil, attSummary, toolResult, nil)
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

	_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body, classification, &tokenUsage, cost, durationMS, 0, true, nil, outputPIIDetected, outputPIITypes, attSummary, toolResult, shadowViolations)
	if err != nil {
		log.Warn().Err(err).Msg("gateway_forward_error")
	}
}

func (g *Gateway) recordEvidence(ctx context.Context, correlationID string, caller *CallerConfig, provider, model string, start time.Time, _ []byte, classification *classifier.Classification, usage *TokenUsage, cost float64, durationMS int64, _ int, allowed bool, reasons []string, outputPIIDetected bool, outputPIITypes []string, attSummary *AttachmentsScanSummary, toolResult *ToolGovernanceResult, shadowViolations []evidence.ShadowViolation) error {
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
