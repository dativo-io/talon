package gateway

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

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
	return &Gateway{
		config:        config,
		classifier:    classifier,
		evidenceStore: evidenceStore,
		secretsStore:  secretsStore,
		policy:        policy,
		costEstimate:  costEstimate,
		timeouts:      timeouts,
		client:        client,
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

	// Step 6: Evaluate policy (skip in log_only; in shadow we log but don't block)
	piiAction := g.config.DefaultPolicy.DefaultPIIAction
	if caller.PolicyOverrides != nil && caller.PolicyOverrides.PIIAction != "" {
		piiAction = caller.PolicyOverrides.PIIAction
	}
	if piiAction == "block" && classification.HasPII {
		WriteProviderError(w, route.Provider, http.StatusBadRequest, "Request contains PII that is not allowed")
		_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body, classification, nil, 0, 0, 0, false, []string{"PII block"})
		return
	}

	// Estimated cost for policy (use default token estimate if we don't have real tokens yet)
	estTokensIn, estTokensOut := 500, 500
	estimatedCost := g.costEstimate(extracted.Model, estTokensIn, estTokensOut)
	dailyCost, monthlyCost := g.callerCostTotals(ctx, caller)
	policyInput := buildGatewayPolicyInput(caller, route.Provider, extracted.Model, tier, estimatedCost, dailyCost, monthlyCost)
	if g.policy != nil && g.config.Mode == ModeEnforce {
		allowed, reasons, err := g.policy.EvaluateGateway(ctx, policyInput)
		if err != nil {
			WriteProviderError(w, route.Provider, http.StatusInternalServerError, "Policy evaluation failed")
			return
		}
		if !allowed {
			WriteProviderError(w, route.Provider, http.StatusForbidden, reasons[0])
			_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body, classification, nil, 0, 0, 0, false, reasons)
			return
		}
	}

	// Step 7: Redact (if policy says redact and PII found)
	forwardBody := body
	if piiAction == "redact" && classification.HasPII {
		redacted, err := RedactRequestBody(ctx, route.Provider, body, g.classifier)
		if err == nil {
			forwardBody = redacted
		}
	}

	// Step 8: Reroute (same-provider model override) — MVP: no model change, just forward

	// Step 9: Forward — get provider key and proxy
	prov, _ := g.config.Provider(route.Provider)
	headers := make(map[string]string)
	for k, v := range r.Header {
		if k == "Authorization" || k == "X-Api-Key" || k == "X-Request-Id" {
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

	var tokenUsage TokenUsage
	err = Forward(w, ForwardParams{
		Context:     ctx,
		Client:      g.client,
		UpstreamURL: route.UpstreamURL,
		Method:      r.Method,
		Body:        forwardBody,
		Headers:     headers,
		Timeouts:    g.timeouts,
		TokenUsage:  &tokenUsage,
	})
	durationMS := time.Since(start).Milliseconds()
	cost := g.costEstimate(extracted.Model, tokenUsage.Input, tokenUsage.Output)
	if tokenUsage.Input == 0 && tokenUsage.Output == 0 {
		cost = estimatedCost
	}

	// Step 10: Evidence (async for streaming we'd do after stream ends; here we do after forward returns)
	_ = g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, body, classification, &tokenUsage, cost, durationMS, 0, true, nil)
	if err != nil {
		log.Warn().Err(err).Msg("gateway_forward_error")
	}
}

func (g *Gateway) recordEvidence(ctx context.Context, correlationID string, caller *CallerConfig, provider, model string, start time.Time, _ []byte, classification *classifier.Classification, usage *TokenUsage, cost float64, durationMS int64, _ int, allowed bool, reasons []string) error {
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
	return RecordGatewayEvidence(ctx, g.evidenceStore, RecordGatewayEvidenceParams{
		CorrelationID:   correlationID,
		TenantID:        caller.TenantID,
		CallerName:      caller.Name,
		Team:            caller.Team,
		Provider:        provider,
		Model:           model,
		PolicyAllowed:   allowed,
		PolicyReasons:   reasons,
		PolicyVersion:   "",
		InputTier:       classification.Tier,
		PIIDetected:     piiDetected,
		PIIRedacted:     false,
		Cost:            cost,
		InputTokens:     inputTokens,
		OutputTokens:    outputTokens,
		DurationMS:      durationMS,
		SecretsAccessed: secretsAccessed,
	})
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
