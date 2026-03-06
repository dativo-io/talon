// Package cache policy evaluates OPA cache eligibility (lookup and store).
package cache

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

//go:embed rego/*.rego
var embedRego embed.FS

// PolicyInput is the input to the cache eligibility Rego policy.
type PolicyInput struct {
	TenantID     string `json:"tenant_id"`
	DataTier     string `json:"data_tier"`    // public | internal | confidential | restricted
	PIIDetected  bool   `json:"pii_detected"` // from classifier pre-scan
	PIISeverity  string `json:"pii_severity"` // none | low | high
	Model        string `json:"model"`
	RequestType  string `json:"request_type"`  // completion | embedding | tool_call
	CacheEnabled bool   `json:"cache_enabled"` // from tenant/config
}

// PolicyResult is the result of cache policy evaluation.
type PolicyResult struct {
	AllowLookup bool `json:"allow_lookup"`
	AllowStore  bool `json:"allow_store"`
}

// Evaluator evaluates cache eligibility policy.
type Evaluator struct {
	query rego.PreparedEvalQuery
}

// NewEvaluator compiles the embedded cache.rego and returns an evaluator.
func NewEvaluator(ctx context.Context) (*Evaluator, error) {
	content, err := embedRego.ReadFile("rego/cache.rego")
	if err != nil {
		return nil, fmt.Errorf("reading cache.rego: %w", err)
	}
	r := rego.New(
		rego.Query("data.talon.cache.allow_lookup; data.talon.cache.allow_store"),
		rego.Module("cache.rego", string(content)),
	)
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("preparing cache policy: %w", err)
	}
	return &Evaluator{query: prepared}, nil
}

// Evaluate returns whether cache lookup and store are allowed for the input.
func (e *Evaluator) Evaluate(ctx context.Context, input *PolicyInput) (*PolicyResult, error) {
	in := map[string]interface{}{
		"tenant_id":     input.TenantID,
		"data_tier":     input.DataTier,
		"pii_detected":  input.PIIDetected,
		"pii_severity":  input.PIISeverity,
		"model":         input.Model,
		"request_type":  input.RequestType,
		"cache_enabled": input.CacheEnabled,
	}
	results, err := e.query.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return nil, fmt.Errorf("evaluating cache policy: %w", err)
	}
	out := &PolicyResult{}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return out, nil
	}
	// Query returns two values: allow_lookup, allow_store (array or object)
	exprs := results[0].Expressions
	if len(exprs) >= 2 {
		if b, ok := exprs[0].Value.(bool); ok {
			out.AllowLookup = b
		}
		if b, ok := exprs[1].Value.(bool); ok {
			out.AllowStore = b
		}
		return out, nil
	}
	// Single expression might be an array [allow_lookup, allow_store]
	if arr, ok := exprs[0].Value.([]interface{}); ok && len(arr) >= 2 {
		if b, ok := arr[0].(bool); ok {
			out.AllowLookup = b
		}
		if b, ok := arr[1].(bool); ok {
			out.AllowStore = b
		}
	}
	return out, nil
}

// EvaluateMap evaluates with a map input (for callers that build input from JSON).
func (e *Evaluator) EvaluateMap(ctx context.Context, input map[string]interface{}) (*PolicyResult, error) {
	results, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("evaluating cache policy: %w", err)
	}
	out := &PolicyResult{}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return out, nil
	}
	exprs := results[0].Expressions
	if len(exprs) >= 2 {
		if b, ok := exprs[0].Value.(bool); ok {
			out.AllowLookup = b
		}
		if b, ok := exprs[1].Value.(bool); ok {
			out.AllowStore = b
		}
	}
	return out, nil
}

// InputToMap converts PolicyInput to a map for Rego.
func InputToMap(in *PolicyInput) map[string]interface{} {
	b, _ := json.Marshal(in)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	return m
}
