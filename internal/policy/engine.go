package policy

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

//go:embed rego/*.rego
var embeddedPolicies embed.FS

// Decision represents the result of policy evaluation.
type Decision struct {
	Allowed       bool     `json:"allowed"`
	Action        string   `json:"action"` // "allow" or "deny"
	Reasons       []string `json:"reasons,omitempty"`
	PolicyVersion string   `json:"policy_version"`
}

// regoPolicy maps a Rego file to the OPA query used to extract deny messages.
type regoPolicy struct {
	file  string
	query string
}

// allPolicies defines the Rego files and the query path for each.
var allPolicies = []regoPolicy{
	{file: "rego/cost_limits.rego", query: "data.talon.policy.cost_limits.deny"},
	{file: "rego/rate_limits.rego", query: "data.talon.policy.rate_limits.deny"},
	{file: "rego/time_restrictions.rego", query: "data.talon.policy.time_restrictions.deny"},
	{file: "rego/tool_access.rego", query: "data.talon.policy.tool_access.deny"},
	{file: "rego/secret_access.rego", query: "data.talon.policy.secret_access.deny"},
	{file: "rego/memory_governance.rego", query: "data.talon.policy.memory_governance.deny"},
	{file: "rego/data_classification.rego", query: "data.talon.policy.data_classification.tier"},
}

// Engine evaluates governance policies using embedded OPA.
type Engine struct {
	policy   *Policy
	prepared map[string]rego.PreparedEvalQuery
}

// NewEngine creates a policy engine with precompiled Rego policies.
// The provided Policy is serialized to JSON and loaded as OPA data.
func NewEngine(ctx context.Context, pol *Policy) (*Engine, error) {
	ctx, span := tracer.Start(ctx, "policy.engine.new")
	defer span.End()

	// Convert Policy struct to a generic map for OPA data store.
	policyData, err := policyToData(pol)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("converting policy to OPA data: %w", err)
	}

	prepared := make(map[string]rego.PreparedEvalQuery, len(allPolicies))

	for _, rp := range allPolicies {
		content, err := embeddedPolicies.ReadFile(rp.file)
		if err != nil {
			return nil, fmt.Errorf("reading embedded policy %s: %w", rp.file, err)
		}

		store := inmem.NewFromObject(map[string]interface{}{
			"policy": policyData,
		})

		r := rego.New(
			rego.Query(rp.query),
			rego.Module(rp.file, string(content)),
			rego.Store(store),
		)

		preparedQuery, err := r.PrepareForEval(ctx)
		if err != nil {
			return nil, fmt.Errorf("preparing Rego policy %s: %w", rp.file, err)
		}

		prepared[rp.file] = preparedQuery
	}

	span.SetAttributes(attribute.Int("policy.prepared_count", len(prepared)))

	return &Engine{
		policy:   pol,
		prepared: prepared,
	}, nil
}

// Evaluate runs the core governance policies (cost, rate, time) and
// returns a combined Decision.
func (e *Engine) Evaluate(ctx context.Context, input map[string]interface{}) (*Decision, error) {
	ctx, span := tracer.Start(ctx, "policy.evaluate",
		trace.WithAttributes(
			attribute.String("policy.version", e.policy.VersionTag),
		))
	defer span.End()

	decision := &Decision{
		Allowed:       true,
		Action:        "allow",
		PolicyVersion: e.policy.VersionTag,
	}

	corePolicies := []string{
		"rego/cost_limits.rego",
		"rego/rate_limits.rego",
		"rego/time_restrictions.rego",
	}

	for _, pkg := range corePolicies {
		reasons, err := e.evaluateDenyPolicy(ctx, pkg, input)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		decision.Reasons = append(decision.Reasons, reasons...)
	}

	if len(decision.Reasons) > 0 {
		decision.Allowed = false
		decision.Action = "deny"
	}

	span.SetAttributes(
		attribute.Bool("policy.allowed", decision.Allowed),
		attribute.Int("policy.deny_reasons", len(decision.Reasons)),
	)
	if decision.Allowed {
		span.SetStatus(codes.Ok, "policy evaluation passed")
	}

	return decision, nil
}

// EvaluateToolAccess checks whether the given tool call is allowed.
func (e *Engine) EvaluateToolAccess(ctx context.Context, toolName string, params map[string]interface{}) (*Decision, error) {
	ctx, span := tracer.Start(ctx, "policy.evaluate_tool_access",
		trace.WithAttributes(
			attribute.String("tool.name", toolName),
		))
	defer span.End()

	input := map[string]interface{}{
		"tool_name": toolName,
		"params":    params,
	}

	decision := &Decision{
		Allowed:       true,
		Action:        "allow",
		PolicyVersion: e.policy.VersionTag,
	}

	reasons, err := e.evaluateDenyPolicy(ctx, "rego/tool_access.rego", input)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	decision.Reasons = append(decision.Reasons, reasons...)

	if len(decision.Reasons) > 0 {
		decision.Allowed = false
		decision.Action = "deny"
	}

	span.SetAttributes(
		attribute.Bool("policy.allowed", decision.Allowed),
		attribute.Int("policy.deny_reasons", len(decision.Reasons)),
	)
	if decision.Allowed {
		span.SetStatus(codes.Ok, "policy evaluation passed")
	}

	return decision, nil
}

// EvaluateSecretAccess checks whether access to the named secret is allowed.
func (e *Engine) EvaluateSecretAccess(ctx context.Context, secretName string) (*Decision, error) {
	ctx, span := tracer.Start(ctx, "policy.evaluate_secret_access",
		trace.WithAttributes(
			attribute.String("secret.name", secretName),
		))
	defer span.End()

	input := map[string]interface{}{
		"secret_name": secretName,
	}

	decision := &Decision{
		Allowed:       true,
		Action:        "allow",
		PolicyVersion: e.policy.VersionTag,
	}

	reasons, err := e.evaluateDenyPolicy(ctx, "rego/secret_access.rego", input)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	decision.Reasons = append(decision.Reasons, reasons...)

	if len(decision.Reasons) > 0 {
		decision.Allowed = false
		decision.Action = "deny"
	}

	span.SetAttributes(
		attribute.Bool("policy.allowed", decision.Allowed),
		attribute.Int("policy.deny_reasons", len(decision.Reasons)),
	)
	if decision.Allowed {
		span.SetStatus(codes.Ok, "policy evaluation passed")
	}

	return decision, nil
}

// EvaluateMemoryWrite checks whether a memory write is allowed by governance rules.
func (e *Engine) EvaluateMemoryWrite(ctx context.Context, category string, contentSizeBytes int) (*Decision, error) {
	ctx, span := tracer.Start(ctx, "policy.evaluate_memory_write",
		trace.WithAttributes(
			attribute.String("memory.category", category),
			attribute.Int("memory.content_size_bytes", contentSizeBytes),
		))
	defer span.End()

	input := map[string]interface{}{
		"category":           category,
		"content_size_bytes": contentSizeBytes,
	}

	decision := &Decision{
		Allowed:       true,
		Action:        "allow",
		PolicyVersion: e.policy.VersionTag,
	}

	reasons, err := e.evaluateDenyPolicy(ctx, "rego/memory_governance.rego", input)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	decision.Reasons = append(decision.Reasons, reasons...)

	if len(decision.Reasons) > 0 {
		decision.Allowed = false
		decision.Action = "deny"
	}

	span.SetAttributes(
		attribute.Bool("policy.allowed", decision.Allowed),
		attribute.Int("policy.deny_reasons", len(decision.Reasons)),
	)
	if decision.Allowed {
		span.SetStatus(codes.Ok, "policy evaluation passed")
	}

	return decision, nil
}

// EvaluateDataClassification returns the data tier (0, 1, or 2) for the given input.
func (e *Engine) EvaluateDataClassification(ctx context.Context, input map[string]interface{}) (int, error) {
	ctx, span := tracer.Start(ctx, "policy.evaluate_data_classification")
	defer span.End()

	prepared, ok := e.prepared["rego/data_classification.rego"]
	if !ok {
		return 0, fmt.Errorf("data classification policy not prepared")
	}

	results, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		span.RecordError(err)
		return 0, fmt.Errorf("evaluating data classification: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return 0, nil
	}

	tierVal, ok := results[0].Expressions[0].Value.(json.Number)
	if ok {
		tier, err := tierVal.Int64()
		if err != nil {
			return 0, fmt.Errorf("parsing tier value: %w", err)
		}
		return int(tier), nil
	}

	// OPA may return as float64 depending on context
	if tierFloat, ok := results[0].Expressions[0].Value.(float64); ok {
		return int(tierFloat), nil
	}

	return 0, nil
}

// evaluateDenyPolicy runs a single Rego policy that produces a set of deny messages.
func (e *Engine) evaluateDenyPolicy(ctx context.Context, pkg string, input map[string]interface{}) ([]string, error) {
	prepared, ok := e.prepared[pkg]
	if !ok {
		return nil, fmt.Errorf("policy package %s not prepared", pkg)
	}

	results, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("evaluating %s: %w", pkg, err)
	}

	var reasons []string
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return nil, nil
	}

	// The result of querying "data.xxx.deny" is a set of strings.
	// OPA returns it as []interface{}.
	exprVal := results[0].Expressions[0].Value
	switch v := exprVal.(type) {
	case []interface{}:
		for _, msg := range v {
			if msgStr, ok := msg.(string); ok {
				reasons = append(reasons, msgStr)
			}
		}
	case map[string]interface{}:
		// OPA sometimes returns sets as maps with string keys
		for _, msg := range v {
			if msgStr, ok := msg.(string); ok {
				reasons = append(reasons, msgStr)
			}
		}
	}

	return reasons, nil
}

// policyToData converts a Policy struct to map[string]interface{} for OPA.
// We marshal to JSON then unmarshal to get clean map types.
func policyToData(pol *Policy) (map[string]interface{}, error) {
	jsonBytes, err := json.Marshal(pol)
	if err != nil {
		return nil, fmt.Errorf("marshalling policy: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return nil, fmt.Errorf("unmarshalling policy data: %w", err)
	}

	return data, nil
}
