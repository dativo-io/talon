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
	{file: "rego/resource_limits.rego", query: "data.talon.policy.resource_limits.deny"},
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

	policyData, err := policyToData(pol)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("converting policy to OPA data: %w", err)
	}

	prepared, err := prepareRegoQueries(ctx, allPolicies, map[string]interface{}{
		"policy": policyData,
	})
	if err != nil {
		return nil, err
	}

	span.SetAttributes(attribute.Int("policy.prepared_count", len(prepared)))

	return &Engine{
		policy:   pol,
		prepared: prepared,
	}, nil
}

// prepareRegoQueries initializes OPA prepared queries for a given set of
// policies. This is shared between Engine and ProxyEngine.
func prepareRegoQueries(ctx context.Context, policies []regoPolicy, opaData map[string]interface{}) (map[string]rego.PreparedEvalQuery, error) {
	prepared := make(map[string]rego.PreparedEvalQuery, len(policies))

	for _, rp := range policies {
		content, err := embeddedPolicies.ReadFile(rp.file)
		if err != nil {
			return nil, fmt.Errorf("reading embedded policy %s: %w", rp.file, err)
		}

		store := inmem.NewFromObject(opaData)

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

	return prepared, nil
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
// tool_history is optional: when non-nil, it provides the sequence of tool calls in this run
// so that future Rego rules can implement tool-chain risk scoring (e.g. deny "read_db" then "send_email").
// Each element should have "name", and optionally "params" and "result_summary".
func (e *Engine) EvaluateToolAccess(ctx context.Context, toolName string, params map[string]interface{}, toolHistory []map[string]interface{}) (*Decision, error) {
	ctx, span := tracer.Start(ctx, "policy.evaluate_tool_access",
		trace.WithAttributes(
			attribute.String("tool.name", toolName),
			attribute.Int("tool_history_len", len(toolHistory)),
		))
	defer span.End()

	th := toolHistory
	if th == nil {
		th = []map[string]interface{}{}
	}
	input := map[string]interface{}{
		"tool_name":    toolName,
		"params":       params,
		"tool_history": mapSliceToInterface(th),
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

// EvaluateLoopContainment checks whether the current agentic loop state exceeds resource_limits.
// Call with current iteration, number of tool calls so far, and cost so far (EUR).
// Returns a deny decision when max_iterations, max_tool_calls_per_run, or max_cost_per_run would be exceeded.
func (e *Engine) EvaluateLoopContainment(ctx context.Context, currentIteration, toolCallsThisRun int, costThisRun float64) (*Decision, error) {
	ctx, span := tracer.Start(ctx, "policy.evaluate_loop_containment",
		trace.WithAttributes(
			attribute.Int("current_iteration", currentIteration),
			attribute.Int("tool_calls_this_run", toolCallsThisRun),
			attribute.Float64("cost_this_run", costThisRun),
		))
	defer span.End()

	input := map[string]interface{}{
		"current_iteration":   currentIteration,
		"tool_calls_this_run": toolCallsThisRun,
		"cost_this_run":       costThisRun,
	}

	decision := &Decision{
		Allowed:       true,
		Action:        "allow",
		PolicyVersion: e.policy.VersionTag,
	}

	reasons, err := e.evaluateDenyPolicy(ctx, "rego/resource_limits.rego", input)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	decision.Reasons = append(decision.Reasons, reasons...)

	if len(decision.Reasons) > 0 {
		decision.Allowed = false
		decision.Action = "deny"
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

// defaultDataTier is the fail-safe tier when OPA returns no result or an
// unrecognised type.  Must match the Rego default (tier 1 = confidential).
const defaultDataTier = 1

// EvaluateDataClassification returns the data tier (0, 1, or 2) for the given input.
func (e *Engine) EvaluateDataClassification(ctx context.Context, input map[string]interface{}) (int, error) {
	ctx, span := tracer.Start(ctx, "policy.evaluate_data_classification")
	defer span.End()

	prepared, ok := e.prepared["rego/data_classification.rego"]
	if !ok {
		return defaultDataTier, fmt.Errorf("data classification policy not prepared")
	}

	results, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		span.RecordError(err)
		return defaultDataTier, fmt.Errorf("evaluating data classification: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return defaultDataTier, nil
	}

	tierVal, ok := results[0].Expressions[0].Value.(json.Number)
	if ok {
		tier, err := tierVal.Int64()
		if err != nil {
			return defaultDataTier, fmt.Errorf("parsing tier value: %w", err)
		}
		return int(tier), nil
	}

	// OPA may return as float64 depending on context
	if tierFloat, ok := results[0].Expressions[0].Value.(float64); ok {
		return int(tierFloat), nil
	}

	return defaultDataTier, nil
}

// evaluateDenyPolicy delegates to the shared evaluateDenyReasons helper.
func (e *Engine) evaluateDenyPolicy(ctx context.Context, pkg string, input map[string]interface{}) ([]string, error) {
	return evaluateDenyReasons(ctx, e.prepared, pkg, input)
}

// evaluateDenyReasons runs a single prepared Rego policy that produces a set
// of deny reason strings. Both Engine and ProxyEngine delegate to this
// shared helper so the OPA result extraction logic lives in one place.
func evaluateDenyReasons(ctx context.Context, prepared map[string]rego.PreparedEvalQuery, pkg string, input map[string]interface{}) ([]string, error) {
	pq, ok := prepared[pkg]
	if !ok {
		return nil, fmt.Errorf("policy package %s not prepared", pkg)
	}

	results, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("evaluating %s: %w", pkg, err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return nil, nil
	}

	// The result of querying "data.xxx.deny" is a set of strings.
	// OPA returns it as []interface{} or, occasionally, map[string]interface{}.
	var reasons []string
	exprVal := results[0].Expressions[0].Value
	switch v := exprVal.(type) {
	case []interface{}:
		for _, msg := range v {
			if msgStr, ok := msg.(string); ok {
				reasons = append(reasons, msgStr)
			}
		}
	case map[string]interface{}:
		for _, msg := range v {
			if msgStr, ok := msg.(string); ok {
				reasons = append(reasons, msgStr)
			}
		}
	}

	return reasons, nil
}

// mapSliceToInterface converts []map[string]interface{} to []interface{} for OPA input.
func mapSliceToInterface(s []map[string]interface{}) []interface{} {
	out := make([]interface{}, len(s))
	for i, m := range s {
		out[i] = m
	}
	return out
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
