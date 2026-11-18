package action

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
)

// rule builds one argument rule config.
func rule(action, argument, typ, op string, value any, effect string, groups ...string) policy.ArgumentRuleConfig {
	return policy.ArgumentRuleConfig{Actions: []string{action}, Argument: argument, Type: typ, Operator: op, Value: value, Effect: effect, ApproverGroups: groups}
}

// refundRules is the refund example expressed with the generic contract:
// above 50.00 approval, above 500.00 deny. The currency and the amount's
// shape are the action's schema, not the policy's.
func refundRules() map[string]policy.ArgumentRuleConfig {
	return map[string]policy.ArgumentRuleConfig{
		"refund-needs-approval": rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "50.00", EffectRequireApproval, "support-leads"),
		"refund-too-large":      rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "500.00", EffectDeny),
	}
}

// examplePolicy declares three unrelated actions governed by the SAME rule
// form: a refund (decimal), a record deletion (integer count, boolean
// dry_run) and a deployment (string environment).
func examplePolicy(url string) *policy.Policy {
	obj := func(required []any, props map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": props}
	}
	dest := func(path string) policy.ActionDestinationConfig {
		return policy.ActionDestinationConfig{Type: "http", URL: url + path, Method: "POST", Success: &policy.ActionSuccessConfig{StatusCodes: []int{201}}}
	}
	rules := refundRules()
	rules["bulk-delete-needs-approval"] = rule("delete_records", "count", ArgTypeInteger, OpGt, 10, EffectRequireApproval, "support-leads")
	rules["mass-delete-denied"] = rule("delete_records", "count", ArgTypeInteger, OpGte, 1000, EffectDeny)
	rules["real-delete-needs-approval"] = rule("delete_records", "dry_run", ArgTypeBoolean, OpEq, false, EffectRequireApproval, "support-leads")
	rules["prod-deploy-needs-approval"] = rule("deploy_service", "environment", ArgTypeString, OpEq, "production", EffectRequireApproval, "support-leads")
	rules["unknown-environment-denied"] = rule("deploy_service", "environment", ArgTypeString, OpEq, "sandbox-legacy", EffectDeny)
	return &policy.Policy{
		Agent:        policy.AgentConfig{Name: "support-bot", TenantID: "acme"},
		Capabilities: &policy.CapabilitiesConfig{ForbiddenTools: []string{"delete_customer"}},
		Actions: &policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{
			"create_refund_request": {
				InputSchema: obj([]any{"ticket_id", "amount", "currency"}, map[string]any{
					"ticket_id": map[string]any{"type": "string"}, "amount": map[string]any{"type": "number", "minimum": 0},
					"currency": map[string]any{"type": "string", "enum": []any{"EUR"}}, "note": map[string]any{"type": "string"}, "iban": map[string]any{"type": "string"},
				}),
				Review:      &policy.ActionReviewConfig{Fields: []string{"ticket_id", "amount", "currency", "iban"}, NonMaterial: []string{"note"}},
				Destination: dest("/refunds"),
			},
			"delete_records": {
				InputSchema: obj([]any{"table", "count", "dry_run"}, map[string]any{
					"table": map[string]any{"type": "string"}, "count": map[string]any{"type": "integer"}, "dry_run": map[string]any{"type": "boolean"},
				}),
				Review:      &policy.ActionReviewConfig{Fields: []string{"table", "count", "dry_run"}},
				Destination: dest("/delete"),
			},
			"deploy_service": {
				InputSchema: obj([]any{"service", "environment"}, map[string]any{
					"service": map[string]any{"type": "string"}, "environment": map[string]any{"type": "string"},
				}),
				Review:      &policy.ActionReviewConfig{Fields: []string{"service", "environment"}},
				Destination: dest("/deploy"),
			},
			"notify_customer": {
				InputSchema: obj([]any{"ticket_id"}, map[string]any{"ticket_id": map[string]any{"type": "string"}}),
				Destination: dest("/notify"),
			},
			"delete_customer": {
				InputSchema: obj([]any{}, map[string]any{"customer_id": map[string]any{"type": "string"}}),
				Destination: dest("/delete-customer"),
			},
		}},
		Policies: policy.PoliciesConfig{Approvals: &policy.ApprovalsConfig{ExpiresAfter: "30m", ArgumentRules: rules}},
	}
}

func compiled(t *testing.T, pol *policy.Policy) *ApprovalPolicy {
	t.Helper()
	ap, err := CompileApprovalPolicy(pol)
	require.NoError(t, err)
	cat, err := CompileCatalog(pol.Actions, nil)
	require.NoError(t, err)
	require.NoError(t, ap.ValidateAgainstCatalog(cat))
	return ap
}

// One evaluator, four argument types, three unrelated actions, no
// domain-specific branch.
func TestArgumentRules_OneEvaluatorAcrossTypesAndActions(t *testing.T) {
	ap := compiled(t, examplePolicy("http://127.0.0.1:9"))
	cases := []struct {
		name, action, args, want, rule, code string
	}{
		// decimal: refund amount
		{"refund small", "create_refund_request", `{"amount":30.00,"currency":"EUR","ticket_id":"T"}`, VerdictAllow, "", ""},
		{"refund at the approval boundary", "create_refund_request", `{"amount":50,"currency":"EUR","ticket_id":"T"}`, VerdictAllow, "", ""},
		{"refund just above", "create_refund_request", `{"amount":50.01,"currency":"EUR","ticket_id":"T"}`, VerdictRequireApproval, "refund-needs-approval", ReasonArgumentRuleApproval},
		{"refund as a decimal string", "create_refund_request", `{"amount":"75.5","currency":"EUR","ticket_id":"T"}`, VerdictRequireApproval, "refund-needs-approval", ReasonArgumentRuleApproval},
		{"refund at the deny boundary", "create_refund_request", `{"amount":500.00,"currency":"EUR","ticket_id":"T"}`, VerdictRequireApproval, "refund-needs-approval", ReasonArgumentRuleApproval},
		{"refund above the deny boundary", "create_refund_request", `{"amount":500.000001,"currency":"EUR","ticket_id":"T"}`, VerdictDeny, "refund-too-large", ReasonArgumentRuleDeny},
		{"refund huge", "create_refund_request", `{"amount":"999999999999999999.999999","currency":"EUR","ticket_id":"T"}`, VerdictDeny, "refund-too-large", ReasonArgumentRuleDeny},
		// integer and boolean: record deletion
		{"dry run of a few records", "delete_records", `{"table":"t","count":5,"dry_run":true}`, VerdictAllow, "", ""},
		{"real delete of a few records", "delete_records", `{"table":"t","count":5,"dry_run":false}`, VerdictRequireApproval, "real-delete-needs-approval", ReasonArgumentRuleApproval},
		{"dry run of many records", "delete_records", `{"table":"t","count":11,"dry_run":true}`, VerdictRequireApproval, "bulk-delete-needs-approval", ReasonArgumentRuleApproval},
		{"mass delete, even as a dry run", "delete_records", `{"table":"t","count":1000,"dry_run":true}`, VerdictDeny, "mass-delete-denied", ReasonArgumentRuleDeny},
		// string: deployment environment
		{"deploy to staging", "deploy_service", `{"service":"api","environment":"staging"}`, VerdictAllow, "", ""},
		{"deploy to production", "deploy_service", `{"service":"api","environment":"production"}`, VerdictRequireApproval, "prod-deploy-needs-approval", ReasonArgumentRuleApproval},
		{"string comparison is exact", "deploy_service", `{"service":"api","environment":"Production"}`, VerdictAllow, "", ""},
		{"deploy to a denied environment", "deploy_service", `{"service":"api","environment":"sandbox-legacy"}`, VerdictDeny, "unknown-environment-denied", ReasonArgumentRuleDeny},
		// no rule, and a forbidden action
		{"an action without rules", "notify_customer", `{"ticket_id":"T"}`, VerdictAllow, "", ""},
		{"a forbidden action", "delete_customer", `{}`, VerdictDeny, UseCaseDenyRuleID, ""},
	}
	for _, c := range cases {
		v := ap.EvaluateArguments(c.action, []byte(c.args))
		require.Equal(t, c.want, v.Outcome, "%s: %s", c.name, v.Reason)
		require.Equal(t, c.rule, v.RuleID, c.name)
		require.Equal(t, c.code, v.Code, c.name)
		if c.want == VerdictRequireApproval {
			require.Equal(t, []string{"support-leads"}, v.ApproverGroups, c.name)
		}
	}
	// A rule never grants: the name-only verdict is the baseline, and
	// nothing in the rules can make a call LESS restricted than it.
	require.Equal(t, VerdictAllow, ap.Evaluate("create_refund_request").Outcome)
}

// Operators per type, including ne and the ordered ones, and normalization.
func TestArgumentRules_Operators(t *testing.T) {
	eval := func(typ, op string, value any, args string) string {
		pol := examplePolicy("http://127.0.0.1:9")
		action, arg := "delete_records", "count"
		switch typ {
		case ArgTypeDecimal:
			action, arg = "create_refund_request", "amount"
		case ArgTypeString:
			action, arg = "deploy_service", "environment"
		case ArgTypeBoolean:
			arg = "dry_run"
		}
		pol.Policies.Approvals.ArgumentRules = map[string]policy.ArgumentRuleConfig{"r": rule(action, arg, typ, op, value, EffectDeny)}
		ap, err := CompileApprovalPolicy(pol)
		require.NoError(t, err)
		return ap.EvaluateArguments(action, []byte(args)).Outcome
	}
	del := func(n string) string { return `{"table":"t","count":` + n + `,"dry_run":true}` }
	ref := func(n string) string { return `{"amount":` + n + `,"currency":"EUR","ticket_id":"T"}` }
	for _, c := range []struct {
		typ, op string
		value   any
		args    string
		deny    bool
	}{
		{ArgTypeInteger, OpEq, 10, del("10"), true},
		{ArgTypeInteger, OpEq, 10, del("11"), false},
		{ArgTypeInteger, OpNe, 10, del("11"), true},
		{ArgTypeInteger, OpNe, 10, del("10"), false},
		{ArgTypeInteger, OpGt, 10, del("11"), true},
		{ArgTypeInteger, OpGt, 10, del("10"), false},
		{ArgTypeInteger, OpGte, 10, del("10"), true},
		{ArgTypeInteger, OpGte, 10, del("9"), false},
		{ArgTypeInteger, OpLt, 10, del("9"), true},
		{ArgTypeInteger, OpLt, 10, del("10"), false},
		{ArgTypeInteger, OpLte, 10, del("10"), true},
		{ArgTypeInteger, OpLte, 10, del("11"), false},
		{ArgTypeInteger, OpLt, 0, del("-1"), true},
		{ArgTypeDecimal, OpEq, "10.5", ref("10.50"), true},
		{ArgTypeDecimal, OpEq, "10.50", ref(`"10.5"`), true},
		{ArgTypeDecimal, OpNe, "10.5", ref("10.500001"), true},
		{ArgTypeDecimal, OpLt, "0", ref("-0.01"), true},
		{ArgTypeDecimal, OpGte, "0.000001", ref("0.000001"), true},
		{ArgTypeDecimal, OpLte, "10", ref("10.000001"), false},
		{ArgTypeString, OpEq, "production", `{"service":"s","environment":"production"}`, true},
		{ArgTypeString, OpNe, "production", `{"service":"s","environment":"staging"}`, true},
		{ArgTypeString, OpNe, "production", `{"service":"s","environment":"production"}`, false},
		{ArgTypeBoolean, OpEq, true, del("1"), true},
		{ArgTypeBoolean, OpNe, true, del("1"), false},
		{ArgTypeBoolean, OpNe, false, del("1"), true},
	} {
		got := eval(c.typ, c.op, c.value, c.args)
		want := VerdictAllow
		if c.deny {
			want = VerdictDeny
		}
		require.Equal(t, want, got, "%s %s %v on %s", c.typ, c.op, c.value, c.args)
	}
}

// An argument a rule depends on that is not established denies; it is never
// a silent non-match, and no type is coerced into another.
func TestArgumentRules_UnestablishedArgumentDenies(t *testing.T) {
	ap, err := CompileApprovalPolicy(examplePolicy("http://127.0.0.1:9"))
	require.NoError(t, err)
	cases := map[string][2]string{
		"decimal missing":                 {"create_refund_request", `{"currency":"EUR"}`},
		"decimal null":                    {"create_refund_request", `{"amount":null}`},
		"decimal exponent":                {"create_refund_request", `{"amount":1e1}`},
		"decimal too many fractions":      {"create_refund_request", `{"amount":10.0000001}`},
		"decimal leading zero":            {"create_refund_request", `{"amount":"010"}`},
		"decimal boolean":                 {"create_refund_request", `{"amount":true}`},
		"decimal object":                  {"create_refund_request", `{"amount":{"v":1}}`},
		"decimal words":                   {"create_refund_request", `{"amount":"ten"}`},
		"decimal padded":                  {"create_refund_request", `{"amount":" 10"}`},
		"decimal too many digits":         {"create_refund_request", `{"amount":"1000000000000000000"}`},
		"integer missing":                 {"delete_records", `{"dry_run":true}`},
		"integer as a string":             {"delete_records", `{"count":"5","dry_run":true}`},
		"integer with a fraction":         {"delete_records", `{"count":5.0,"dry_run":true}`},
		"integer exponent":                {"delete_records", `{"count":1e2,"dry_run":true}`},
		"boolean missing":                 {"delete_records", `{"count":5}`},
		"boolean as a string":             {"delete_records", `{"count":5,"dry_run":"false"}`},
		"boolean as a number":             {"delete_records", `{"count":5,"dry_run":0}`},
		"string missing":                  {"deploy_service", `{"service":"s"}`},
		"string as a number":              {"deploy_service", `{"service":"s","environment":1}`},
		"string null":                     {"deploy_service", `{"service":"s","environment":null}`},
		"arguments are not an object":     {"deploy_service", `["production"]`},
		"no arguments at all":             {"deploy_service", ``},
		"an over-long string":             {"deploy_service", `{"service":"s","environment":"` + strings.Repeat("x", 1025) + `"}`},
		"decimal rule on a number string": {"create_refund_request", `{"amount":"1,5"}`},
	}
	for name, c := range cases {
		v := ap.EvaluateArguments(c[0], []byte(c[1]))
		require.Equal(t, VerdictDeny, v.Outcome, "%s: %s", name, v.Reason)
		require.Equal(t, ReasonArgumentNotEstablished, v.Code, name)
		require.NotEmpty(t, v.RuleID, name)
	}
}

// Reasons end up in signed evidence, which outlives the sealed payload: they
// never repeat an argument value of the call, nor the rule's operand.
func TestArgumentRules_ReasonsCarryNoArgumentValues(t *testing.T) {
	ap, err := CompileApprovalPolicy(examplePolicy("http://127.0.0.1:9"))
	require.NoError(t, err)
	for _, c := range [][2]string{
		{"create_refund_request", `{"amount":123.45,"currency":"EUR","ticket_id":"T-secret"}`},
		{"create_refund_request", `{"amount":777.77,"currency":"EUR","ticket_id":"T-secret"}`},
		{"create_refund_request", `{"amount":"secret-text","currency":"EUR"}`},
		{"deploy_service", `{"service":"payments-core","environment":"production"}`},
		{"deploy_service", `{"service":"payments-core","environment":"sandbox-legacy"}`},
		{"delete_records", `{"table":"customers_pii","count":4242,"dry_run":false}`},
	} {
		v := ap.EvaluateArguments(c[0], []byte(c[1]))
		require.NotEqual(t, VerdictAllow, v.Outcome)
		for _, leaked := range []string{"123.45", "777.77", "secret-text", "T-secret", "payments-core", "production", "sandbox-legacy", "customers_pii", "4242", "500", "50.00"} {
			require.NotContains(t, v.Reason, leaked, c[1])
		}
	}
}

func TestArgumentRules_CompanyLayering(t *testing.T) {
	company := &CompanyActionPolicy{Source: "test", ArgumentRules: refundRules()}
	useCase := func(rules map[string]policy.ArgumentRuleConfig) *policy.Policy {
		pol := examplePolicy("http://127.0.0.1:9")
		pol.Policies.Approvals.ArgumentRules = rules
		return pol
	}
	refund := func(amount string) []byte {
		return []byte(`{"amount":` + amount + `,"currency":"EUR","ticket_id":"T"}`)
	}

	t.Run("a use case cannot lift a company rule", func(t *testing.T) {
		// The use case declares nothing restrictive at these amounts; the
		// company rules still apply. There is no "allow" effect to declare.
		ap, err := CompileEffectiveActionPolicy(useCase(nil), company)
		require.NoError(t, err)
		v := ap.EvaluateArguments("create_refund_request", refund("75"))
		require.Equal(t, VerdictRequireApproval, v.Outcome)
		require.Equal(t, "company:refund-needs-approval", v.RuleID)
		require.Equal(t, PolicySourceCompany, v.Source)
		v = ap.EvaluateArguments("create_refund_request", refund("600"))
		require.Equal(t, VerdictDeny, v.Outcome)
		require.Equal(t, "company:refund-too-large", v.RuleID)
	})
	t.Run("a use case can tighten", func(t *testing.T) {
		ap, err := CompileEffectiveActionPolicy(useCase(map[string]policy.ArgumentRuleConfig{
			"tight-approval": rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "20", EffectRequireApproval, "support-leads"),
			"tight-deny":     rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "200", EffectDeny),
		}), company)
		require.NoError(t, err)
		require.Equal(t, VerdictAllow, ap.EvaluateArguments("create_refund_request", refund("20")).Outcome)
		v := ap.EvaluateArguments("create_refund_request", refund("30"))
		require.Equal(t, VerdictRequireApproval, v.Outcome)
		require.Equal(t, "tight-approval", v.RuleID)
		v = ap.EvaluateArguments("create_refund_request", refund("300"))
		require.Equal(t, VerdictDeny, v.Outcome)
		require.Equal(t, "tight-deny", v.RuleID, "the use case's deny applies where the company only asks approval")
	})
	t.Run("a company forbidden action is denied whatever the arguments", func(t *testing.T) {
		forbid := &CompanyActionPolicy{Source: "test", ForbiddenActions: []string{"create_refund_*"}, ArgumentRules: refundRules()}
		ap, err := CompileEffectiveActionPolicy(useCase(nil), forbid)
		require.NoError(t, err)
		v := ap.EvaluateArguments("create_refund_request", refund("1"))
		require.Equal(t, VerdictDeny, v.Outcome)
		require.Equal(t, CompanyDenyRuleID, v.RuleID)
	})
	t.Run("explicit company guards restrict a domain in every use case", func(t *testing.T) {
		// Company-wide restrictions on values the action's schema leaves
		// open: deployments only to named environments, no real deletion.
		// Both are ordinary rules (string ne, boolean eq), no domain code.
		guards := &CompanyActionPolicy{Source: "test", ArgumentRules: map[string]policy.ArgumentRuleConfig{
			"staging-only":     rule("deploy_*", "environment", ArgTypeString, OpNe, "staging", EffectDeny),
			"no-real-deletion": rule("delete_records", "dry_run", ArgTypeBoolean, OpEq, false, EffectDeny),
		}}
		pol := useCase(nil)
		ap, err := CompileEffectiveActionPolicy(pol, guards)
		require.NoError(t, err)
		cat, err := CompileCatalog(pol.Actions, nil)
		require.NoError(t, err)
		require.NoError(t, ap.ValidateAgainstCatalog(cat))

		require.Equal(t, VerdictAllow, ap.EvaluateArguments("deploy_service", []byte(`{"service":"api","environment":"staging"}`)).Outcome)
		for _, env := range []string{"production", "Staging", ""} {
			v := ap.EvaluateArguments("deploy_service", []byte(`{"service":"api","environment":"`+env+`"}`))
			require.Equal(t, VerdictDeny, v.Outcome, env)
			require.Equal(t, "company:staging-only", v.RuleID, env)
			require.Equal(t, PolicySourceCompany, v.Source, env)
			require.Equal(t, ReasonArgumentRuleDeny, v.Code, env)
		}
		// The guard's argument not established: denied, attributed to the guard.
		v := ap.EvaluateArguments("deploy_service", []byte(`{"service":"api"}`))
		require.Equal(t, VerdictDeny, v.Outcome)
		require.Equal(t, ReasonArgumentNotEstablished, v.Code)
		require.Equal(t, PolicySourceCompany, v.Source)

		require.Equal(t, VerdictAllow, ap.EvaluateArguments("delete_records", []byte(`{"table":"t","count":1,"dry_run":true}`)).Outcome)
		v = ap.EvaluateArguments("delete_records", []byte(`{"table":"t","count":1,"dry_run":false}`))
		require.Equal(t, VerdictDeny, v.Outcome)
		require.Equal(t, "company:no-real-deletion", v.RuleID)

		// The use case's own approval rule for production does not soften
		// the company deny, and inspection names the company layer.
		pol = useCase(map[string]policy.ArgumentRuleConfig{
			"prod-deploy-needs-approval": rule("deploy_service", "environment", ArgTypeString, OpEq, "production", EffectRequireApproval, "support-leads"),
		})
		ap, err = CompileEffectiveActionPolicy(pol, guards)
		require.NoError(t, err)
		v = ap.EvaluateArguments("deploy_service", []byte(`{"service":"api","environment":"production"}`))
		require.Equal(t, VerdictDeny, v.Outcome)
		require.Equal(t, "company:staging-only", v.RuleID)
		d := ap.Decision("deploy_service")
		require.Equal(t, DecisionByArguments, d.DecisionBasis)
		sources := map[string]string{}
		for _, r := range d.ArgumentRules {
			sources[r.ID] = r.Source
		}
		require.Equal(t, map[string]string{"company:staging-only": PolicySourceCompany, "prod-deploy-needs-approval": PolicySourceUseCase}, sources)

		// A use case whose action cannot establish the guard's argument is
		// refused at load, naming the company rule.
		open := useCase(nil)
		def := open.Actions.Definitions["deploy_service"]
		def.InputSchema = map[string]any{"type": "object", "additionalProperties": false, "required": []any{"service"}, "properties": map[string]any{"service": map[string]any{"type": "string"}, "environment": map[string]any{"type": "string"}}}
		open.Actions.Definitions["deploy_service"] = def
		ap, err = CompileEffectiveActionPolicy(open, guards)
		require.NoError(t, err)
		cat, err = CompileCatalog(open.Actions, nil)
		require.NoError(t, err)
		require.ErrorContains(t, ap.ValidateAgainstCatalog(cat), `company argument rule "company:staging-only" on action "deploy_service"`)
	})
	t.Run("a company name rule is reported over a use-case argument rule; deny still wins", func(t *testing.T) {
		withRule := &CompanyActionPolicy{Source: "test", Rules: map[string]CompanyApprovalRule{"all-refunds": {Actions: []string{"create_refund_request"}, ApproverGroups: []string{"support-leads"}}}}
		ap, err := CompileEffectiveActionPolicy(useCase(refundRules()), withRule)
		require.NoError(t, err)
		v := ap.EvaluateArguments("create_refund_request", refund("10"))
		require.Equal(t, VerdictRequireApproval, v.Outcome)
		require.Equal(t, "company:all-refunds", v.RuleID)
		require.Equal(t, VerdictDeny, ap.EvaluateArguments("create_refund_request", refund("501")).Outcome)
	})
}

func TestArgumentRules_Digests(t *testing.T) {
	plain := examplePolicy("http://127.0.0.1:9")
	plain.Policies.Approvals.ArgumentRules = nil
	before, err := CompileApprovalPolicy(plain)
	require.NoError(t, err)

	withRules := func(rules map[string]policy.ArgumentRuleConfig) string {
		pol := examplePolicy("http://127.0.0.1:9")
		pol.Policies.Approvals.ArgumentRules = rules
		ap, err := CompileApprovalPolicy(pol)
		require.NoError(t, err)
		return ap.Digest
	}
	base := withRules(refundRules())
	require.NotEqual(t, before.Digest, base, "adding argument rules changes the approval-relevant digest")

	moved := refundRules()
	moved["refund-too-large"] = rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "500.01", EffectDeny)
	require.NotEqual(t, base, withRules(moved), "moving an operand invalidates approvals bound to the old policy")

	respelled := refundRules()
	respelled["refund-needs-approval"] = rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "50", EffectRequireApproval, "support-leads")
	respelled["refund-too-large"] = rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "500.0", EffectDeny)
	require.Equal(t, base, withRules(respelled), "operands are normalized: 50 and 50.00 are one decimal")

	// A string operand cannot imitate a digest delimiter or another line.
	a := withRules(map[string]policy.ArgumentRuleConfig{"r": rule("deploy_service", "environment", ArgTypeString, OpEq, "a effect=deny", EffectRequireApproval, "support-leads")})
	b := withRules(map[string]policy.ArgumentRuleConfig{"r": rule("deploy_service", "environment", ArgTypeString, OpEq, "a", EffectDeny)})
	require.NotEqual(t, a, b)

	// A policy without argument rules keeps the digest it always had, and a
	// company policy without them keeps its version-1 encoding.
	v1 := string(companyCanonical([]string{"delete_customer"}, nil, nil))
	require.Contains(t, v1, `"v":1`)
	require.NotContains(t, v1, "argument_rules")
	withCompany := &CompanyActionPolicy{ArgumentRules: refundRules()}
	require.NotEqual(t, (&CompanyActionPolicy{}).Digest(), withCompany.Digest())
}

func TestArgumentRules_InvalidConfigurationIsRefused(t *testing.T) {
	ok := rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "50.00", EffectRequireApproval, "support-leads")
	bad := func(mut func(*policy.ArgumentRuleConfig)) policy.ArgumentRuleConfig {
		c := ok
		c.Actions, c.ApproverGroups = append([]string(nil), ok.Actions...), append([]string(nil), ok.ApproverGroups...)
		mut(&c)
		return c
	}
	cases := map[string]policy.ArgumentRuleConfig{
		"no actions":                        bad(func(c *policy.ArgumentRuleConfig) { c.Actions = nil }),
		"bad action pattern":                bad(func(c *policy.ArgumentRuleConfig) { c.Actions = []string{"Refund"} }),
		"nested argument path":              bad(func(c *policy.ArgumentRuleConfig) { c.Argument = "amount.value" }),
		"unknown type":                      bad(func(c *policy.ArgumentRuleConfig) { c.Type = "money" }),
		"unknown operator":                  bad(func(c *policy.ArgumentRuleConfig) { c.Operator = "in" }),
		"decimal operand as a float":        bad(func(c *policy.ArgumentRuleConfig) { c.Value = 50.0 }),
		"decimal operand with seven digits": bad(func(c *policy.ArgumentRuleConfig) { c.Value = "50.0000001" }),
		"integer operand as a string":       bad(func(c *policy.ArgumentRuleConfig) { c.Type, c.Value = ArgTypeInteger, "50" }),
		"boolean operand as a string":       bad(func(c *policy.ArgumentRuleConfig) { c.Type, c.Operator, c.Value = ArgTypeBoolean, OpEq, "true" }),
		"ordered comparison on a string":    bad(func(c *policy.ArgumentRuleConfig) { c.Type, c.Value = ArgTypeString, "a" }),
		"ordered comparison on a boolean":   bad(func(c *policy.ArgumentRuleConfig) { c.Type, c.Value = ArgTypeBoolean, true }),
		"an allow effect":                   bad(func(c *policy.ArgumentRuleConfig) { c.Effect = "allow" }),
		"approval without groups":           bad(func(c *policy.ArgumentRuleConfig) { c.ApproverGroups = nil }),
		"deny with groups":                  bad(func(c *policy.ArgumentRuleConfig) { c.Effect = EffectDeny }),
		"bad group":                         bad(func(c *policy.ArgumentRuleConfig) { c.ApproverGroups = []string{"Finance Leads"} }),
		"string operand with a line break":  bad(func(c *policy.ArgumentRuleConfig) { c.Type, c.Operator, c.Value = ArgTypeString, OpEq, "a\nb" }),
	}
	for name, c := range cases {
		pol := examplePolicy("http://127.0.0.1:9")
		pol.Policies.Approvals.ArgumentRules = map[string]policy.ArgumentRuleConfig{"r": c}
		_, err := CompileApprovalPolicy(pol)
		require.Error(t, err, name)
	}

	t.Run("two approval requirements on one action with different groups are ambiguous", func(t *testing.T) {
		pol := examplePolicy("http://127.0.0.1:9")
		pol.Policies.Approvals.Rules = map[string]policy.ApprovalRuleConfig{"refunds": {Actions: []string{"create_refund_*"}, ApproverGroups: []string{"finance"}}}
		_, err := CompileApprovalPolicy(pol)
		require.ErrorContains(t, err, "different approver groups")
	})
	t.Run("an argument rule cannot reuse a rule id", func(t *testing.T) {
		pol := examplePolicy("http://127.0.0.1:9")
		pol.Policies.Approvals.Rules = map[string]policy.ApprovalRuleConfig{"refund-too-large": {Actions: []string{"notify_customer"}, ApproverGroups: []string{"support-leads"}}}
		_, err := CompileApprovalPolicy(pol)
		require.ErrorContains(t, err, "same id")
	})
	t.Run("an invalid company rule fails the company policy", func(t *testing.T) {
		c := &CompanyActionPolicy{ArgumentRules: map[string]policy.ArgumentRuleConfig{"x": bad(func(c *policy.ArgumentRuleConfig) { c.Type = "" })}}
		require.Error(t, c.Validate())
		_, err := CompileEffectiveActionPolicy(examplePolicy("http://127.0.0.1:9"), c)
		require.Error(t, err)
	})
}

// Rules are resolved against the trusted catalog: the argument must be a
// declared, REQUIRED top-level property of a matching JSON type.
func TestArgumentRules_ValidateAgainstCatalog(t *testing.T) {
	check := func(r policy.ArgumentRuleConfig) error {
		pol := examplePolicy("http://127.0.0.1:9")
		pol.Policies.Approvals.ArgumentRules = map[string]policy.ArgumentRuleConfig{"r": r}
		ap, err := CompileApprovalPolicy(pol)
		require.NoError(t, err)
		cat, err := CompileCatalog(pol.Actions, nil)
		require.NoError(t, err)
		return ap.ValidateAgainstCatalog(cat)
	}
	require.NoError(t, check(rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "50", EffectDeny)))
	require.NoError(t, check(rule("no_such_action", "amount", ArgTypeDecimal, OpGt, "50", EffectDeny)), "a rule for an action not in the catalog is allowed")
	require.ErrorContains(t, check(rule("create_refund_request", "total", ArgTypeDecimal, OpGt, "50", EffectDeny)), "not a declared top-level property")
	require.ErrorContains(t, check(rule("create_refund_request", "note", ArgTypeString, OpEq, "x", EffectDeny)), "must be required")
	require.ErrorContains(t, check(rule("create_refund_request", "amount", ArgTypeInteger, OpGt, 50, EffectDeny)), "no implicit coercion")
	require.ErrorContains(t, check(rule("delete_records", "count", ArgTypeDecimal, OpGt, "50", EffectDeny)), "no implicit coercion")
	require.ErrorContains(t, check(rule("deploy_service", "environment", ArgTypeBoolean, OpEq, true, EffectDeny)), "no implicit coercion")
	require.ErrorContains(t, check(rule("delete_*", "count", ArgTypeInteger, OpGt, 1, EffectDeny)), `on action "delete_customer"`, "a prefix rule must be valid for every action it matches")
}

func ruleHarness(t *testing.T) *harness {
	t.Helper()
	down := newDownstream(t)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return newHarnessWith(t, down, store, examplePolicy(down.srv.URL), testVaultKey)
}

// The service applies the rules at establish and re-applies them to the
// sealed arguments before any claim, with a counting downstream as proof,
// for all three example actions.
func TestArgumentRules_ServiceDispatchCounts(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	down := h.down

	for _, c := range []struct{ op, action, args string }{
		{"op-refund-small", "create_refund_request", `{"ticket_id":"T-1","amount":30.00,"currency":"EUR"}`},
		{"op-delete-dry", "delete_records", `{"table":"t","count":3,"dry_run":true}`},
		{"op-deploy-staging", "deploy_service", `{"service":"api","environment":"staging"}`},
	} {
		res := h.establish(t, c.op, c.action, c.args)
		require.Equal(t, VerdictAllow, res.Operation.Verdict, c.op)
		_, err := h.svc.Execute(ctx, c.op)
		require.NoError(t, err, c.op)
	}
	require.Equal(t, int64(3), down.calls.Load(), "the three unrestricted calls are dispatched once each")

	for _, c := range []struct{ op, action, args string }{
		{"op-refund-large", "create_refund_request", `{"ticket_id":"T-2","amount":900.00,"currency":"EUR"}`},
		{"op-delete-mass", "delete_records", `{"table":"t","count":5000,"dry_run":false}`},
		{"op-deploy-denied", "deploy_service", `{"service":"api","environment":"sandbox-legacy"}`},
	} {
		res := h.establish(t, c.op, c.action, c.args)
		require.Equal(t, VerdictDeny, res.Operation.Verdict, c.op)
		require.Equal(t, OpDenied, res.Operation.Status, c.op)
		require.False(t, res.Operation.Payload.Present, c.op)
		_, err := h.svc.Execute(ctx, c.op)
		require.Equal(t, CodePolicyDenied, CodeOf(err), c.op)
		f := h.verify(t, c.op)
		require.Equal(t, LifecycleValid, f.Verdict, f.Summary())
	}
	require.Equal(t, int64(3), down.calls.Load(), "denied calls never reach the downstream")

	want := int64(3)
	for _, c := range []struct{ op, action, args, changed, rule string }{
		{"op-refund-mid", "create_refund_request", `{"ticket_id":"T-6","amount":75.00,"currency":"EUR"}`, `{"ticket_id":"T-6","amount":450.00,"currency":"EUR"}`, "refund-needs-approval"},
		{"op-delete-real", "delete_records", `{"table":"t","count":3,"dry_run":false}`, `{"table":"t","count":4,"dry_run":false}`, "real-delete-needs-approval"},
		{"op-deploy-prod", "deploy_service", `{"service":"api","environment":"production"}`, `{"service":"billing","environment":"production"}`, "prod-deploy-needs-approval"},
	} {
		res := h.establish(t, c.op, c.action, c.args)
		require.Equal(t, VerdictRequireApproval, res.Operation.Verdict, c.op)
		require.Equal(t, c.rule, res.Operation.MatchedRuleID, c.op)
		_, err := h.svc.Execute(ctx, c.op)
		require.Equal(t, CodeApprovalPending, CodeOf(err), c.op)
		h.approve(t, res, lead("lead-1"))
		require.Equal(t, want, down.calls.Load(), "the approval itself dispatches nothing")
		_, err = h.svc.Establish(ctx, EstablishRequest{OperationID: c.op, Action: c.action, Arguments: json.RawMessage(c.changed)})
		require.Equal(t, CodeOperationConflict, CodeOf(err), "changed arguments cannot reuse the approval: %s", c.op)
		_, err = h.svc.Execute(ctx, c.op)
		require.NoError(t, err, c.op)
		want++
		require.Equal(t, want, down.calls.Load(), c.op)
		_, err = h.svc.Execute(ctx, c.op)
		require.Equal(t, CodeOperationAlreadySucceeded, CodeOf(err), c.op)
		require.Equal(t, want, down.calls.Load(), "a replay never dispatches twice")
		f := h.verify(t, c.op)
		require.Equal(t, LifecycleValid, f.Verdict, f.Summary())
	}
}

// An operation authorized under one policy is re-checked against the current
// policy and its own sealed arguments before a claim.
func TestArgumentRules_TightenedPolicyRefusesEarlierOperations(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	down := h.down
	mid := h.establish(t, "op-mid", "create_refund_request", `{"ticket_id":"T-6","amount":75.00,"currency":"EUR"}`)
	h.approve(t, mid, lead("lead-1"))

	tightened := examplePolicy(down.srv.URL)
	tightened.Policies.Approvals.ArgumentRules["refund-too-large"] = rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "60", EffectDeny)
	h2 := newHarnessWith(t, down, h.store, tightened, testVaultKey)
	h2.now = h.now
	_, err := h2.svc.Execute(ctx, "op-mid")
	require.Contains(t, []string{CodePolicyDenied, CodeApprovalBindingStale}, CodeOf(err), "a policy change voids the approval")
	require.Equal(t, int64(0), down.calls.Load())

	// Allowed by name under a policy without rules; the rules are added later.
	plain := examplePolicy(down.srv.URL)
	plain.Policies.Approvals.ArgumentRules = nil
	h3 := newHarnessWith(t, down, h.store, plain, testVaultKey)
	h3.now = h.now
	needs := h3.establish(t, "op-now-needs-approval", "create_refund_request", `{"ticket_id":"T-7","amount":75.00,"currency":"EUR"}`)
	require.Equal(t, VerdictAllow, needs.Operation.Verdict)
	denied := h3.establish(t, "op-now-denied", "deploy_service", `{"service":"api","environment":"sandbox-legacy"}`)
	require.Equal(t, VerdictAllow, denied.Operation.Verdict)

	h4 := newHarnessWith(t, down, h.store, examplePolicy(down.srv.URL), testVaultKey)
	h4.now = h.now
	_, err = h4.svc.Execute(ctx, "op-now-needs-approval")
	require.Equal(t, CodeApprovalRequired, CodeOf(err), "the name-only re-check allows it; only the sealed arguments show it needs approval")
	_, err = h4.svc.Execute(ctx, "op-now-denied")
	require.Equal(t, CodePolicyDenied, CodeOf(err))
	require.Equal(t, int64(0), down.calls.Load())
	f := h4.verify(t, "op-now-denied")
	require.Equal(t, LifecycleIncomplete, f.Verdict, "refused at claim: consistent, not closed; "+f.Summary())
}

// An approval required by an argument rule keeps the reviewer and claim
// guarantees of name-based approvals.
func TestArgumentRules_ApprovalAuthorityAndSingleClaim(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	down := h.down
	prod := h.establish(t, "op-prod", "deploy_service", `{"service":"api","environment":"production"}`)

	intern := lead("intern")
	intern.Groups = []string{"interns"}
	_, err := h.svc.Decide(ctx, DecideRequest{ApprovalID: prod.Operation.Approval.ID, Approve: true, Reviewer: intern})
	require.Equal(t, CodeApprovalNotAuthorized, CodeOf(err))
	foreign := lead("foreign")
	foreign.TenantScope = "other-tenant"
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: prod.Operation.Approval.ID, Approve: true, Reviewer: foreign})
	require.Error(t, err)
	_, err = h.svc.Execute(ctx, "op-prod")
	require.Equal(t, CodeApprovalPending, CodeOf(err))
	require.Equal(t, int64(0), down.calls.Load())

	h.approve(t, prod, lead("lead-1"))
	var wg sync.WaitGroup
	start := make(chan struct{})
	var succeeded atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := h.svc.Execute(ctx, "op-prod"); err == nil {
				succeeded.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.Equal(t, int64(1), succeeded.Load(), "exactly one claim wins")
	require.Equal(t, int64(1), down.calls.Load(), "one effect")
}

// A rule-required approval that is rejected, expires undecided, or expires
// after being granted dispatches nothing.
func TestArgumentRules_RejectedAndExpiredApprovalsNeverDispatch(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	const args = `{"table":"t","count":50,"dry_run":false}`

	rej := h.establish(t, "op-rejected", "delete_records", args)
	_, err := h.svc.Decide(ctx, DecideRequest{ApprovalID: rej.Operation.Approval.ID, Approve: false, Reason: "duplicate", Reviewer: lead("lead-1")})
	require.NoError(t, err)
	_, err = h.svc.Execute(ctx, "op-rejected")
	require.Equal(t, CodeApprovalRejected, CodeOf(err))

	undecided := h.establish(t, "op-undecided", "delete_records", args)
	granted := h.establish(t, "op-granted", "delete_records", args)
	h.approve(t, granted, lead("lead-1"))
	h.now = h.now.Add(31 * time.Minute) // expires_after: 30m
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: undecided.Operation.Approval.ID, Approve: true, Reviewer: lead("lead-1")})
	require.Equal(t, CodeApprovalExpired, CodeOf(err))
	for _, op := range []string{"op-undecided", "op-granted"} {
		_, err = h.svc.Execute(ctx, op)
		require.Equal(t, CodeApprovalExpired, CodeOf(err), op)
	}
	require.Equal(t, int64(0), h.down.calls.Load())
}

// The signed lifecycle of a rule-approved action verifies; with a record
// omitted or two sequence numbers exchanged it does not verify as valid.
func TestArgumentRules_LifecycleOmissionAndReorderAreDetected(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	res := h.establish(t, "op-mid", "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR"}`)
	h.approve(t, res, lead("lead-1"))
	_, err := h.svc.Execute(ctx, "op-mid")
	require.NoError(t, err)
	recs := h.lifecycle(t, "op-mid")
	require.Equal(t, LifecycleValid, VerifyLifecycle(recs, h.store.VerifyRecord).Verdict)
	require.GreaterOrEqual(t, len(recs), 5)

	for i := range recs {
		omitted := append(append([]*evidence.Evidence{}, recs[:i]...), recs[i+1:]...)
		f := VerifyLifecycle(omitted, h.store.VerifyRecord)
		require.NotEqual(t, LifecycleValid, f.Verdict, "omitting %s must not verify as valid", recs[i].ActionLifecycle.Event)
	}
	reversed := make([]*evidence.Evidence, len(recs))
	for i, r := range recs {
		reversed[len(recs)-1-i] = r
	}
	require.Equal(t, LifecycleValid, VerifyLifecycle(reversed, h.store.VerifyRecord).Verdict, "the order is the signed sequence, not the presentation order")
	for i := 0; i+1 < len(recs); i++ {
		swapped := make([]*evidence.Evidence, len(recs))
		for j, r := range recs {
			cp := *r
			l := *r.ActionLifecycle
			cp.ActionLifecycle = &l
			swapped[j] = &cp
		}
		swapped[i].ActionLifecycle.Sequence, swapped[i+1].ActionLifecycle.Sequence = swapped[i+1].ActionLifecycle.Sequence, swapped[i].ActionLifecycle.Sequence
		f := VerifyLifecycle(swapped, h.store.VerifyRecord)
		require.Equal(t, LifecycleInvalid, f.Verdict, "reordering %s and %s must be detected", recs[i].ActionLifecycle.Event, recs[i+1].ActionLifecycle.Event)
	}
	// The signed records carry the rule id, never an argument value.
	for _, r := range recs {
		raw, err := json.Marshal(r)
		require.NoError(t, err)
		require.NotContains(t, string(raw), "75.00")
		require.NotContains(t, string(raw), "T-9")
	}
}

// A crash after the dispatch was armed leaves the outcome unknown: the
// restart closes the attempt as UNKNOWN and nothing retries it.
func TestArgumentRules_RestartAfterArmedDispatchIsUnknown(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	res := h.establish(t, "op-small", "create_refund_request", `{"ticket_id":"T-9","amount":30.00,"currency":"EUR"}`)
	require.Equal(t, VerdictAllow, res.Operation.Verdict)
	h.down.lossy.Store(true) // the request is consumed, no response comes back
	exec, err := h.svc.Execute(ctx, "op-small")
	require.NoError(t, err)
	require.Equal(t, AttemptUnknown, exec.Attempt.Status)
	require.Equal(t, int64(1), h.down.calls.Load())
	h.down.lossy.Store(false)

	h2 := newHarnessWith(t, h.down, h.store, examplePolicy(h.down.srv.URL), testVaultKey)
	_, err = h2.svc.RecoverInterrupted(ctx)
	require.NoError(t, err)
	_, err = h2.svc.Execute(ctx, "op-small")
	require.Equal(t, CodeOperationOutcomeUnknown, CodeOf(err))
	require.Equal(t, int64(1), h.down.calls.Load(), "an unknown outcome is never retried")
}

// Machine-readable inspection never presents a name-only ALLOW as
// unconditional: an action with argument rules says so and lists them.
func TestArgumentRules_InspectionMarksArgumentDependentDecisions(t *testing.T) {
	pol := examplePolicy("http://127.0.0.1:9")
	ap := compiled(t, pol)
	cat, err := CompileCatalog(pol.Actions, nil)
	require.NoError(t, err)

	refund, ok := cat.DefinitionView("create_refund_request", ap)
	require.True(t, ok)
	require.Equal(t, VerdictAllow, refund.Verdict)
	require.Equal(t, DecisionByArguments, refund.DecisionBasis)
	require.Len(t, refund.ArgumentRules, 2)
	require.Equal(t, "amount gt 50", refund.ArgumentRules[0].Condition)
	require.Equal(t, EffectRequireApproval, refund.ArgumentRules[0].Effect)
	require.Equal(t, PolicySourceUseCase, refund.ArgumentRules[0].Source)

	deploy, _ := cat.DefinitionView("deploy_service", ap)
	conditions := []string{}
	for _, r := range deploy.ArgumentRules {
		conditions = append(conditions, r.Condition)
	}
	require.ElementsMatch(t, []string{`environment eq "production"`, `environment eq "sandbox-legacy"`}, conditions)

	notify, _ := cat.DefinitionView("notify_customer", ap)
	require.Equal(t, DecisionByName, notify.DecisionBasis)
	require.Empty(t, notify.ArgumentRules)
	forbidden, _ := cat.DefinitionView("delete_customer", ap)
	require.Equal(t, VerdictDeny, forbidden.Verdict)
	require.Equal(t, DecisionByName, forbidden.DecisionBasis, "a forbidden action is denied whatever its arguments")
}
