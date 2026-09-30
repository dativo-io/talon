package action

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
)

func TestCanonicalize(t *testing.T) {
	cases := map[string]string{
		`{"b":1,"a":{"y":[3,2,1],"x":null}}`:  `{"a":{"x":null,"y":[3,2,1]},"b":1}`,
		"{ \"amount\" : 50.00 , \"n\": 1e2 }": `{"amount":50.00,"n":1e2}`,
		`{"s":"<a>&é"}`:                       `{"s":"<a>&é"}`,
		`[]`:                                  `[]`,
		`{"z":{},"a":[{"k":true}]}`:           `{"a":[{"k":true}],"z":{}}`,
	}
	for in, want := range cases {
		got, err := Canonicalize([]byte(in))
		require.NoError(t, err, in)
		require.Equal(t, want, string(got), in)
	}
	a, _ := Canonicalize([]byte(`{"amount":50}`))
	b, _ := Canonicalize([]byte(`{"amount":50.0}`))
	require.NotEqual(t, Digest(a), Digest(b), "1 and 1.0 are different material arguments")
	c, _ := Canonicalize([]byte(`{"note":null}`))
	d, _ := Canonicalize([]byte(`{}`))
	require.NotEqual(t, Digest(c), Digest(d), "explicit null is not absence")
	for _, bad := range []string{`{"a":1,"a":2}`, `{"a":1} x`, `{`, `"\xff"`, `{"a":` + deep(40) + `}`} {
		_, err := Canonicalize([]byte(bad))
		require.Error(t, err, bad)
	}
}

func deep(n int) string {
	s := "1"
	for i := 0; i < n; i++ {
		s = "[" + s + "]"
	}
	return s
}

func TestCompileCatalog_FailsClosed(t *testing.T) {
	good := policy.ActionDefinitionConfig{InputSchema: map[string]any{"type": "object"}, Destination: policy.ActionDestinationConfig{Type: "http", URL: "https://api.example/x"}}
	for name, cfg := range map[string]policy.ActionDefinitionConfig{
		"Bad-Name":   good,
		"no_schema":  {Destination: good.Destination},
		"not_object": {InputSchema: map[string]any{"type": "string"}, Destination: good.Destination},
		"plain_http": {InputSchema: good.InputSchema, Destination: policy.ActionDestinationConfig{Type: "http", URL: "http://api.example/x"}},
		"creds":      {InputSchema: good.InputSchema, Destination: policy.ActionDestinationConfig{Type: "http", URL: "https://u:p@api.example/x"}},
		"bad_type":   {InputSchema: good.InputSchema, Destination: policy.ActionDestinationConfig{Type: "grpc", URL: "https://api.example/x"}},
	} {
		_, err := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{name: cfg}})
		require.Error(t, err, name)
	}
	cat, err := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"ok": good, "loop": {InputSchema: good.InputSchema, Destination: policy.ActionDestinationConfig{Type: "http", URL: "http://127.0.0.1:9/x"}}}})
	require.NoError(t, err)
	require.Equal(t, []string{"loop", "ok"}, cat.Names())
	d, _ := cat.Lookup("ok")
	require.Equal(t, "POST", d.Destination.Method)
	require.Equal(t, ExecutionProfileTalonForwarded, d.ExecutionProfile)
	cat2, _ := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"loop": {InputSchema: good.InputSchema, Destination: policy.ActionDestinationConfig{Type: "http", URL: "http://127.0.0.1:9/x"}}, "ok": good}})
	require.Equal(t, cat.Digest, cat2.Digest, "catalog digest is order-independent")
}

func TestVerdictPrecedence(t *testing.T) {
	pol := &policy.Policy{
		Capabilities: &policy.CapabilitiesConfig{ForbiddenTools: []string{"publish_release"}},
		Policies: policy.PoliciesConfig{Approvals: &policy.ApprovalsConfig{Rules: map[string]policy.ApprovalRuleConfig{
			"releases": {Actions: []string{"publish_*"}, ApproverGroups: []string{"release-managers"}},
		}}},
	}
	ap, err := CompileApprovalPolicy(pol)
	require.NoError(t, err)
	require.Equal(t, VerdictDeny, ap.Evaluate("publish_release").Outcome, "DENY beats a matching approval rule")
	v := ap.Evaluate("publish_docs")
	require.Equal(t, VerdictRequireApproval, v.Outcome)
	require.Equal(t, "releases", v.RuleID)
	require.Equal(t, []string{"release-managers"}, v.ApproverGroups)
	require.Equal(t, VerdictAllow, ap.Evaluate("notify").Outcome)
	require.Equal(t, DefaultApprovalLifetime, ap.ExpiresAfter)

	ap2, _ := CompileApprovalPolicy(pol)
	require.Equal(t, ap.Digest, ap2.Digest)
	pol.Policies.Approvals.Rules["releases"] = policy.ApprovalRuleConfig{Actions: []string{"publish_*"}, ApproverGroups: []string{"anyone"}}
	ap3, _ := CompileApprovalPolicy(pol)
	require.NotEqual(t, ap.Digest, ap3.Digest, "approver groups are approval-relevant")
	_, err = CompileApprovalPolicy(&policy.Policy{Policies: policy.PoliciesConfig{Approvals: &policy.ApprovalsConfig{ExpiresAfter: "never"}}})
	require.Error(t, err)
	_, err = CompileApprovalPolicy(&policy.Policy{Policies: policy.PoliciesConfig{Approvals: &policy.ApprovalsConfig{Rules: map[string]policy.ApprovalRuleConfig{"r": {Actions: []string{"x"}}}}}})
	require.Error(t, err, "rule without approver groups fails closed")
}
