package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/mcp/wire"
)

// evidenceToken is the complete grammar of what the MCP routes may store as
// a policy reason or execution error: a stable identifier, optionally one
// validated field name or numeric limit, or (for upstream failures) a
// kind/code/category suffix. Anything else is free text and is a bug.
var evidenceToken = regexp.MustCompile(`^[a-z_]+(:(field|limit|threshold)=[A-Za-z0-9_.-]{1,64}|: (code=-?\d+ category=[a-z_]+|[a-z_]+))?$`)

// assertOnlyEvidenceTokens checks every free-text-capable field of a signed
// record against the token grammar: policy reasons, the execution error and
// each explanation's trigger (the reason/fix texts are Talon's own catalog
// strings and are checked not to echo a reason verbatim by the callers).
func assertOnlyEvidenceTokens(t *testing.T, rec *evidence.Evidence) {
	t.Helper()
	for _, r := range rec.PolicyDecision.Reasons {
		assert.Regexp(t, evidenceToken, r, "policy reason is not a token")
	}
	if rec.Execution.Error != "" {
		assert.Regexp(t, evidenceToken, rec.Execution.Error, "execution error is not a token")
	}
	for i := range rec.Explanations {
		if trig := rec.Explanations[i].Trigger; trig != "" {
			assert.Regexp(t, evidenceToken, trig, "explanation trigger is not a token")
		}
	}
}

// Every denial template Talon's rego can emit maps to its token; anything
// else — including text that merely contains the vocabulary words, carries
// ordinary identifiers, or almost matches a template — is the opaque token.
func TestPolicyReasonTokens(t *testing.T) {
	for in, want := range map[string]string{
		"Tool 'crm_lookup' not in allowed_tools list":                                                                            "tool_not_allowed",
		"Tool 'crm_lookup' not in allowed_tools":                                                                                 "tool_not_allowed",
		"Tool 'delete_customer' is forbidden by policy":                                                                          "tool_forbidden",
		"Tool 'x' is in allowed_tools but overridden by forbidden_tools":                                                         "tool_forbidden_override",
		"Tool 'drop_table' matches destructive pattern; requires explicit allowed_tools entry":                                   "tool_destructive_pattern",
		"Admin operation 'tools/list' requires explicit allow":                                                                   "admin_operation_requires_allow",
		"File path matches a forbidden pattern (capabilities.forbidden_patterns)":                                                "forbidden_path_pattern",
		"estimated_row_count exceeds policy limit 1000 for tool bulk_update":                                                     "row_count_exceeded:limit=1000",
		"dry_run required for bulk_update when estimated_row_count > 500":                                                        "dry_run_required:threshold=500",
		"argument recipient has a forbidden value for tool pay (tool_policies.forbidden_argument_values)":                        "forbidden_argument_value:field=recipient",
		"argument private.person@example.test has a forbidden value for tool pay (tool_policies.forbidden_argument_values)":      opaquePolicyReason, // field name fails validation
		"argument " + string(make([]byte, 65)) + " has a forbidden value for tool pay (tool_policies.forbidden_argument_values)": opaquePolicyReason,
		"Tool rejected for customer private.person@example.test":                                                                 opaquePolicyReason,
		"Tool 'only_this' is forbidden by policy for account CUST-7391":                                                          opaquePolicyReason,
		"forbidden: CUST-7391 private.person@example.test":                                                                       opaquePolicyReason,
		"argument api_key=sk-live-123 is forbidden for tool x":                                                                   opaquePolicyReason,
		"Tool 'x' not in allowed_tools list; see https://user:pw@internal/host":                                                  opaquePolicyReason,
		"estimated_row_count exceeds policy limit 1000000000000000 for tool t":                                                   opaquePolicyReason, // limit too long to be a policy limit
		"policy denied": opaquePolicyReason,
	} {
		got := policyReasonTokens([]string{in})
		require.Len(t, got, 1, in)
		assert.Equal(t, want, got[0], in)
		assert.Regexp(t, evidenceToken, got[0])
		assert.NotEqual(t, explanation.CodeLegacyReasonUnmigrated,
			explanation.BuildLegacyFacts(false, "deny", got, explanation.StagePolicyEvaluation, "", "")[0].Code,
			"every token classifies as a policy denial in the signed explanation: %s", got[0])
	}
	assert.Nil(t, policyReasonTokens(nil))
	assert.Empty(t, policyReasonTokens([]string{"", "  "}), "blank reasons are dropped, not tokenized")
}

func TestVendorErrorToken(t *testing.T) {
	for code, cat := range map[int]string{
		-32700: "parse_error", -32600: "invalid_request", -32601: "method_not_found", -32602: "invalid_params",
		-32603: "internal_error", -32000: "server_error", -32001: "server_error", -32099: "server_error",
		-32100: "vendor_defined", 1: "vendor_defined", 0: "vendor_defined",
	} {
		got := vendorErrorToken("upstream_jsonrpc_error", code)
		assert.Equal(t, fmt.Sprintf("upstream_jsonrpc_error: code=%d category=%s", code, cat), got)
		assert.Regexp(t, evidenceToken, got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "dial tcp 10.0.0.9:443: i/o timeout to vendor.internal" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

func TestUpstreamFailureToken(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		kind string
	}{
		"protocol":    {fmt.Errorf("%w: unsupported Content-Type %q", wire.ErrUpstreamProtocol, "text/html; charset=utf-8"), "protocol_violation"},
		"status":      {fmt.Errorf("%w: 502 from https://user:pw@vendor.internal/mcp", wire.ErrUpstreamStatus), "http_status"},
		"redirect":    {fmt.Errorf("%w: to http://169.254.169.254/", wire.ErrRedirectRefused), "redirect_refused"},
		"type":        {wire.ErrResultTypeMissing, "result_type_missing"},
		"unsupported": {fmt.Errorf("%w: task", wire.ErrResultTypeUnsupported), "result_type_unsupported"},
		"list":        {wire.ErrListResultInvalid, "list_result_invalid"},
		"deadline":    {context.DeadlineExceeded, "timeout"},
		"net timeout": {timeoutErr{}, "timeout"},
		"net":         {&net.OpError{Op: "dial", Err: errors.New("connection refused by 10.0.0.9")}, "transport"},
		"eof":         {io.ErrUnexpectedEOF, "connection_closed"},
		"secret":      {fmt.Errorf("%w: vault at /var/lib/talon/vault.db", errSecretRetrieval), "secret_retrieval"},
		"other":       {errors.New("customer CUST-7391 private.person@example.test"), "unclassified"},
	} {
		t.Run(name, func(t *testing.T) {
			got := upstreamFailureToken("upstream_error", tc.err)
			assert.Equal(t, "upstream_error: "+tc.kind, got)
			assert.Regexp(t, evidenceToken, got)
			assert.True(t, upstreamOutcomeUnknown(got), "post-dispatch upstream failures keep the unknown-outcome prefix")
		})
	}
}

// Regression for the final PR #493 finding: ordinary identifiers (an e-mail
// address, a customer id — nothing secret-shaped) placed in a denial reason
// by a policy engine, on both routes, never reach any field of the signed
// record or its explanations; the record holds tokens only and verifies.
func TestSafety_OrdinaryIdentifiersNeverReachEvidence(t *testing.T) {
	identifiers := []string{"private.person@example.test", "CUST-7391", "Acme Holdings"}
	reasons := []string{
		"Tool rejected for customer private.person@example.test",
		"Tool 'crm_lookup' is forbidden by policy for CUST-7391 (Acme Holdings)",
		"Tool 'crm_lookup' is forbidden by policy",
	}
	check := func(t *testing.T, store *evidence.Store, out map[string]any, raw string) {
		t.Helper()
		ext := governanceOf(t, out)
		require.NotNil(t, ext)
		assert.Equal(t, publicPolicyDenied, out["error"].(map[string]any)["message"])
		assert.Equal(t, explanation.CodePolicyDeniedTool, ext["reasonCode"])
		for _, p := range identifiers {
			assert.NotContains(t, raw, p, "public response leaks %q", p)
		}
		rec, err := store.Get(context.Background(), ext["evidence"].(map[string]any)["id"].(string))
		require.NoError(t, err)
		require.True(t, store.VerifyRecord(rec), "the signed record verifies")
		js, _ := json.Marshal(rec)
		for _, p := range append(identifiers, "rejected", "customer") {
			assert.NotContains(t, string(js), p, "the entire signed record is free of %q: %s", p, js)
		}
		assert.Equal(t, []string{opaquePolicyReason, opaquePolicyReason, "tool_forbidden"}, rec.PolicyDecision.Reasons)
		assertOnlyEvidenceTokens(t, rec)
		require.NotEmpty(t, rec.Explanations)
		assert.Equal(t, explanation.CodePolicyDeniedTool, rec.Explanations[0].Code)
		assert.Equal(t, ext["reasonCode"], rec.Explanations[0].Code)
	}

	t.Run("native", func(t *testing.T) {
		h, store, _ := nativeDenyFixture(t)
		tool := &capturingTool{name: "crm_lookup"}
		h.registry = tools.NewRegistry()
		h.registry.Register(tool)
		h.policyEngine = denyingToolEvaluator{reasons: reasons}
		out := callNative(t, h, "crm_lookup", 31)
		raw, _ := json.Marshal(out)
		check(t, store, out, string(raw))
		assert.Equal(t, 0, tool.executions())
	})
	t.Run("proxy", func(t *testing.T) {
		hit := false
		up := attribUpstream(t, &hit)
		h, store := attribHandler(t, up.URL, nil)
		h.proxyEngine = denyingProxyEvaluator{reasons: reasons}
		rec, out := do(t, h, "/mcp/proxy", mcpBody(t, 32, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
		check(t, store, out, rec.Body.String())
		assert.False(t, hit, "the upstream was never contacted")
	})
}
