package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
)

func sampleReview(now time.Time) *action.ApprovalView {
	return &action.ApprovalView{
		ApprovalID: "apr_0123456789abcdef0123", Tenant: "default", UseCase: "support-agent", Action: "refund_payment",
		ActionDescription: "Refund a customer payment", Status: action.ApprovalPending, Unresolved: true,
		Eligibility: action.Eligibility{
			State: action.EligibilityEligible, Class: action.ClassActionable, Basis: action.CurrentRuntime,
			Explanation: "an eligible reviewer can approve or reject this now", Policy: action.BindingUnchanged, Definition: action.BindingUnchanged,
		},
		ApproverGroups: []string{"finance-approvers"}, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(42 * time.Minute),
		Disclosure: "reviewer",
		Arguments: []action.ReviewArgument{
			{Name: "amount", Value: json.RawMessage(`250.00`)}, {Name: "currency", Value: json.RawMessage(`"EUR"`)}, {Name: "customer_id", Value: json.RawMessage(`"c_1042"`)},
		},
		Bound: action.ApprovalBound{
			RuleID: "refund-over-100", RuleSource: "company", Destination: "POST https://payments.internal/refunds",
			ArgumentsDigest: "sha256:args", DefinitionDigest: "sha256:def", PolicyDigest: "sha256:pol", EstablishedAt: now.Add(-time.Minute),
		},
		Current:       action.ApprovalCurrent{Basis: action.CurrentRuntime, Rule: "company argument rule refund-over-100: a call of refund_payment where amount gt 100 (decimal) requires approval by finance-approvers", RulePresent: true},
		Operation:     action.ApprovalOperation{OperationID: "refund-c1042-1", OperationRef: "op_1", Status: "awaiting_approval", Verdict: "REQUIRE_APPROVAL"},
		AfterApproval: "An approval authorizes this exact operation and dispatches nothing.",
	}
}

// `talon approvals show` answers in the operator's order, prints the exact
// material values, uses the complete approval id in every command, and
// keeps identifiers and digests behind --technical.
func TestApprovalsShow_InformationHierarchy(t *testing.T) {
	now := time.Date(2026, 11, 19, 13, 23, 0, 0, time.UTC)
	var b bytes.Buffer
	printReview(&b, sampleReview(now), now, false)
	out := b.String()
	order := []string{
		"Refund a customer payment  (refund_payment)", "Requested by", "AI use case support-agent (tenant default)",
		"Status", "CAN BE DECIDED NOW, expires 2026-11-19 14:05 UTC (in 42m)",
		"Arguments", "amount           250.00", `currency         "EUR"`, `customer_id      "c_1042"`,
		"Destination", "POST https://payments.internal/refunds",
		"Why", "rule refund-over-100 of the company policy required approval by finance-approvers. The rule: company argument rule refund-over-100",
		"Still current", "policy unchanged, action definition unchanged",
		"Decision", "none yet", "Outcome", "nothing was dispatched",
		`talon approvals approve apr_0123456789abcdef0123 --reason "..."`,
		`talon approvals reject apr_0123456789abcdef0123 --reason "..."`,
		"After approval", "talon approvals show apr_0123456789abcdef0123 --technical",
	}
	at := 0
	for _, want := range order {
		i := strings.Index(out[at:], want)
		require.GreaterOrEqual(t, i, 0, "%q missing or out of order in:\n%s", want, out)
		at += i + len(want)
	}
	for _, hidden := range []string{"sha256:args", "sha256:pol", "sha256:def", "op_1", "Technical details"} {
		require.NotContains(t, out, hidden, "identifiers and digests are shown with --technical only")
	}

	b.Reset()
	printReview(&b, sampleReview(now), now, true)
	for _, shown := range []string{"Technical details", "sha256:args", "sha256:pol", "sha256:def", "refund-c1042-1 (ref op_1)", "talon audit verify --operation refund-c1042-1", "runtime (policy unchanged, action definition unchanged)"} {
		require.Contains(t, b.String(), shown)
	}

	// Decided: who, when, why, and what happened afterwards; no decision
	// command is offered any more.
	v := sampleReview(now)
	decided := now.Add(-10 * time.Minute)
	v.Status, v.Unresolved = action.ApprovalApproved, false
	v.Eligibility = action.Eligibility{State: action.EligibilityDecided, Class: action.ClassDecided, Basis: "record", Explanation: "this approval is already approved; no further decision is possible", Policy: action.BindingUnknown, Definition: action.BindingUnknown}
	v.Decision = &action.ApprovalDecision{Status: action.ApprovalApproved, DecidedAt: &decided, DecidedBy: "apr_ops", DecidedGroup: "finance-approvers", Reason: "customer verified"}
	v.Operation.Status, v.Operation.AttemptCount, v.Operation.OutcomeCode = "succeeded", 1, "ACTION_COMPLETED"
	v.Operation.LatestAttempt = &action.ApprovalAttempt{Ordinal: 1, Status: "completed", HTTPStatus: 201, ResultProvenance: "observed", RequestWritten: true, ResponseObserved: true}
	b.Reset()
	printReview(&b, v, now, false)
	out = b.String()
	require.Contains(t, out, "Status         APPROVED")
	require.Contains(t, out, `approved by apr_ops (group finance-approvers) at 2026-11-19 13:13 UTC. Reason: "customer verified"`)
	require.Contains(t, out, "operation succeeded; 1 dispatch attempt(s), latest completed, destination answered HTTP 201 (observed), outcome ACTION_COMPLETED")
	require.NotContains(t, out, "talon approvals approve")

	// Unresolved but not decidable: said plainly, no decision command.
	v = sampleReview(now)
	v.Eligibility = action.Eligibility{State: action.EligibilityStalePolicy, Class: action.ClassNotDecidable, Basis: action.CurrentRuntime, Explanation: "the approval-relevant policy changed", Policy: action.BindingChanged, Definition: action.BindingUnchanged}
	b.Reset()
	printReview(&b, v, now, false)
	require.Contains(t, b.String(), "CANNOT BE DECIDED (stale policy); still unresolved in the store")
	require.Contains(t, b.String(), "The rule as it reads TODAY (not necessarily as it read then)")
	require.Contains(t, b.String(), "policy CHANGED since establish")
	require.NotContains(t, b.String(), "talon approvals approve")
}

// The listing is compact: one line per approval with its complete id, and
// no argument name or value.
func TestApprovalsList_Compact(t *testing.T) {
	now := time.Date(2026, 11, 19, 13, 23, 0, 0, time.UTC)
	v := sampleReview(now)
	row := action.ApprovalSummary{ApprovalID: v.ApprovalID, Tenant: v.Tenant, UseCase: v.UseCase, Action: v.Action, Status: v.Status, Unresolved: true, Eligibility: v.Eligibility, ApproverGroups: v.ApproverGroups, ExpiresAt: v.ExpiresAt}
	stale := row
	stale.ApprovalID = "apr_ffffffffffffffffffff"
	stale.Eligibility = action.Eligibility{State: action.EligibilityExpired, Class: action.ClassNotDecidable}
	stale.ExpiresAt = now.Add(-time.Hour)
	var b bytes.Buffer
	printApprovalList(&b, &approvalsListResponse{Tenant: "default", State: action.SelectUnresolved, Approvals: []action.ApprovalSummary{row, stale}, Next: "CURSOR"}, now, false)
	out := b.String()
	require.Regexp(t, `apr_0123456789abcdef0123\s+refund_payment\s+support-agent\s+can be decided\s+in 42m\s+finance-approvers`, out)
	require.Regexp(t, `apr_ffffffffffffffffffff\s+refund_payment\s+support-agent\s+expired\s+expired\s+finance-approvers`, out)
	require.Contains(t, out, "talon approvals list --all --after CURSOR")
	require.Contains(t, out, "talon approvals show <approval>")
	for _, absent := range []string{"amount", "250.00", "c_1042", "currency"} {
		require.NotContains(t, out, absent)
	}
	b.Reset()
	printApprovalList(&b, &approvalsListResponse{Tenant: "default", State: action.SelectAttention}, now, false)
	require.Contains(t, b.String(), "Approvals of your groups that need a decision in tenant default: none.")
	require.Contains(t, b.String(), "talon approvals list --all")
}

// The approver credential is sent to the URL the operator gave and nowhere
// else: a redirect, to another host or to plain http on the same one, is
// not followed (#565 review).
func TestApprovalsRequest_NeverFollowsARedirectWithTheCredential(t *testing.T) {
	var elsewhereHits atomic.Int64
	var leaked atomic.Value
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhereHits.Add(1)
		leaked.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"tenant":"x","approvals":[]}`))
	}))
	defer elsewhere.Close()
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+r.URL.Path, code)
		}))
		t.Setenv(approverKeyEnv, "talon_appr_test_credential")
		approvalsURL = first.URL
		var out map[string]any
		_, err := approvalsRequest(context.Background(), http.MethodGet, "/v1/reviews", nil, &out)
		require.Error(t, err, "HTTP %d", code)
		require.Contains(t, err.Error(), "redirect")
		require.NotContains(t, err.Error(), "talon_appr_test_credential")
		_, err = approvalsRequest(context.Background(), http.MethodPost, "/v1/approvals/apr_1/decisions", []byte(`{"decision":"approve","reason":"x"}`), &out)
		require.Error(t, err, "HTTP %d", code)
		first.Close()
	}
	require.Zero(t, elsewhereHits.Load(), "the redirect target never received a request (credential %v)", leaked.Load())
	approvalsURL = "http://localhost:8080"
}

// The CLI asks for a reason for an approval AND for a rejection and sends
// nothing without one; the decision API's own rule is the v1.16.1 one
// (internal/server TestDecisionAPI_ReasonContractIsTheV1161One).
func TestApprovalsDecide_CLIRequiresAReasonForBothDecisions(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"operation":{"operation_id":"op","operation_status":"authorized"},"approval":{"id":"apr_1","status":"approved","decided_by":"apr_ops","decided_group":"g"}}`))
	}))
	defer srv.Close()
	t.Setenv(approverKeyEnv, "talon_appr_test_credential")
	approvalsURL = srv.URL
	defer func() { approvalsURL, approvalsReason = "http://localhost:8080", "" }()
	for _, approve := range []bool{true, false} {
		c := decideCmd(map[bool]string{true: "approve", false: "reject"}[approve], approve)
		c.SetContext(context.Background())
		var out bytes.Buffer
		c.SetOut(&out)
		for _, blank := range []string{"", "   "} {
			approvalsReason = blank
			err := c.RunE(c, []string{"apr_1"})
			require.ErrorContains(t, err, "--reason is required")
		}
		require.Zero(t, hits.Load(), "nothing is sent without a reason")
		approvalsReason = "verified"
		require.NoError(t, c.RunE(c, []string{"apr_1"}))
		require.Contains(t, out.String(), "nothing was dispatched by this decision")
		require.Equal(t, int64(1), hits.Load())
		hits.Store(0)
	}
}

// #565 review, finding 4 (reproduction): a page can be empty although the
// selection is not exhausted (the server stops a page at its scan bound and
// returns a cursor). The CLI must not print "none" then.
func TestApprovalsList_EmptyPageWithACursorIsNotAnEmptySelection(t *testing.T) {
	var b bytes.Buffer
	now := time.Now().UTC()
	printApprovalList(&b, &approvalsListResponse{Tenant: "acme", State: action.SelectAttention, Approvals: nil, Next: "Y3Vyc29y"}, now, false)
	out := b.String()
	require.NotContains(t, out, "none.", "the selection is not exhausted: nothing may claim it is empty\n%s", out)
	require.NotContains(t, out, "More exist", "nothing was listed yet")
	require.Contains(t, out, "The listing is NOT exhausted")
	require.Contains(t, out, "Continue: talon approvals list --after Y3Vyc29y")

	// The same for the other selections, with their flag in the command.
	b.Reset()
	printApprovalList(&b, &approvalsListResponse{Tenant: "acme", State: action.SelectUnresolved, Next: "Y3Vyc29y"}, now, true)
	require.Contains(t, b.String(), "Continue: talon approvals list --all --after Y3Vyc29y")
	require.NotContains(t, b.String(), "none.")

	// A page reached with --after that holds nothing and has no cursor is
	// the end of a listing, not an empty selection.
	b.Reset()
	printApprovalList(&b, &approvalsListResponse{Tenant: "acme", State: action.SelectAttention}, now, true)
	require.Contains(t, b.String(), "no further approvals. This is the end of the listing.")
	require.NotContains(t, b.String(), "none.")

	// Only a first page without rows and without a cursor is "none".
	b.Reset()
	printApprovalList(&b, &approvalsListResponse{Tenant: "acme", State: action.SelectAttention}, now, false)
	require.Contains(t, b.String(), "in tenant acme: none.")
}

// #565 review, finding 6. The approver credential is sent to --url. The URL
// is therefore validated strictly and completely before any request: http
// or https only, a host, no embedded credentials, no query or fragment (the
// request path is appended to it), and plain http only to loopback unless
// --allow-plaintext says the path is protected.
func TestApprovalsURL_StrictValidation(t *testing.T) {
	for _, tc := range []struct {
		raw       string
		plaintext bool
		ok        bool
		why       string
	}{
		{"http://localhost:8080", false, true, "loopback"},
		{"http://127.0.0.1:8080/", false, true, "loopback, trailing slash"},
		{"http://[::1]:8080", false, true, "IPv6 loopback"},
		{"https://talon.example.com", false, true, "https"},
		{"https://talon.example.com/talon/", false, true, "a path prefix behind a reverse proxy"},
		{"http://talon.internal:8080", true, true, "plain http, stated as protected"},
		{"http://talon.internal:8080", false, false, "plain http to a remote host"},
		{"ftp://talon.example.com", true, false, "--allow-plaintext must not admit another scheme"},
		{"gopher://localhost", false, false, "not http(s)"},
		{"localhost:8080", false, false, "no scheme"},
		{"talon.example.com", false, false, "no scheme"},
		{"https://", false, false, "no host"},
		{"https://:8443", false, false, "a port without a host"},
		{"https://operator:secret@talon.example.com", false, false, "credentials embedded in the URL"},
		{"https://talon.example.com?tenant=acme", false, false, "a query: the request path is appended to the base URL"},
		{"https://talon.example.com/#frag", false, false, "a fragment"},
		{"https://talon.example.com:notaport", false, false, "an invalid port"},
		{"https://talon.example.com/a b", false, false, "whitespace"},
		{"https://talon.example.com/talon?", false, false, "an empty query"},
		{"https://talon.example.com/talon#", false, false, "an empty fragment"},
		{"HTTPS://talon.example.com", false, true, "the scheme is case-insensitive"},
		{" https://talon.example.com", false, false, "leading whitespace"},
		{"https://talon.example.com\n.evil.example", false, false, "a control character"},
		{"", false, false, "empty"},
	} {
		u, err := approvalsBaseURL(tc.raw, tc.plaintext)
		if tc.ok {
			require.NoError(t, err, "%q: %s", tc.raw, tc.why)
			require.NotNil(t, u)
		} else {
			require.Error(t, err, "%q must be refused: %s", tc.raw, tc.why)
			require.NotContains(t, err.Error(), "secret", "an error never repeats a password from the URL")
		}
	}

	// The request path is appended to the validated base, prefix kept.
	u, err := approvalsBaseURL("https://talon.example.com/talon/", false)
	require.NoError(t, err)
	require.Equal(t, "https://talon.example.com/talon/v1/reviews?state=attention", approvalsEndpoint(u, "/v1/reviews?state=attention"))
	u, err = approvalsBaseURL("http://localhost:8080", false)
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8080/v1/reviews/apr_1", approvalsEndpoint(u, "/v1/reviews/apr_1"))
}

// No request leaves the process for a URL that fails validation: the
// credential is never sent to a host the operator did not clearly name.
func TestApprovalsRequest_InvalidURLSendsNothing(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { atomic.AddInt32(&hits, 1) }))
	defer srv.Close()
	t.Setenv(approverKeyEnv, "talon_appr_test_credential_0001")
	old := approvalsURL
	t.Cleanup(func() { approvalsURL = old })
	for _, bad := range []string{srv.URL + "?x=1", srv.URL + "#f", strings.Replace(srv.URL, "http://", "http://operator:secret@", 1), strings.Replace(srv.URL, "http://", "ftp://", 1)} {
		approvalsURL = bad
		var out map[string]any
		_, err := approvalsRequest(context.Background(), http.MethodGet, "/v1/reviews", nil, &out)
		require.Error(t, err, bad)
	}
	require.Zero(t, atomic.LoadInt32(&hits), "a refused URL must not receive the credential")
}
