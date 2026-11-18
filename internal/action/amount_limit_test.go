package action

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
)

// refundBands is the illustrative refund policy of #205 / #561: up to
// 50.00 EUR allow, up to 500.00 EUR approval by support-leads, above deny.
func refundBands(allow, approval string) policy.AmountLimitConfig {
	return policy.AmountLimitConfig{
		Actions: []string{"create_refund_request"}, AmountArgument: "amount", CurrencyArgument: "currency",
		Currency: "EUR", AllowUpTo: allow, ApprovalUpTo: approval, ApproverGroups: []string{"support-leads"},
	}
}

// limitPolicy is testPolicy with the name-only refund approval rule
// replaced by the refund amount bands.
func limitPolicy(url string) *policy.Policy {
	pol := testPolicy(url)
	pol.Policies.Approvals = &policy.ApprovalsConfig{ExpiresAfter: "30m", AmountLimits: map[string]policy.AmountLimitConfig{
		"refund-bands": refundBands("50.00", "500.00"),
	}}
	return pol
}

func refund(amount string) []byte {
	return []byte(`{"amount":` + amount + `,"currency":"EUR","ticket_id":"T-1"}`)
}

func TestAmountLimit_Bands(t *testing.T) {
	ap, err := CompileApprovalPolicy(limitPolicy("http://x"))
	require.NoError(t, err)
	cases := []struct {
		amount, want string
	}{
		{`0`, VerdictAllow},
		{`49.99`, VerdictAllow},
		{`50`, VerdictAllow},
		{`50.00`, VerdictAllow},
		{`"50.00"`, VerdictAllow},
		{`50.01`, VerdictRequireApproval},
		{`"75.5"`, VerdictRequireApproval},
		{`500.00`, VerdictRequireApproval},
		{`500.01`, VerdictDeny},
		{`900`, VerdictDeny},
		{`"999999999999999.99"`, VerdictDeny},
	}
	for _, c := range cases {
		v := ap.EvaluateArguments("create_refund_request", refund(c.amount))
		require.Equal(t, c.want, v.Outcome, "amount %s: %s", c.amount, v.Reason)
		if c.want != VerdictAllow {
			require.Equal(t, "refund-bands", v.RuleID)
			require.Equal(t, PolicySourceUseCase, v.Source)
		}
		if c.want == VerdictRequireApproval {
			require.Equal(t, []string{"support-leads"}, v.ApproverGroups)
			require.Contains(t, v.Reason, "requires approval")
		}
	}
	// Other actions are untouched by the limit.
	require.Equal(t, VerdictAllow, ap.EvaluateArguments("notify_customer", []byte(`{"ticket_id":"T"}`)).Outcome)
	// The name-only verdict ignores limits; it is never used to authorize.
	require.Equal(t, VerdictAllow, ap.Evaluate("create_refund_request").Outcome)
}

// Every argument the band cannot establish is a DENY, never an ALLOW.
func TestAmountLimit_UnestablishedAmountDenies(t *testing.T) {
	ap, err := CompileApprovalPolicy(limitPolicy("http://x"))
	require.NoError(t, err)
	cases := map[string]string{
		"missing amount":          `{"currency":"EUR"}`,
		"null amount":             `{"amount":null,"currency":"EUR"}`,
		"negative number":         `{"amount":-1,"currency":"EUR"}`,
		"negative string":         `{"amount":"-0.01","currency":"EUR"}`,
		"exponent":                `{"amount":1e1,"currency":"EUR"}`,
		"three fractional digits": `{"amount":10.001,"currency":"EUR"}`,
		"leading zero":            `{"amount":"010","currency":"EUR"}`,
		"boolean":                 `{"amount":true,"currency":"EUR"}`,
		"object":                  `{"amount":{"v":1},"currency":"EUR"}`,
		"words":                   `{"amount":"ten","currency":"EUR"}`,
		"padded string":           `{"amount":" 10","currency":"EUR"}`,
		"too many digits":         `{"amount":"1000000000000000","currency":"EUR"}`,
		"missing currency":        `{"amount":10}`,
		"currency not a string":   `{"amount":10,"currency":1}`,
		"other currency":          `{"amount":10,"currency":"USD"}`,
		"lower-case currency":     `{"amount":10,"currency":"eur"}`,
		"not an object":           `[10,"EUR"]`,
		"no arguments":            ``,
	}
	for name, args := range cases {
		v := ap.EvaluateArguments("create_refund_request", []byte(args))
		require.Equal(t, VerdictDeny, v.Outcome, "%s: %s", name, v.Reason)
		require.Equal(t, "refund-bands", v.RuleID, name)
	}
}

func TestAmountLimit_CompanyLayering(t *testing.T) {
	company := &CompanyActionPolicy{Source: "test", AmountLimits: map[string]policy.AmountLimitConfig{"refund-bands": refundBands("50.00", "500.00")}}

	t.Run("a use case cannot lift the company bands", func(t *testing.T) {
		pol := limitPolicy("http://x")
		pol.Policies.Approvals.AmountLimits = map[string]policy.AmountLimitConfig{"generous": refundBands("1000.00", "5000.00")}
		ap, err := CompileEffectiveActionPolicy(pol, company)
		require.NoError(t, err)
		v := ap.EvaluateArguments("create_refund_request", refund(`75`))
		require.Equal(t, VerdictRequireApproval, v.Outcome)
		require.Equal(t, "company:refund-bands", v.RuleID)
		require.Equal(t, PolicySourceCompany, v.Source)
		v = ap.EvaluateArguments("create_refund_request", refund(`600`))
		require.Equal(t, VerdictDeny, v.Outcome)
		require.Equal(t, "company:refund-bands", v.RuleID)
	})
	t.Run("a use case can tighten the company bands", func(t *testing.T) {
		pol := limitPolicy("http://x")
		pol.Policies.Approvals.AmountLimits = map[string]policy.AmountLimitConfig{"tight": refundBands("20.00", "200.00")}
		ap, err := CompileEffectiveActionPolicy(pol, company)
		require.NoError(t, err)
		require.Equal(t, VerdictAllow, ap.EvaluateArguments("create_refund_request", refund(`20`)).Outcome)
		v := ap.EvaluateArguments("create_refund_request", refund(`30`))
		require.Equal(t, VerdictRequireApproval, v.Outcome)
		require.Equal(t, "tight", v.RuleID)
		v = ap.EvaluateArguments("create_refund_request", refund(`300`))
		require.Equal(t, VerdictDeny, v.Outcome)
		require.Equal(t, "tight", v.RuleID)
	})
	t.Run("a company forbidden action is denied whatever the amount", func(t *testing.T) {
		forbid := &CompanyActionPolicy{Source: "test", ForbiddenActions: []string{"create_refund_*"}, AmountLimits: company.AmountLimits}
		ap, err := CompileEffectiveActionPolicy(limitPolicy("http://x"), forbid)
		require.NoError(t, err)
		v := ap.EvaluateArguments("create_refund_request", refund(`1`))
		require.Equal(t, VerdictDeny, v.Outcome)
		require.Equal(t, CompanyDenyRuleID, v.RuleID)
	})
	t.Run("a company approval rule wins the report over a use-case band", func(t *testing.T) {
		withRule := &CompanyActionPolicy{Source: "test", Rules: map[string]CompanyApprovalRule{"all-refunds": {Actions: []string{"create_refund_request"}, ApproverGroups: []string{"support-leads"}}}}
		ap, err := CompileEffectiveActionPolicy(limitPolicy("http://x"), withRule)
		require.NoError(t, err)
		v := ap.EvaluateArguments("create_refund_request", refund(`10`))
		require.Equal(t, VerdictRequireApproval, v.Outcome, "the company rule needs approval even inside the use case's allow band")
		require.Equal(t, "company:all-refunds", v.RuleID)
		require.Equal(t, VerdictDeny, ap.EvaluateArguments("create_refund_request", refund(`501`)).Outcome, "DENY beats REQUIRE_APPROVAL")
	})
}

func TestAmountLimit_Digests(t *testing.T) {
	plain := testPolicy("http://x")
	plain.Policies.Approvals.Rules = nil
	before, err := CompileApprovalPolicy(plain)
	require.NoError(t, err)

	limited, err := CompileApprovalPolicy(limitPolicy("http://x"))
	require.NoError(t, err)
	require.NotEqual(t, before.Digest, limited.Digest, "adding a limit changes the approval-relevant digest")

	raised := limitPolicy("http://x")
	raised.Policies.Approvals.AmountLimits["refund-bands"] = refundBands("50.00", "500.01")
	raisedAP, err := CompileApprovalPolicy(raised)
	require.NoError(t, err)
	require.NotEqual(t, limited.Digest, raisedAP.Digest, "moving a threshold by one cent invalidates approvals bound to the old policy")

	same := limitPolicy("http://x")
	same.Policies.Approvals.AmountLimits["refund-bands"] = refundBands("50", "500.0")
	sameAP, err := CompileApprovalPolicy(same)
	require.NoError(t, err)
	require.Equal(t, limited.Digest, sameAP.Digest, "thresholds are compared as minor units, not spellings")

	// A company policy without limits keeps its version-1 encoding.
	v1 := string(companyCanonical([]string{"delete_customer"}, nil, nil))
	require.Contains(t, v1, `"v":1`)
	require.NotContains(t, v1, "limits")
	withLimits := &CompanyActionPolicy{AmountLimits: map[string]policy.AmountLimitConfig{"refund-bands": refundBands("50.00", "500.00")}}
	require.NotEqual(t, (&CompanyActionPolicy{}).Digest(), withLimits.Digest())
}

func TestAmountLimit_InvalidConfigurationIsRefused(t *testing.T) {
	bad := func(mut func(*policy.AmountLimitConfig)) policy.AmountLimitConfig {
		c := refundBands("50.00", "500.00")
		mut(&c)
		return c
	}
	cases := map[string]policy.AmountLimitConfig{
		"no actions":              bad(func(c *policy.AmountLimitConfig) { c.Actions = nil }),
		"bad action pattern":      bad(func(c *policy.AmountLimitConfig) { c.Actions = []string{"Refund"} }),
		"bad amount argument":     bad(func(c *policy.AmountLimitConfig) { c.AmountArgument = "amount.value" }),
		"same arguments":          bad(func(c *policy.AmountLimitConfig) { c.CurrencyArgument = "amount" }),
		"bad currency":            bad(func(c *policy.AmountLimitConfig) { c.Currency = "euro" }),
		"three fractional digits": bad(func(c *policy.AmountLimitConfig) { c.AllowUpTo = "50.001" }),
		"negative threshold":      bad(func(c *policy.AmountLimitConfig) { c.AllowUpTo = "-1" }),
		"approval below allow":    bad(func(c *policy.AmountLimitConfig) { c.ApprovalUpTo = "10.00" }),
		"no groups":               bad(func(c *policy.AmountLimitConfig) { c.ApproverGroups = nil }),
		"bad group":               bad(func(c *policy.AmountLimitConfig) { c.ApproverGroups = []string{"Finance Leads"} }),
	}
	for name, c := range cases {
		pol := limitPolicy("http://x")
		pol.Policies.Approvals.AmountLimits = map[string]policy.AmountLimitConfig{"refund-bands": c}
		_, err := CompileApprovalPolicy(pol)
		require.Error(t, err, name)
	}

	t.Run("an approval band with other groups than an overlapping rule is ambiguous", func(t *testing.T) {
		pol := limitPolicy("http://x")
		pol.Policies.Approvals.Rules = map[string]policy.ApprovalRuleConfig{"refunds": {Actions: []string{"create_refund_*"}, ApproverGroups: []string{"finance"}}}
		_, err := CompileApprovalPolicy(pol)
		require.ErrorContains(t, err, "different approver groups")
	})
	t.Run("a limit cannot reuse a rule id", func(t *testing.T) {
		pol := limitPolicy("http://x")
		pol.Policies.Approvals.Rules = map[string]policy.ApprovalRuleConfig{"refund-bands": {Actions: []string{"notify_customer"}, ApproverGroups: []string{"support-leads"}}}
		_, err := CompileApprovalPolicy(pol)
		require.ErrorContains(t, err, "same id")
	})
	t.Run("an invalid company limit fails the company policy", func(t *testing.T) {
		c := &CompanyActionPolicy{AmountLimits: map[string]policy.AmountLimitConfig{"x": bad(func(c *policy.AmountLimitConfig) { c.Currency = "" })}}
		require.Error(t, c.Validate())
		_, err := CompileEffectiveActionPolicy(limitPolicy("http://x"), c)
		require.Error(t, err)
	})
}

// The service applies the bands at establish AND re-applies them to the
// sealed arguments before any claim, with a counting downstream as proof.
func TestAmountLimit_ServiceDispatchCounts(t *testing.T) {
	ctx := context.Background()
	down := newDownstream(t)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	h := newHarnessWith(t, down, store, limitPolicy(down.srv.URL), testVaultKey)

	// Allow band: dispatched once.
	small := h.establish(t, "op-small", "create_refund_request", `{"ticket_id":"T-1","amount":30.00,"currency":"EUR"}`)
	require.Equal(t, VerdictAllow, small.Operation.Verdict)
	_, err = h.svc.Execute(ctx, "op-small")
	require.NoError(t, err)
	require.Equal(t, int64(1), down.calls.Load())

	// Deny band and unestablished amounts: denied at establish, no payload kept, zero dispatch.
	for opID, args := range map[string]string{
		"op-large":    `{"ticket_id":"T-2","amount":900.00,"currency":"EUR"}`,
		"op-negative": `{"ticket_id":"T-3","amount":-5,"currency":"EUR"}`,
		"op-usd":      `{"ticket_id":"T-4","amount":10,"currency":"USD"}`,
		"op-sub-cent": `{"ticket_id":"T-5","amount":10.005,"currency":"EUR"}`,
	} {
		res := h.establish(t, opID, "create_refund_request", args)
		require.Equal(t, VerdictDeny, res.Operation.Verdict, opID)
		require.Equal(t, OpDenied, res.Operation.Status, opID)
		require.False(t, res.Operation.Payload.Present, opID)
		_, err = h.svc.Execute(ctx, opID)
		require.Equal(t, CodePolicyDenied, CodeOf(err), opID)
		f := h.verify(t, opID)
		require.Equal(t, LifecycleValid, f.Verdict, f.Summary())
	}
	require.Equal(t, int64(1), down.calls.Load(), "denied refunds never reach the downstream")

	// Approval band: zero dispatch until an authorized approval; then once.
	mid := h.establish(t, "op-mid", "create_refund_request", `{"ticket_id":"T-6","amount":75.00,"currency":"EUR"}`)
	require.Equal(t, VerdictRequireApproval, mid.Operation.Verdict)
	require.Equal(t, "refund-bands", mid.Operation.MatchedRuleID)
	_, err = h.svc.Execute(ctx, "op-mid")
	require.Equal(t, CodeApprovalPending, CodeOf(err))
	require.Equal(t, int64(1), down.calls.Load())
	h.approve(t, mid, lead("lead-1"))
	require.Equal(t, int64(1), down.calls.Load(), "the approval itself dispatches nothing")
	// Changed material arguments cannot reuse the approval.
	_, err = h.svc.Establish(ctx, EstablishRequest{OperationID: "op-mid", Action: "create_refund_request", Arguments: json.RawMessage(`{"ticket_id":"T-6","amount":450.00,"currency":"EUR"}`)})
	require.Equal(t, CodeOperationConflict, CodeOf(err))
	_, err = h.svc.Execute(ctx, "op-mid")
	require.NoError(t, err)
	require.Equal(t, int64(2), down.calls.Load())
	_, err = h.svc.Execute(ctx, "op-mid")
	require.Equal(t, CodeOperationAlreadySucceeded, CodeOf(err))
	require.Equal(t, int64(2), down.calls.Load(), "a replay never dispatches twice")
	f := h.verify(t, "op-mid")
	require.Equal(t, LifecycleValid, f.Verdict, f.Summary())
}

// An operation authorized under one band is re-checked against the current
// policy and its own sealed arguments before a claim: lowering the ceiling
// below an approved amount refuses with zero dispatch.
func TestAmountLimit_LoweredCeilingRefusesAnApprovedOperation(t *testing.T) {
	ctx := context.Background()
	down := newDownstream(t)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	h := newHarnessWith(t, down, store, limitPolicy(down.srv.URL), testVaultKey)
	mid := h.establish(t, "op-mid", "create_refund_request", `{"ticket_id":"T-6","amount":75.00,"currency":"EUR"}`)
	h.approve(t, mid, lead("lead-1"))

	lowered := limitPolicy(down.srv.URL)
	lowered.Policies.Approvals.AmountLimits["refund-bands"] = refundBands("50.00", "60.00")
	h2 := newHarnessWith(t, down, store, lowered, testVaultKey)
	h2.now = h.now
	_, err = h2.svc.Execute(ctx, "op-mid")
	require.Contains(t, []string{CodePolicyDenied, CodeApprovalBindingStale}, CodeOf(err), "a policy change voids the approval")
	require.Equal(t, int64(0), down.calls.Load())

	// A newly limited action that was allowed by name now needs an approval it does not hold.
	plain := testPolicy(down.srv.URL)
	plain.Policies.Approvals.Rules = nil
	h3 := newHarnessWith(t, down, store, plain, testVaultKey)
	h3.now = h.now
	allowed := h3.establish(t, "op-was-allowed", "create_refund_request", `{"ticket_id":"T-7","amount":75.00,"currency":"EUR"}`)
	require.Equal(t, VerdictAllow, allowed.Operation.Verdict)
	h4 := newHarnessWith(t, down, store, limitPolicy(down.srv.URL), testVaultKey)
	h4.now = h.now
	_, err = h4.svc.Execute(ctx, "op-was-allowed")
	require.Equal(t, CodeApprovalRequired, CodeOf(err), "the name-only re-check allows it; only the sealed arguments show it needs approval")
	require.Equal(t, int64(0), down.calls.Load())

	// Allowed under the old policy, above the new ceiling: denied from the
	// sealed arguments before any claim.
	big := h3.establish(t, "op-was-allowed-big", "create_refund_request", `{"ticket_id":"T-8","amount":900.00,"currency":"EUR"}`)
	require.Equal(t, VerdictAllow, big.Operation.Verdict)
	_, err = h4.svc.Execute(ctx, "op-was-allowed-big")
	require.Equal(t, CodePolicyDenied, CodeOf(err))
	require.Equal(t, int64(0), down.calls.Load())
	f := h4.verify(t, "op-was-allowed-big")
	require.Equal(t, LifecycleIncomplete, f.Verdict, "refused at claim: consistent, not closed; "+f.Summary())
}

// Reasons end up in signed evidence, which outlives the sealed payload:
// they never repeat an argument value of the call.
func TestAmountLimit_ReasonsCarryNoArgumentValues(t *testing.T) {
	ap, err := CompileApprovalPolicy(limitPolicy("http://x"))
	require.NoError(t, err)
	for _, args := range []string{
		`{"amount":12.34,"currency":"EUR"}`, `{"amount":"123.45","currency":"EUR"}`, `{"amount":777.77,"currency":"EUR"}`,
		`{"amount":"12.345","currency":"EUR"}`, `{"amount":"secret-text","currency":"EUR"}`, `{"amount":12.34,"currency":"XTS"}`,
	} {
		v := ap.EvaluateArguments("create_refund_request", []byte(args))
		for _, leaked := range []string{"12.34", "123.45", "777.77", "12.345", "secret-text", "XTS"} {
			require.NotContains(t, v.Reason, leaked, args)
		}
	}
}

// An approval required by an amount band keeps the reviewer and claim
// guarantees of rule-based approvals: only the band's groups decide, and
// concurrent claims produce one effect.
func TestAmountLimit_ApprovalAuthorityAndSingleClaim(t *testing.T) {
	ctx := context.Background()
	down := newDownstream(t)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	h := newHarnessWith(t, down, store, limitPolicy(down.srv.URL), testVaultKey)
	mid := h.establish(t, "op-mid", "create_refund_request", `{"ticket_id":"T-6","amount":75.00,"currency":"EUR"}`)

	intern := lead("intern")
	intern.Groups = []string{"interns"}
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: mid.Operation.Approval.ID, Approve: true, Reviewer: intern})
	require.Equal(t, CodeApprovalNotAuthorized, CodeOf(err))
	foreign := lead("foreign")
	foreign.TenantScope = "other-tenant"
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: mid.Operation.Approval.ID, Approve: true, Reviewer: foreign})
	require.Error(t, err)
	_, err = h.svc.Execute(ctx, "op-mid")
	require.Equal(t, CodeApprovalPending, CodeOf(err))
	require.Equal(t, int64(0), down.calls.Load())

	h.approve(t, mid, lead("lead-1"))
	var wg sync.WaitGroup
	start := make(chan struct{})
	var succeeded atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := h.svc.Execute(ctx, "op-mid"); err == nil {
				succeeded.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.Equal(t, int64(1), succeeded.Load(), "exactly one claim wins")
	require.Equal(t, int64(1), down.calls.Load(), "one effect")
}

func limitHarness(t *testing.T) *harness {
	t.Helper()
	down := newDownstream(t)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return newHarnessWith(t, down, store, limitPolicy(down.srv.URL), testVaultKey)
}

// A band-required approval that is rejected, expires undecided, or expires
// after being granted dispatches nothing.
func TestAmountLimit_RejectedAndExpiredApprovalsNeverDispatch(t *testing.T) {
	ctx := context.Background()
	h := limitHarness(t)
	const args = `{"ticket_id":"T-9","amount":75.00,"currency":"EUR"}`

	rej := h.establish(t, "op-rejected", "create_refund_request", args)
	_, err := h.svc.Decide(ctx, DecideRequest{ApprovalID: rej.Operation.Approval.ID, Approve: false, Reason: "duplicate", Reviewer: lead("lead-1")})
	require.NoError(t, err)
	_, err = h.svc.Execute(ctx, "op-rejected")
	require.Equal(t, CodeApprovalRejected, CodeOf(err))

	undecided := h.establish(t, "op-undecided", "create_refund_request", args)
	granted := h.establish(t, "op-granted", "create_refund_request", args)
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

// The signed lifecycle of a band-approved refund verifies; with a record
// omitted or two records swapped it does not verify as valid.
func TestAmountLimit_LifecycleOmissionAndReorderAreDetected(t *testing.T) {
	ctx := context.Background()
	h := limitHarness(t)
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
	// The order is the signed sequence number, not the order records are
	// presented in: shuffling the list changes nothing...
	reversed := make([]*evidence.Evidence, len(recs))
	for i, r := range recs {
		reversed[len(recs)-1-i] = r
	}
	require.Equal(t, LifecycleValid, VerifyLifecycle(reversed, h.store.VerifyRecord).Verdict)
	// ...and exchanging the sequence numbers of two transitions breaks their signatures.
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
}

// A crash after the dispatch was armed leaves the outcome unknown: the
// restart closes the attempt as UNKNOWN and nothing retries it.
func TestAmountLimit_RestartAfterArmedDispatchIsUnknown(t *testing.T) {
	ctx := context.Background()
	h := limitHarness(t)
	res := h.establish(t, "op-small", "create_refund_request", `{"ticket_id":"T-9","amount":30.00,"currency":"EUR"}`)
	require.Equal(t, VerdictAllow, res.Operation.Verdict)
	h.down.lossy.Store(true) // the request is consumed, no response comes back
	exec, err := h.svc.Execute(ctx, "op-small")
	require.NoError(t, err)
	require.Equal(t, AttemptUnknown, exec.Attempt.Status)
	require.Equal(t, int64(1), h.down.calls.Load())
	h.down.lossy.Store(false)

	// "Restart": a new service over the same store recovers and still refuses.
	h2 := newHarnessWith(t, h.down, h.store, limitPolicy(h.down.srv.URL), testVaultKey)
	_, err = h2.svc.RecoverInterrupted(ctx)
	require.NoError(t, err)
	_, err = h2.svc.Execute(ctx, "op-small")
	require.Equal(t, CodeOperationOutcomeUnknown, CodeOf(err))
	require.Equal(t, int64(1), h.down.calls.Load(), "an unknown outcome is never retried")
}

// The reviewer view shows the declared material fields and nothing else of
// the payload: a non-material field's value never appears in it.
func TestReview_ShowsDeclaredFieldsOnly(t *testing.T) {
	ctx := context.Background()
	h := limitHarness(t)
	res := h.establish(t, "op-mid", "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR","iban":"DE89370400440532013000","note":"internal-remark-do-not-show"}`)
	view, err := h.svc.Review(ctx, res.Operation.Approval.ID)
	require.NoError(t, err)
	raw, err := json.Marshal(view)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"amount":75.00`)
	require.Contains(t, string(raw), "DE89370400440532013000", "a declared material field is shown exactly")
	require.NotContains(t, string(raw), "internal-remark-do-not-show", "a non-material field is not shown to the reviewer")
	require.Equal(t, "support-bot", view.UseCase)
	require.Contains(t, view.Rule, "require approval by support-leads")
}

// Approvals of other groups never push an eligible approval out of a
// reviewer's listing, and a listing that is not complete says so.
func TestPendingApprovals_FilterBeforeBoundAndReportMore(t *testing.T) {
	ctx := context.Background()
	h := limitHarness(t)
	const n = MaxPendingList + 5
	for i := 0; i < n; i++ {
		h.establish(t, fmt.Sprintf("op-%03d", i), "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR"}`)
		h.now = h.now.Add(time.Second)
	}
	// Everything but the NEWEST approval belongs to another group.
	_, err := h.store.DB().ExecContext(ctx, `UPDATE action_approvals SET groups_json = '["finance"]' WHERE id NOT IN (SELECT id FROM action_approvals ORDER BY created_at DESC, id DESC LIMIT 1)`)
	require.NoError(t, err)

	list, more, err := h.repo.PendingApprovals(ctx, "acme", []string{"support-leads"}, MaxPendingList)
	require.NoError(t, err)
	require.Len(t, list, 1, "the one eligible approval is listed although %d others are older", n-1)
	require.False(t, more)

	list, more, err = h.repo.PendingApprovals(ctx, "acme", []string{"finance"}, MaxPendingList)
	require.NoError(t, err)
	require.Len(t, list, MaxPendingList)
	require.True(t, more, "an incomplete listing reports that more exist")

	list, more, err = h.repo.PendingApprovals(ctx, "other-tenant", []string{"finance", "support-leads"}, MaxPendingList)
	require.NoError(t, err)
	require.Empty(t, list)
	require.False(t, more)
}
