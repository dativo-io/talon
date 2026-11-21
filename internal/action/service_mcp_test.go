package action

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
)

// The Action Gateway lifecycle of an MCP-sourced action (#431): the same
// service, approval and claim path as an http destination; the dispatch is
// one tools/call to a real MCP server (the official Go SDK) that counts
// every call it receives.

const mcpRefundArgs = `{"amount":30,"currency":"EUR","ticket_id":"T-1"}`

func mcpOK(*sdk.CallToolRequest) (*sdk.CallToolResult, error) {
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "refund r-1 created"}}}, nil
}

type mcpHarnessOpts struct {
	approval bool
	auth     *policy.UpstreamAuthConfig
	secrets  SecretGetter
}

func newMCPHarness(t *testing.T, behave func(*sdk.CallToolRequest) (*sdk.CallToolResult, error), o mcpHarnessOpts) (*harness, *sdkRefundSource) {
	t.Helper()
	src := newSDKRefundSource(t, behave)
	srcCfg := policy.ActionSourceConfig{Type: "mcp", URL: src.srv.URL, Auth: o.auth}
	actions := &policy.ActionsConfig{
		Sources: map[string]policy.ActionSourceConfig{"refunds": srcCfg},
		Definitions: map[string]policy.ActionDefinitionConfig{
			"create_refund_request": {Source: "refunds", UpstreamName: "refund.create", Review: &policy.ActionReviewConfig{Fields: []string{"ticket_id", "amount", "currency", "region"}, NonMaterial: []string{"note"}}},
		},
	}
	cat, err := CompileCatalog(actions, map[string]*SourceSnapshot{"refunds": snapshotFor(t, "refunds", srcCfg, refundTool())})
	require.NoError(t, err)
	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "support-bot", TenantID: "acme"}, Actions: actions,
		Policies: policy.PoliciesConfig{Approvals: &policy.ApprovalsConfig{ExpiresAfter: "30m", Rules: map[string]policy.ApprovalRuleConfig{}}},
	}
	if o.approval {
		pol.Policies.Approvals.Rules["refund-request"] = policy.ApprovalRuleConfig{Actions: []string{"create_refund_request"}, ApproverGroups: []string{"support-leads"}}
	}
	ap, err := CompileApprovalPolicy(pol)
	require.NoError(t, err)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	repo, err := NewRepository(context.Background(), store.DB())
	require.NoError(t, err)
	cryptor, err := NewPayloadCryptor(testVaultKey)
	require.NoError(t, err)
	mcp := NewMCPDispatcher(nil, o.secrets, "test")
	mcp.Timeout = 2 * time.Second
	svc, err := NewService("acme", "support-bot", cat, ap, repo, store, Dispatchers{DestinationTypeMCP: mcp}, cryptor)
	require.NoError(t, err)
	h := &harness{svc: svc, store: store, repo: repo, cryptor: cryptor, now: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)}
	svc.now = func() time.Time { return h.now }
	return h, src
}

func TestMCPAction_ApprovedOperationDispatchesExactlyOnce(t *testing.T) {
	h, src := newMCPHarness(t, mcpOK, mcpHarnessOpts{approval: true})
	res := h.establish(t, "op-mcp-1", "create_refund_request", mcpRefundArgs)
	require.Equal(t, OpAwaitingApproval, res.Operation.Status)

	_, err := h.svc.Execute(context.Background(), "op-mcp-1")
	assert.Equal(t, CodeApprovalPending, CodeOf(err))
	h.approve(t, res, lead("ann"))
	assert.Zero(t, src.calls.Load(), "neither the claim before approval nor the decision dispatches")

	out, err := h.svc.Execute(context.Background(), "op-mcp-1")
	require.NoError(t, err)
	assert.Equal(t, OpSucceeded, out.Operation.Status)
	assert.Contains(t, string(out.Result), "refund r-1 created", "the observed result travels back to the adapter")
	assert.EqualValues(t, 1, src.calls.Load())

	_, err = h.svc.Execute(context.Background(), "op-mcp-1")
	assert.Equal(t, CodeOperationAlreadySucceeded, CodeOf(err))
	assert.EqualValues(t, 1, src.calls.Load(), "a repeated execute never dispatches again")

	f := h.verify(t, "op-mcp-1")
	assert.Equal(t, LifecycleValid, f.Verdict, f.Details)
	assert.Equal(t, OpSucceeded, f.FinalStatus)
}

func TestMCPAction_ExpiryBeforeContinuationNeverDispatches(t *testing.T) {
	h, src := newMCPHarness(t, mcpOK, mcpHarnessOpts{approval: true})
	res := h.establish(t, "op-mcp-exp", "create_refund_request", mcpRefundArgs)
	require.Equal(t, OpAwaitingApproval, res.Operation.Status)
	h.now = h.now.Add(31 * time.Minute)
	_, err := h.svc.Execute(context.Background(), "op-mcp-exp")
	assert.Equal(t, CodeApprovalExpired, CodeOf(err))
	assert.Zero(t, src.calls.Load())
	assert.Equal(t, LifecycleValid, h.verify(t, "op-mcp-exp").Verdict)
}

func TestMCPAction_ChangedArgumentsUnderTheSameIDConflict(t *testing.T) {
	h, src := newMCPHarness(t, mcpOK, mcpHarnessOpts{})
	h.establish(t, "op-mcp-c", "create_refund_request", mcpRefundArgs)
	_, err := h.svc.Establish(context.Background(), EstablishRequest{OperationID: "op-mcp-c", Action: "create_refund_request", Arguments: []byte(`{"amount":3000,"currency":"EUR","ticket_id":"T-1"}`)})
	assert.Equal(t, CodeOperationConflict, CodeOf(err))
	assert.Zero(t, src.calls.Load())
}

func TestMCPAction_ConcurrentExecutesDispatchOnce(t *testing.T) {
	h, src := newMCPHarness(t, mcpOK, mcpHarnessOpts{})
	h.establish(t, "op-mcp-cc", "create_refund_request", mcpRefundArgs)
	var wg sync.WaitGroup
	gate := make(chan struct{})
	var mu sync.Mutex
	succeeded := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			if out, err := h.svc.Execute(context.Background(), "op-mcp-cc"); err == nil && out.Operation.Status == OpSucceeded {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}()
	}
	close(gate)
	wg.Wait()
	assert.EqualValues(t, 1, src.calls.Load(), "eight concurrent executes, one tools/call")
	assert.Equal(t, 1, succeeded)
	assert.Equal(t, LifecycleValid, h.verify(t, "op-mcp-cc").Verdict)
}

// A tool-reported error after dispatch is UNKNOWN and blocks every retry:
// the operator reconciles, Talon never re-sends.
func TestMCPAction_UnknownBlocksEveryRetry(t *testing.T) {
	h, src := newMCPHarness(t, func(*sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "ledger timeout"}}}, nil
	}, mcpHarnessOpts{})
	h.establish(t, "op-mcp-u", "create_refund_request", mcpRefundArgs)
	out, err := h.svc.Execute(context.Background(), "op-mcp-u")
	require.NoError(t, err)
	assert.Equal(t, OpUnknown, out.Operation.Status)
	assert.Equal(t, "upstream_tool_error", out.Attempt.OutcomeCode)
	for i := 0; i < 3; i++ {
		_, err = h.svc.Execute(context.Background(), "op-mcp-u")
		assert.Equal(t, CodeOperationOutcomeUnknown, CodeOf(err))
	}
	assert.EqualValues(t, 1, src.calls.Load())
	f := h.verify(t, "op-mcp-u")
	assert.Equal(t, LifecycleValid, f.Verdict, f.Details)
	assert.Equal(t, OpUnknown, f.FinalStatus)
}

// A request that never left Talon (the source credential was unavailable)
// is a retryable failure: the next explicit execute dispatches once, with
// the same operation-scoped idempotency identity and a new attempt id.
func TestMCPAction_NotDispatchedIsRetriedWithTheSameIdempotencyKey(t *testing.T) {
	sec := &stubSecrets{err: errors.New("vault sealed"), value: "tok"}
	h, src := newMCPHarness(t, mcpOK, mcpHarnessOpts{auth: &policy.UpstreamAuthConfig{SecretName: "refunds-token"}, secrets: sec})
	h.establish(t, "op-mcp-r", "create_refund_request", mcpRefundArgs)

	out, err := h.svc.Execute(context.Background(), "op-mcp-r")
	require.NoError(t, err)
	assert.Equal(t, OpFailed, out.Operation.Status)
	assert.Equal(t, "dispatch_credential_unavailable", out.Attempt.OutcomeCode)
	assert.Zero(t, src.calls.Load())
	firstKey, firstAttempt := out.Attempt.IdempotencyKey, out.Attempt.ID

	sec.err = nil
	out, err = h.svc.Execute(context.Background(), "op-mcp-r")
	require.NoError(t, err)
	assert.Equal(t, OpSucceeded, out.Operation.Status)
	assert.EqualValues(t, 1, src.calls.Load())
	assert.Equal(t, firstKey, out.Attempt.IdempotencyKey)
	assert.NotEqual(t, firstAttempt, out.Attempt.ID)
	meta, _ := src.lastMeta.Load().(map[string]any)
	assert.Equal(t, firstKey, meta[MetaIdempotencyKey])
	assert.Equal(t, LifecycleValid, h.verify(t, "op-mcp-r").Verdict)
}

func TestMCPAction_RecoveryHoldRefusesDispatch(t *testing.T) {
	h, src := newMCPHarness(t, mcpOK, mcpHarnessOpts{})
	h.establish(t, "op-mcp-h", "create_refund_request", mcpRefundArgs)
	require.NoError(t, StampRecoveryHold(context.Background(), h.store.DB(), "bk_1", h.now.Add(-time.Hour), "cfg"))
	_, err := h.svc.Execute(context.Background(), "op-mcp-h")
	assert.Equal(t, CodeRecoveryHold, CodeOf(err))
	assert.Zero(t, src.calls.Load())
}

// A caller that goes away after the claim committed (an MCP client that
// disconnects) must not leave the operation `executing`: the dispatch and
// the completion run to a recorded outcome.
func TestExecute_CallerCancellationAfterTheClaimStillRecordsTheOutcome(t *testing.T) {
	h, src := newMCPHarness(t, mcpOK, mcpHarnessOpts{})
	h.establish(t, "op-mcp-x", "create_refund_request", mcpRefundArgs)
	ctx, cancel := context.WithCancel(context.Background())
	h.svc.hookAfterClaim = cancel
	out, err := h.svc.Execute(ctx, "op-mcp-x")
	require.NoError(t, err)
	assert.Equal(t, OpSucceeded, out.Operation.Status)
	assert.EqualValues(t, 1, src.calls.Load())
	p, err := h.svc.Get(context.Background(), "op-mcp-x")
	require.NoError(t, err)
	assert.Equal(t, OpSucceeded, p.Status)
}
