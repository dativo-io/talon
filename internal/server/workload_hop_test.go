package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/workload"
)

const (
	hopSubject = "spiffe://openshell/sandbox/sb-hop-1"
	hopBody    = `{"operation_id":"op-hop-1","action":"notify_customer","arguments":{"ticket_id":"T-1"}}`
)

// hopTestHarness is the generation harness with hop-assertion ingress
// enabled: the binder accepts exactly one (subject → support-bot/default)
// binding on generation g1, as the real binder resolves from the runtime
// snapshot.
func hopTestHarness(t *testing.T) (*generationHarness, *workload.HopSigner) {
	t.Helper()
	hs, err := workload.NewHopSigner("server-hop-root-key-0123456789abcdef", 0)
	require.NoError(t, err)
	var h *generationHarness
	binder := func(c *workload.HopClaims) (requestctx.AgentIdentity, bool) {
		if c.Runtime == "openshell" && c.Subject == hopSubject && c.Agent == "support-bot" && c.Tenant == "default" {
			return requestctx.AgentIdentity{AgentID: "support-bot", TenantID: "default", Generation: h.current.Load().(string)}, true
		}
		return requestctx.AgentIdentity{}, false
	}
	h = newGenerationHarnessWith(t, WithWorkloadHop(hs, binder))
	return h, hs
}

func mintFor(t *testing.T, hs *workload.HopSigner, method, path, body string, mut func(*workload.HopClaims)) string {
	t.Helper()
	c := workload.HopClaims{
		Runtime: "openshell", RuntimeIssuer: "openshell-gateway:gw-test", Subject: hopSubject, PrincipalID: "p-hop",
		SandboxRef: "sb-hop-1", RequestID: "osreq-77", Agent: "support-bot", Tenant: "default",
		Method: method, Path: path, BodySHA256: workload.BodyDigest([]byte(body)), SessionID: "sess-hop-1",
	}
	if mut != nil {
		mut(&c)
	}
	tok, err := hs.Mint(c)
	require.NoError(t, err)
	return tok
}

func (h *generationHarness) doHop(t *testing.T, method, path, body, assertion, bearer string) (status int, out map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	if assertion != "" {
		req.Header.Set(workload.HopAssertionHeader, assertion)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (h *generationHarness) lastLifecycle(t *testing.T) evidence.Evidence {
	t.Helper()
	var js string
	require.NoError(t, h.store.DB().QueryRowContext(context.Background(),
		`SELECT evidence_json FROM evidence WHERE invocation_type = 'action_lifecycle' ORDER BY rowid DESC LIMIT 1`).Scan(&js))
	var ev evidence.Evidence
	require.NoError(t, json.Unmarshal([]byte(js), &ev))
	return ev
}

// A valid hop assertion authenticates the sandbox's use case without any
// agent key; the operation is established as workload_asserted and its
// lifecycle evidence carries the verified identity, the runtime references
// and the client-asserted session that joins it to the model records.
func TestWorkloadHop_ValidAssertionEstablishesWithIdentityFacts(t *testing.T) {
	h, hs := hopTestHarness(t)
	code, out := h.doHop(t, "POST", "/v1/action-operations", hopBody, mintFor(t, hs, "POST", "/v1/action-operations", hopBody, nil), "")
	require.Equal(t, http.StatusCreated, code, "%v", out)
	ops, _, _, lifecycle := h.counts(t)
	assert.Equal(t, 1, ops)
	assert.Equal(t, 1, lifecycle)

	ev := h.lastLifecycle(t)
	require.True(t, h.store.VerifyRecord(&ev), "the record verifies")
	assert.Equal(t, "support-bot", ev.AgentID)
	assert.Equal(t, "default", ev.TenantID)
	assert.Equal(t, "sess-hop-1", ev.SessionID)
	require.NotNil(t, ev.WorkloadIdentity)
	assert.Equal(t, evidence.WorkloadIdentityVerified, ev.WorkloadIdentity.Status)
	assert.Equal(t, "openshell", ev.WorkloadIdentity.Runtime)
	assert.Equal(t, workload.AuthMethodHopAssertion, ev.WorkloadIdentity.AuthMethod)
	assert.Equal(t, hopSubject, ev.WorkloadIdentity.Subject)
	assert.Equal(t, "openshell-gateway:gw-test", ev.WorkloadIdentity.Issuer)
	assert.Equal(t, evidence.WorkloadIdentityBindingAgentConfig, ev.WorkloadIdentity.Binding)
	require.NotNil(t, ev.Enforcement)
	assert.Equal(t, evidence.ProvenanceTalonEnforced, ev.Enforcement.Provenance, "Talon dispatches the action itself")
	require.NotNil(t, ev.Enforcement.Runtime)
	assert.Equal(t, "sb-hop-1", ev.Enforcement.Runtime.Reference)
	assert.Equal(t, "osreq-77", ev.Enforcement.Runtime.RequestID)
	require.NotNil(t, ev.ActionLifecycle)
	assert.Equal(t, action.IdentityWorkloadAsserted, ev.ActionLifecycle.IdentitySource)
	js, _ := json.Marshal(ev)
	assert.NotContains(t, string(js), "v1.", "no assertion material is persisted")

	// Exact replay of the same request (same assertion): the idempotency
	// contract answers with the existing operation, no second operation.
	code, out = h.doHop(t, "POST", "/v1/action-operations", hopBody, mintFor(t, hs, "POST", "/v1/action-operations", hopBody, nil), "")
	assert.Equal(t, http.StatusOK, code, "%v", out)
	assert.Equal(t, false, out["created"])
	ops, _, _, _ = h.counts(t)
	assert.Equal(t, 1, ops)
}

// Every assertion failure is refused BEFORE any domain call: nothing is
// established, nothing is dispatched, and the failure never degrades into
// the agent-key path or dev-open.
func TestWorkloadHop_RefusalsLeaveNoState(t *testing.T) {
	h, hs := hopTestHarness(t)
	other, _ := workload.NewHopSigner("another-deployment-root-key-0123456789", 0)
	valid := mintFor(t, hs, "POST", "/v1/action-operations", hopBody, nil)
	for name, tc := range map[string]struct {
		assertion, bearer, body, path string
		status                        int
		code                          string
	}{
		"tampered":           {valid[:len(valid)-4] + "AAAA", "", hopBody, "/v1/action-operations", 401, CodeWorkloadIdentityInvalid},
		"other deployment":   {mintFor(t, other, "POST", "/v1/action-operations", hopBody, nil), "", hopBody, "/v1/action-operations", 401, CodeWorkloadIdentityInvalid},
		"other body":         {valid, "", strings.Replace(hopBody, "T-1", "T-2", 1), "/v1/action-operations", 401, CodeWorkloadIdentityInvalid},
		"other route":        {valid, "", hopBody, "/v1/action-operations/op-hop-1/attempts", 401, CodeWorkloadIdentityInvalid},
		"sandbox-forged":     {"v1.eyJhZ2VudCI6InN1cHBvcnQtYm90In0.c2ln", "", hopBody, "/v1/action-operations", 401, CodeWorkloadIdentityInvalid},
		"unbound agent":      {mintFor(t, hs, "POST", "/v1/action-operations", hopBody, func(c *workload.HopClaims) { c.Agent = "other-bot" }), "", hopBody, "/v1/action-operations", 403, CodeWorkloadIdentityUnbound},
		"unbound subject":    {mintFor(t, hs, "POST", "/v1/action-operations", hopBody, func(c *workload.HopClaims) { c.Subject = "spiffe://openshell/sandbox/sb-other" }), "", hopBody, "/v1/action-operations", 403, CodeWorkloadIdentityUnbound},
		"cross tenant":       {mintFor(t, hs, "POST", "/v1/action-operations", hopBody, func(c *workload.HopClaims) { c.Tenant = "other-tenant" }), "", hopBody, "/v1/action-operations", 403, CodeWorkloadIdentityUnbound},
		"foreign agent key":  {valid, "unknown-key", hopBody, "/v1/action-operations", 401, CodeWorkloadIdentityConflict},
		"oversized body":     {valid, "", strings.Repeat("x", maxActionBody+1), "/v1/action-operations", 413, "invalid_request"},
		"unknown route only": {mintFor(t, hs, "POST", "/v1/action-operations/op-x/attempts", "", nil), "", "", "/v1/action-operations/op-x/attempts", 404, action.CodeNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			before, _, _, lifecycleBefore := h.counts(t)
			code, out := h.doHop(t, "POST", tc.path, tc.body, tc.assertion, tc.bearer)
			assert.Equal(t, tc.status, code, "%v", out)
			if e, ok := out["error"].(map[string]any); ok {
				assert.Equal(t, tc.code, e["code"])
			} else {
				t.Fatalf("no error envelope: %v", out)
			}
			after, _, _, lifecycleAfter := h.counts(t)
			assert.Equal(t, before, after, "nothing established")
			assert.Equal(t, int64(0), h.downCalls.Load(), "nothing dispatched")
			if tc.status != 404 {
				assert.Equal(t, lifecycleBefore, lifecycleAfter, "an unattributable refusal writes no record")
			}
		})
	}
}

// An agent key presented together with an assertion must name the same use
// case; the agent-key path alone is unchanged.
func TestWorkloadHop_AgentKeyAgreementAndKeyOnlyPath(t *testing.T) {
	h, hs := hopTestHarness(t)
	code, out := h.doHop(t, "POST", "/v1/action-operations", hopBody, mintFor(t, hs, "POST", "/v1/action-operations", hopBody, nil), "agent-key-g1")
	assert.Equal(t, http.StatusCreated, code, "%v", out)
	ev := h.lastLifecycle(t)
	assert.Equal(t, action.IdentityWorkloadAsserted, ev.ActionLifecycle.IdentitySource, "the verified runtime identity is the source of record")

	keyBody := strings.Replace(hopBody, "op-hop-1", "op-key-1", 1)
	code, out = h.doHop(t, "POST", "/v1/action-operations", keyBody, "", "agent-key-g1")
	assert.Equal(t, http.StatusCreated, code, "%v", out)
	ev = h.lastLifecycle(t)
	assert.Equal(t, action.IdentityCallerProvided, ev.ActionLifecycle.IdentitySource)
	assert.Nil(t, ev.WorkloadIdentity, "an agent-key request carries no workload facts")
	assert.Nil(t, ev.Enforcement)
	assert.Empty(t, ev.SessionID)
}

// A deployment without hop ingress configured refuses assertions outright
// (never silently ignores the header and falls back to another identity).
func TestWorkloadHop_NotConfiguredRefusesAssertion(t *testing.T) {
	h := newGenerationHarness(t)
	hs, _ := workload.NewHopSigner("server-hop-root-key-0123456789abcdef", 0)
	code, out := h.doHop(t, "POST", "/v1/action-operations", hopBody, mintFor(t, hs, "POST", "/v1/action-operations", hopBody, nil), "agent-key-g1")
	assert.Equal(t, http.StatusUnauthorized, code, "%v", out)
	ops, _, _, _ := h.counts(t)
	assert.Equal(t, 0, ops)
}
