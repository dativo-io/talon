package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
)

// One request, one generation (#267) on the Action Gateway: the Service is
// resolved for the generation the agent key authenticated against. A
// reload between authentication and resolution is refused with
// generation_changed before any domain call — zero operation, approval,
// attempt, lifecycle evidence or dispatch. A Service resolved against a
// matching generation completes the request even if a reload lands after.

type generationHarness struct {
	srv       *Server
	handler   http.Handler
	store     *evidence.Store
	svc       *action.Service
	current   atomic.Value // the "current" runtime generation
	resolved  atomic.Int64
	downCalls atomic.Int64
	afterHook func()
}

func newGenerationHarness(t *testing.T) *generationHarness {
	t.Helper()
	h := &generationHarness{}
	h.current.Store("g1")
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h.downCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(down.Close)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	h.store = store
	pol := minimalPolicy()
	pol.Actions = &policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{
		"notify_customer": {
			InputSchema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"ticket_id": map[string]any{"type": "string"}}},
			Destination: policy.ActionDestinationConfig{Type: "http", URL: down.URL + "/notify", Success: &policy.ActionSuccessConfig{StatusCodes: []int{200}}},
		},
	}}
	cat, err := action.CompileCatalog(pol.Actions, nil)
	require.NoError(t, err)
	ap, err := action.CompileApprovalPolicy(pol)
	require.NoError(t, err)
	repo, err := action.NewRepository(context.Background(), store.DB())
	require.NoError(t, err)
	cryptor, err := action.NewPayloadCryptor("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	h.svc, err = action.NewService("default", "support-bot", cat, ap, repo, store, action.NewHTTPDispatcher(&http.Client{}), cryptor)
	require.NoError(t, err)

	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	resolver := func(id requestctx.AgentIdentity) (*action.Service, error) {
		if id.Generation != h.current.Load().(string) {
			return nil, &ActionServiceError{Code: CodeGenerationChanged, Message: "runtime generation changed between authentication and action resolution; re-authenticate and retry"}
		}
		h.resolved.Add(1)
		if h.afterHook != nil {
			h.afterHook()
		}
		return h.svc, nil
	}
	h.srv = NewServer(nil, store, nil, engine, pol, "", nil, "admin-key", map[string]string{},
		WithAgentKeyResolver(StaticAgentKeys(map[string]requestctx.AgentIdentity{
			"agent-key-g1": {AgentID: "support-bot", TenantID: "default", Generation: "g1"},
		})),
		WithActionGateway(resolver, nil, nil),
	)
	h.handler = h.srv.Routes()
	return h
}

func (h *generationHarness) do(t *testing.T, method, path, body string) (code int, out map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer agent-key-g1")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// counts reads the durable state straight from the evidence database.
func (h *generationHarness) counts(t *testing.T) (ops, approvals, attempts, lifecycle int) {
	t.Helper()
	db := h.store.DB()
	for _, q := range []struct {
		sql string
		dst *int
	}{
		{"SELECT COUNT(*) FROM action_operations", &ops},
		{"SELECT COUNT(*) FROM action_approvals", &approvals},
		{"SELECT COUNT(*) FROM action_attempts", &attempts},
		{"SELECT COUNT(*) FROM evidence WHERE invocation_type = 'action_lifecycle'", &lifecycle},
	} {
		require.NoError(t, db.QueryRowContext(context.Background(), q.sql).Scan(q.dst))
	}
	return
}

func TestActionGateway_GenerationChangedBetweenAuthAndResolution(t *testing.T) {
	h := newGenerationHarness(t)
	h.current.Store("g2") // reload activated after the key authenticated against g1

	for _, rt := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/action-operations", `{"operation_id":"op-1","action":"notify_customer","arguments":{"ticket_id":"T-1"}}`},
		{http.MethodGet, "/v1/action-operations/op-1", ""},
		{http.MethodPost, "/v1/action-operations/op-1/attempts", ""},
		{http.MethodGet, "/v1/approvals/ap-1", ""},
	} {
		code, out := h.do(t, rt.method, rt.path, rt.body)
		assert.Equal(t, http.StatusConflict, code, "%s %s", rt.method, rt.path)
		errObj, _ := out["error"].(map[string]any)
		assert.Equal(t, CodeGenerationChanged, errObj["code"], "%s %s", rt.method, rt.path)
	}
	ops, approvals, attempts, lifecycle := h.counts(t)
	assert.Zero(t, ops, "no operation row")
	assert.Zero(t, approvals, "no approval row")
	assert.Zero(t, attempts, "no attempt row")
	assert.Zero(t, lifecycle, "no action lifecycle evidence")
	assert.Zero(t, h.downCalls.Load(), "no dispatch")
	assert.Zero(t, h.resolved.Load(), "the Service was never resolved")

	// Same generation again: normal behaviour.
	h.current.Store("g1")
	code, out := h.do(t, http.MethodPost, "/v1/action-operations", `{"operation_id":"op-1","action":"notify_customer","arguments":{"ticket_id":"T-1"}}`)
	require.Equal(t, http.StatusCreated, code, out)
	ops, _, _, lifecycle = h.counts(t)
	assert.Equal(t, 1, ops)
	assert.Equal(t, 1, lifecycle)
}

// A reload that activates AFTER the Service was resolved does not change
// the catalog under the request: the Service is bound to its immutable
// generation and completes the request.
func TestActionGateway_ReloadAfterResolutionKeepsTheRequestOnItsGeneration(t *testing.T) {
	h := newGenerationHarness(t)
	h.afterHook = func() { h.current.Store("g2") } // the swap lands right after resolution
	code, out := h.do(t, http.MethodPost, "/v1/action-operations", `{"operation_id":"op-2","action":"notify_customer","arguments":{"ticket_id":"T-2"}}`)
	require.Equal(t, http.StatusCreated, code, out)
	assert.Equal(t, "g2", h.current.Load().(string))
	ops, _, _, _ := h.counts(t)
	assert.Equal(t, 1, ops)
	// The next request authenticates against g1 while g2 is current: refused.
	h.afterHook = nil
	code, out = h.do(t, http.MethodGet, "/v1/action-operations/op-2", "")
	assert.Equal(t, http.StatusConflict, code, out)
}
