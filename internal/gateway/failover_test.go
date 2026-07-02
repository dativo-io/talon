package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

const (
	failoverTestTenantKey = "talon-gw-failover-001"
	failoverTestBody      = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize our public roadmap"}]}`
)

// failoverUpstream is a controllable fake provider endpoint.
type failoverUpstream struct {
	server *httptest.Server
	calls  atomic.Int64
	// status controls the response code (200 = success). 0 = kill connection.
	status atomic.Int64
	// lastModel records the "model" field of the last request body.
	lastModel  atomic.Value
	lastAuth   atomic.Value
	statusBody string
}

func newFailoverUpstream(t *testing.T, status int) *failoverUpstream {
	t.Helper()
	u := &failoverUpstream{statusBody: `{"error":{"message":"upstream unavailable","type":"server_error"}}`}
	u.status.Store(int64(status))
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.calls.Add(1)
		var body struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		u.lastModel.Store(body.Model)
		u.lastAuth.Store(r.Header.Get("Authorization"))
		st := int(u.status.Load())
		if st == 0 {
			// Kill the connection mid-request (simulates provider death).
			hj, ok := w.(http.Hijacker)
			require.True(t, ok)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
			return
		}
		if st == -1 {
			// 200 headers, then die before delivering the promised body:
			// the client's body read fails with unexpected EOF.
			hj, ok := w.(http.Hijacker)
			require.True(t, ok)
			conn, buf, _ := hj.Hijack()
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"partial\":")
			_ = buf.Flush()
			_ = conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		if st == http.StatusOK {
			_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"fallback says hi"}}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
			return
		}
		_, _ = w.Write([]byte(u.statusBody))
	}))
	t.Cleanup(u.server.Close)
	return u
}

// extraBackup adds another provider to the fallback chain after "backup".
type extraBackup struct {
	name   string
	region string
	up     *failoverUpstream
}

// setupFailoverGateway wires a gateway with a primary provider ("openai") and
// a fallback provider ("backup") whose regions and chain are configurable.
// Additional chain targets can be appended via extras.
func setupFailoverGateway(t *testing.T, sovereigntyMode, primaryRegion, backupRegion string, primary, backup *failoverUpstream, fallbackModel string, extras ...extraBackup) (*Gateway, *evidence.Store) {
	t.Helper()
	dir := t.TempDir()

	chain := []FallbackTarget{{Provider: "backup", Model: fallbackModel}}
	providers := map[string]ProviderConfig{
		"backup": {Enabled: true, BaseURL: backup.server.URL, SecretName: "backup-api-key", Region: backupRegion},
	}
	for _, e := range extras {
		providers[e.name] = ProviderConfig{Enabled: true, BaseURL: e.up.server.URL, SecretName: "backup-api-key", Region: e.region}
		chain = append(chain, FallbackTarget{Provider: e.name})
	}
	providers["openai"] = ProviderConfig{
		Enabled: true, BaseURL: primary.server.URL, SecretName: "openai-api-key", Region: primaryRegion,
		Fallback: chain,
	}

	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers:    providers,
		Callers: []CallerConfig{
			{
				Name: "failover-bot", TenantKey: failoverTestTenantKey, TenantID: "test-tenant",
				PolicyOverrides: &CallerPolicyOverrides{PIIAction: "warn", MaxDailyCost: 100, MaxMonthlyCost: 2000},
			},
		},
		ServerDefaults: ServerDefaults{DefaultPIIAction: "warn", MaxDailyCost: 100, MaxMonthlyCost: 2000},
		Timeouts:       TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	cfg.EffectiveSovereigntyMode = sovereigntyMode
	require.NoError(t, cfg.Validate())

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	acl := secrets.ACL{Tenants: []string{"test-tenant"}, Agents: []string{"*"}}
	require.NoError(t, secStore.Set(context.Background(), "openai-api-key", []byte("sk-primary-key-1234567890"), acl))
	require.NoError(t, secStore.Set(context.Background(), "backup-api-key", []byte("sk-backup-key-1234567890"), acl))

	gw, err := NewGateway(cfg, classifier.MustNewScanner(), evStore, secStore, nil, nil)
	require.NoError(t, err)
	return gw, evStore
}

func makeFailoverRequest(gw *Gateway, body string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) {
		r.Handle("/*", gw)
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://test/v1/proxy/openai/v1/chat/completions", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+failoverTestTenantKey)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// correlationIDFromResponse recovers the correlation ID from the session
// header the gateway sets ("sess_" + correlation ID when none was supplied).
func correlationIDFromResponse(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	sid := w.Header().Get("X-Talon-Session-ID")
	require.True(t, strings.HasPrefix(sid, "sess_"), "session header %q", sid)
	return strings.TrimPrefix(sid, "sess_")
}

func failoverRecords(t *testing.T, store *evidence.Store, correlationID string) (attempts []*evidence.Evidence, final *evidence.Evidence) {
	t.Helper()
	records, err := store.ListByCorrelationID(context.Background(), correlationID)
	require.NoError(t, err)
	for _, ev := range records {
		if ev.InvocationType == "gateway_failover_attempt" {
			attempts = append(attempts, ev)
			continue
		}
		if ev.InvocationType == "gateway" {
			final = ev
		}
	}
	return attempts, final
}

func TestGatewayFailover_Upstream5xx_FailsOverToSecondary(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, store := setupFailoverGateway(t, config.DataSovereigntyEUStrict, "EU", "EU", primary, backup, "")

	w := makeFailoverRequest(gw, failoverTestBody)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "fallback says hi")
	assert.Equal(t, int64(1), primary.calls.Load())
	assert.Equal(t, int64(1), backup.calls.Load())
	// Fallback attempt must use the backup provider's own credentials.
	assert.Equal(t, "Bearer sk-backup-key-1234567890", backup.lastAuth.Load())

	correlationID := correlationIDFromResponse(t, w)
	attempts, final := failoverRecords(t, store, correlationID)

	require.Len(t, attempts, 1, "failed primary attempt must be a separate signed evidence record")
	att := attempts[0]
	assert.Equal(t, evidence.FailoverRoleFailedAttempt, att.Failover.Role)
	assert.Equal(t, "openai", att.Failover.Provider)
	assert.Equal(t, "upstream_5xx", att.Failover.ErrorClass)
	assert.Equal(t, http.StatusServiceUnavailable, att.Failover.UpstreamStatus)
	assert.Equal(t, evidence.FailureReasonProviderTransient, att.FailureReason)
	assert.True(t, store.VerifyRecord(att), "failed-attempt record must be signed")

	require.NotNil(t, final, "final gateway record must exist")
	require.NotNil(t, final.Failover, "final record must carry the fallback decision")
	assert.Equal(t, evidence.FailoverRoleFallbackDecision, final.Failover.Role)
	assert.Equal(t, "backup", final.Failover.Provider)
	assert.Equal(t, "EU", final.Failover.Region)
	assert.Equal(t, "allowed", final.Failover.SovereigntyCheck)
	assert.Equal(t, []string{att.ID}, final.Failover.FailedAttemptIDs)
	assert.Equal(t, "backup", final.RoutingDecision.SelectedProvider, "evidence must record the provider actually used")
	assert.True(t, store.VerifyRecord(final))

	finding, err := store.VerifyFailoverChain(context.Background(), correlationID)
	require.NoError(t, err)
	require.NotNil(t, finding)
	assert.Equal(t, evidence.FailoverVerdictValidFallback, finding.Verdict, "details: %v", finding.Details)
}

func TestGatewayFailover_KilledPrimaryConnection_FailsOver(t *testing.T) {
	primary := newFailoverUpstream(t, 0) // kill connection mid-request
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")

	w := makeFailoverRequest(gw, failoverTestBody)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "fallback says hi")

	correlationID := correlationIDFromResponse(t, w)
	attempts, final := failoverRecords(t, store, correlationID)
	require.Len(t, attempts, 1)
	assert.Equal(t, "connection_error", attempts[0].Failover.ErrorClass)
	require.NotNil(t, final.Failover)
	assert.Equal(t, evidence.FailoverRoleFallbackDecision, final.Failover.Role)
}

func TestGatewayFailover_EUStrict_USSecondary_FailsClosed(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, store := setupFailoverGateway(t, config.DataSovereigntyEUStrict, "EU", "US", primary, backup, "")

	w := makeFailoverRequest(gw, failoverTestBody)

	// The caller sees the primary's upstream error; the US secondary is never dispatched.
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, int64(1), primary.calls.Load())
	assert.Equal(t, int64(0), backup.calls.Load(), "sovereignty-rejected candidate must never be dispatched")

	correlationID := correlationIDFromResponse(t, w)
	attempts, final := failoverRecords(t, store, correlationID)
	require.Len(t, attempts, 1)
	require.NotNil(t, final)
	require.NotNil(t, final.Failover)
	assert.Equal(t, evidence.FailoverRoleFailClosed, final.Failover.Role)
	assert.Equal(t, "failed", final.Status)
	assert.Equal(t, evidence.FailureReasonNoSovereignFallback, final.FailureReason)
	require.Len(t, final.Failover.SkippedCandidates, 1)
	assert.Equal(t, "backup", final.Failover.SkippedCandidates[0].Provider)
	assert.Equal(t, "sovereignty", final.Failover.SkippedCandidates[0].Filter)
	assert.True(t, store.VerifyRecord(final), "fail-closed governance outcome must be signed")

	finding, err := store.VerifyFailoverChain(context.Background(), correlationID)
	require.NoError(t, err)
	require.NotNil(t, finding)
	assert.Equal(t, evidence.FailoverVerdictValidFailClosed, finding.Verdict, "details: %v", finding.Details)
}

func TestGatewayFailover_PermanentError_NoFailover(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusUnauthorized)
	primary.statusBody = `{"error":{"message":"bad key","type":"invalid_request_error"}}`
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")

	w := makeFailoverRequest(gw, failoverTestBody)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "permanent auth errors pass through unchanged")
	assert.Equal(t, int64(0), backup.calls.Load(), "permanent errors must not trigger failover")

	correlationID := correlationIDFromResponse(t, w)
	attempts, final := failoverRecords(t, store, correlationID)
	assert.Empty(t, attempts)
	require.NotNil(t, final)
	assert.Nil(t, final.Failover, "no failover context when failover was not engaged")
}

func TestGatewayFailover_RateLimited_ModelRewrite(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusTooManyRequests)
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "gpt-4o-mini-eu")

	w := makeFailoverRequest(gw, failoverTestBody)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "gpt-4o-mini", primary.lastModel.Load(), "primary receives the client's model")
	assert.Equal(t, "gpt-4o-mini-eu", backup.lastModel.Load(), "fallback body model must be rewritten")

	correlationID := correlationIDFromResponse(t, w)
	attempts, final := failoverRecords(t, store, correlationID)
	require.Len(t, attempts, 1)
	assert.Equal(t, "rate_limited", attempts[0].Failover.ErrorClass)
	require.NotNil(t, final.Failover)
	assert.Equal(t, "gpt-4o-mini-eu", final.Failover.Model)
	assert.Equal(t, "gpt-4o-mini-eu", final.RoutingDecision.SelectedModel)
}

func TestGatewayFailover_BothProvidersFail_FailClosedWithAttempts(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
	backup := newFailoverUpstream(t, http.StatusBadGateway)
	gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")

	w := makeFailoverRequest(gw, failoverTestBody)

	assert.Equal(t, http.StatusBadGateway, w.Code, "caller sees the last upstream error")

	correlationID := correlationIDFromResponse(t, w)
	attempts, final := failoverRecords(t, store, correlationID)
	require.Len(t, attempts, 2, "both failed attempts must be evidenced")
	require.NotNil(t, final.Failover)
	assert.Equal(t, evidence.FailoverRoleFailClosed, final.Failover.Role)
	assert.Len(t, final.Failover.FailedAttemptIDs, 2)

	finding, err := store.VerifyFailoverChain(context.Background(), correlationID)
	require.NoError(t, err)
	assert.Equal(t, evidence.FailoverVerdictValidFailClosed, finding.Verdict, "details: %v", finding.Details)
}

// A fallback candidate failing with a PERMANENT error (misconfigured secret,
// missing model) must never be recorded as the provider actually used: it is
// a failed attempt and the outcome is fail-closed, not a fallback decision.
func TestGatewayFailover_FallbackPermanentError_FailsClosed(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		wantClass  string
		statusBody string
	}{
		{name: "fallback 401", status: http.StatusUnauthorized, wantClass: "auth_error", statusBody: `{"error":{"message":"bad key","type":"invalid_request_error"}}`},
		{name: "fallback 404", status: http.StatusNotFound, wantClass: "client_error", statusBody: `{"error":{"message":"model not found","type":"invalid_request_error"}}`},
		{name: "fallback 422", status: http.StatusUnprocessableEntity, wantClass: "client_error", statusBody: `{"error":{"message":"unprocessable","type":"invalid_request_error"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
			backup := newFailoverUpstream(t, tc.status)
			backup.statusBody = tc.statusBody
			gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")

			w := makeFailoverRequest(gw, failoverTestBody)

			assert.Equal(t, tc.status, w.Code, "caller sees the fallback's upstream error")
			assert.Equal(t, int64(1), backup.calls.Load())

			correlationID := correlationIDFromResponse(t, w)
			attempts, final := failoverRecords(t, store, correlationID)
			require.Len(t, attempts, 2, "the permanent fallback failure must be a failed attempt too")
			assert.Equal(t, "upstream_5xx", attempts[0].Failover.ErrorClass)
			assert.Equal(t, evidence.FailureReasonProviderTransient, attempts[0].FailureReason)
			assert.Equal(t, tc.wantClass, attempts[1].Failover.ErrorClass)
			assert.Equal(t, evidence.FailureReasonProviderPermanent, attempts[1].FailureReason,
				"failure_reason must match the error class, not claim transient")

			require.NotNil(t, final)
			require.NotNil(t, final.Failover)
			assert.Equal(t, evidence.FailoverRoleFailClosed, final.Failover.Role,
				"a failed fallback must never become the fallback decision")
			assert.Equal(t, "failed", final.Status)
			assert.Len(t, final.Failover.FailedAttemptIDs, 2)

			finding, err := store.VerifyFailoverChain(context.Background(), correlationID)
			require.NoError(t, err)
			assert.Equal(t, evidence.FailoverVerdictValidFailClosed, finding.Verdict, "details: %v", finding.Details)
		})
	}
}

// Once failover is engaged, only success ends the chain: a permanently
// failing fallback candidate is skipped over and the next candidate is tried.
func TestGatewayFailover_ChainContinuesPastPermanentFallback(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
	badBackup := newFailoverUpstream(t, http.StatusUnauthorized)
	goodBackup := newFailoverUpstream(t, http.StatusOK)
	gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, badBackup, "",
		extraBackup{name: "backup2", region: "EU", up: goodBackup})

	w := makeFailoverRequest(gw, failoverTestBody)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "fallback says hi")
	assert.Equal(t, int64(1), badBackup.calls.Load())
	assert.Equal(t, int64(1), goodBackup.calls.Load())

	correlationID := correlationIDFromResponse(t, w)
	attempts, final := failoverRecords(t, store, correlationID)
	require.Len(t, attempts, 2)
	assert.Equal(t, "auth_error", attempts[1].Failover.ErrorClass)

	require.NotNil(t, final.Failover)
	assert.Equal(t, evidence.FailoverRoleFallbackDecision, final.Failover.Role)
	assert.Equal(t, "backup2", final.Failover.Provider)
	assert.Equal(t, 2, final.Failover.ChainPosition)
	assert.Len(t, final.Failover.FailedAttemptIDs, 2)

	finding, err := store.VerifyFailoverChain(context.Background(), correlationID)
	require.NoError(t, err)
	assert.Equal(t, evidence.FailoverVerdictValidFallback, finding.Verdict, "details: %v", finding.Details)
}

// A 200-with-headers upstream that dies before the body is delivered must
// still be able to fail over: the failoverWriter commits on the first body
// write, not on the header write.
func TestGatewayFailover_200HeadersThenBodyEOF_FailsOver(t *testing.T) {
	primary := newFailoverUpstream(t, -1) // 200 headers, then connection dies
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")

	w := makeFailoverRequest(gw, failoverTestBody)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "fallback says hi")
	assert.Equal(t, int64(1), backup.calls.Load())

	correlationID := correlationIDFromResponse(t, w)
	attempts, final := failoverRecords(t, store, correlationID)
	require.Len(t, attempts, 1)
	assert.Equal(t, "connection_error", attempts[0].Failover.ErrorClass)
	require.NotNil(t, final.Failover)
	assert.Equal(t, evidence.FailoverRoleFallbackDecision, final.Failover.Role)
}

// Fallback candidates must pass the caller's allowed_providers gate — the
// same authorization the primary route passed. A candidate outside the
// caller's allowlist is skipped, never dispatched.
func TestGatewayFailover_CallerAllowedProviders_SkipsCandidate(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")
	// Restrict the caller to the primary provider only.
	gw.config.Callers[0].AllowedProviders = []string{"openai"}

	w := makeFailoverRequest(gw, failoverTestBody)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, int64(0), backup.calls.Load(), "candidate outside caller allowed_providers must never be dispatched")

	correlationID := correlationIDFromResponse(t, w)
	_, final := failoverRecords(t, store, correlationID)
	require.NotNil(t, final)
	require.NotNil(t, final.Failover)
	assert.Equal(t, evidence.FailoverRoleFailClosed, final.Failover.Role)
	require.Len(t, final.Failover.SkippedCandidates, 1)
	assert.Equal(t, "caller_allowlist", final.Failover.SkippedCandidates[0].Filter)
}

// Fallback candidates re-run the full gateway policy with their own provider
// and model, so a caller-level model restriction cannot be bypassed by a
// fallback model rewrite.
func TestGatewayFailover_CallerModelPolicy_SkipsCandidate(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "gpt-4o")
	gw.config.Callers[0].PolicyOverrides.AllowedModels = []string{"gpt-4o-mini"}
	// Wire the real gateway policy engine so caller model lists are enforced.
	policyEngine, err := policy.NewGatewayEngine(context.Background())
	require.NoError(t, err)
	gw.policy = policyEngine

	w := makeFailoverRequest(gw, failoverTestBody)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, int64(0), backup.calls.Load(), "fallback model outside caller allowed_models must never be dispatched")

	correlationID := correlationIDFromResponse(t, w)
	_, final := failoverRecords(t, store, correlationID)
	require.NotNil(t, final)
	require.NotNil(t, final.Failover)
	assert.Equal(t, evidence.FailoverRoleFailClosed, final.Failover.Role)
	require.Len(t, final.Failover.SkippedCandidates, 1)
	assert.Equal(t, "gateway_policy", final.Failover.SkippedCandidates[0].Filter)
}

// api_family lets aliased Anthropic-compatible endpoints join chains and get
// Anthropic auth conventions (x-api-key + anthropic-version).
func TestGatewayFailover_APIFamilyAliases(t *testing.T) {
	t.Run("fallbackAuthHeaders uses x-api-key for anthropic-family alias", func(t *testing.T) {
		primary := newFailoverUpstream(t, http.StatusOK)
		backup := newFailoverUpstream(t, http.StatusOK)
		gw, _ := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")

		prov := ProviderConfig{Enabled: true, BaseURL: backup.server.URL, SecretName: "backup-api-key", APIFamily: "anthropic"}
		gw.config.Providers["anthropic-eu"] = prov
		headers, err := gw.fallbackAuthHeaders(context.Background(),
			gw.config.CallerByName("failover-bot"), "anthropic-eu", prov,
			"Bearer client-token", map[string]string{"Authorization": "Bearer old", "Content-Type": "application/json"})
		require.NoError(t, err)
		assert.Equal(t, "sk-backup-key-1234567890", headers["x-api-key"])
		assert.Equal(t, "2023-06-01", headers["anthropic-version"])
		assert.Empty(t, headers["Authorization"], "bearer auth of the failed provider must not leak to an anthropic-family target")
	})
}

func TestGatewayConfig_ValidateFallbackChain(t *testing.T) {
	base := func() *GatewayConfig {
		return &GatewayConfig{
			ListenPrefix: "/v1/proxy",
			Mode:         ModeEnforce,
			Providers: map[string]ProviderConfig{
				"openai":    {Enabled: true, BaseURL: "https://api.openai.com", SecretName: "k"},
				"backup":    {Enabled: true, BaseURL: "https://eu.example.com", SecretName: "k2"},
				"anthropic": {Enabled: true, BaseURL: "https://api.anthropic.com", SecretName: "k3"},
				"disabled":  {Enabled: false, BaseURL: "https://off.example.com"},
			},
		}
	}

	tests := []struct {
		name    string
		mutate  func(*GatewayConfig)
		wantErr string
	}{
		{
			name: "valid chain",
			mutate: func(c *GatewayConfig) {
				p := c.Providers["openai"]
				p.Fallback = []FallbackTarget{{Provider: "backup", Model: "m"}}
				c.Providers["openai"] = p
			},
		},
		{
			name: "self-referencing target",
			mutate: func(c *GatewayConfig) {
				p := c.Providers["openai"]
				p.Fallback = []FallbackTarget{{Provider: "openai"}}
				c.Providers["openai"] = p
			},
			wantErr: "duplicate or self-referencing",
		},
		{
			name: "duplicate target",
			mutate: func(c *GatewayConfig) {
				p := c.Providers["openai"]
				p.Fallback = []FallbackTarget{{Provider: "backup"}, {Provider: "backup"}}
				c.Providers["openai"] = p
			},
			wantErr: "duplicate or self-referencing",
		},
		{
			name: "unknown target",
			mutate: func(c *GatewayConfig) {
				p := c.Providers["openai"]
				p.Fallback = []FallbackTarget{{Provider: "missing"}}
				c.Providers["openai"] = p
			},
			wantErr: "not an enabled gateway provider",
		},
		{
			name: "disabled target",
			mutate: func(c *GatewayConfig) {
				p := c.Providers["openai"]
				p.Fallback = []FallbackTarget{{Provider: "disabled"}}
				c.Providers["openai"] = p
			},
			wantErr: "not an enabled gateway provider",
		},
		{
			name: "cross-family target",
			mutate: func(c *GatewayConfig) {
				p := c.Providers["openai"]
				p.Fallback = []FallbackTarget{{Provider: "anthropic"}}
				c.Providers["openai"] = p
			},
			wantErr: "API family",
		},
		{
			name: "empty provider name",
			mutate: func(c *GatewayConfig) {
				p := c.Providers["openai"]
				p.Fallback = []FallbackTarget{{Provider: ""}}
				c.Providers["openai"] = p
			},
			wantErr: "provider is required",
		},
		{
			name: "anthropic alias without api_family is rejected",
			mutate: func(c *GatewayConfig) {
				c.Providers["anthropic-eu"] = ProviderConfig{Enabled: true, BaseURL: "https://eu.anthropic.example.com", SecretName: "k4"}
				p := c.Providers["anthropic"]
				p.Fallback = []FallbackTarget{{Provider: "anthropic-eu"}}
				c.Providers["anthropic"] = p
			},
			wantErr: "API family", // without api_family, anthropic-eu resolves to openai by name
		},
		{
			name: "anthropic alias with api_family anthropic is accepted",
			mutate: func(c *GatewayConfig) {
				c.Providers["anthropic-eu"] = ProviderConfig{Enabled: true, BaseURL: "https://eu.anthropic.example.com", SecretName: "k4", APIFamily: "anthropic"}
				p := c.Providers["anthropic"]
				p.Fallback = []FallbackTarget{{Provider: "anthropic-eu"}}
				c.Providers["anthropic"] = p
			},
		},
		{
			name: "invalid api_family value is rejected",
			mutate: func(c *GatewayConfig) {
				p := c.Providers["openai"]
				p.APIFamily = "grpc"
				c.Providers["openai"] = p
			},
			wantErr: "api_family must be openai or anthropic",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base()
			tt.mutate(cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestFailoverWriter(t *testing.T) {
	t.Run("success status commits on first body write, not on headers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		fw := newFailoverWriter(rec)
		fw.Header().Set("Content-Type", "application/json")
		fw.WriteHeader(http.StatusOK)
		assert.False(t, fw.committed, "200 headers alone must not commit — a body-read failure can still fail over")
		_, _ = fw.Write([]byte("hello"))
		assert.True(t, fw.committed)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "hello", rec.Body.String())
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	})

	t.Run("success status with empty body commits on flushTo", func(t *testing.T) {
		rec := httptest.NewRecorder()
		fw := newFailoverWriter(rec)
		fw.WriteHeader(http.StatusNoContent)
		assert.False(t, fw.committed)
		fw.flushTo()
		assert.True(t, fw.committed)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("error status stays buffered until flushTo", func(t *testing.T) {
		rec := httptest.NewRecorder()
		fw := newFailoverWriter(rec)
		fw.Header().Set("Content-Type", "application/json")
		fw.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fw.Write([]byte(`{"error":"down"}`))
		assert.False(t, fw.committed)
		assert.Equal(t, http.StatusOK, rec.Code, "nothing written to destination yet")
		assert.Empty(t, rec.Body.String())

		fw.flushTo()
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, `{"error":"down"}`, rec.Body.String())
	})
}
