package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gatewayResidualScanner(t *testing.T) *classifier.Scanner {
	t.Helper()
	score := 0.95
	s, err := classifier.NewScanner(classifier.WithCustomRecognizers([]classifier.RecognizerConfig{
		{
			Name:            "Placeholder Email Residual",
			SupportedEntity: "EMAIL_ADDRESS",
			Patterns: []classifier.PatternConfig{
				{Name: "email-placeholder", Regex: `\[EMAIL\]`, Score: &score},
			},
		},
	}))
	require.NoError(t, err)
	return s
}

func TestNoPIIEgressAfterRedaction_GatewayRequest(t *testing.T) {
	rawEmail := "jan.kowalski@gmail.com"
	var forwardedBody []byte
	gw, _, _ := setupOpenClawGateway(t, "redact", func(w http.ResponseWriter, r *http.Request) {
		forwardedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"contact ` + rawEmail + `"}]}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEmpty(t, forwardedBody, "gateway should forward a redacted request")
	assert.NotContains(t, string(forwardedBody), rawEmail, "raw PII must not egress to provider")
}

func TestGatewayResidualPIIApprovalCannotBypass(t *testing.T) {
	upstreamCalls := 0
	rawEmail := "jan.kowalski@gmail.com"
	gw, _, _ := setupOpenClawGateway(t, "redact", func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	})
	gw.classifier = gatewayResidualScanner(t)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"contact ` + rawEmail + `"}]}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Approval", "approved")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "residual PII must fail closed")
	assert.Contains(t, rec.Body.String(), "recognized PII remains after redaction")
	assert.Equal(t, 0, upstreamCalls, "approval headers must not bypass residual PII block")
}
