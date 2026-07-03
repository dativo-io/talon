package llm_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/classifier/adapter"
	"github.com/dativo-io/talon/internal/classifier/adapter/llm"
	"github.com/dativo-io/talon/internal/testutil"
)

// nerReply builds the JSON object the prompt demands.
func nerReply(entities ...[2]string) string {
	type det struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	dets := make([]det, 0, len(entities))
	for _, e := range entities {
		dets = append(dets, det{Type: e[0], Value: e[1]})
	}
	b, _ := json.Marshal(map[string]interface{}{"entities": dets})
	return string(b)
}

func newAdapter(t *testing.T, respond testutil.NERRespondFunc) *llm.Adapter {
	t.Helper()
	srv := testutil.NewNERMockServer(t, respond, "test-model")
	a, err := llm.New(llm.Config{
		Endpoint: srv.URL + "/v1",
		Model:    "test-model",
	})
	require.NoError(t, err)
	return a
}

func TestAnalyze_ValueRelocationFindsAllOccurrences(t *testing.T) {
	text := "mail kai@example.com then cc kai@example.com again"
	a := newAdapter(t, func(string) string {
		// The model reports the value ONCE; relocation finds both occurrences.
		return nerReply([2]string{"EMAIL_ADDRESS", "kai@example.com"})
	})

	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	require.True(t, cls.HasPII)
	require.Len(t, cls.Entities, 2, "every occurrence of a reported value is an entity")
	for _, e := range cls.Entities {
		assert.Equal(t, "email", e.Type)
		assert.Equal(t, "kai@example.com", e.Value)
		assert.Equal(t, "kai@example.com", text[e.Position:e.Position+len(e.Value)],
			"offsets are computed by Talon, byte-exact")
	}
}

func TestAnalyze_UnicodeTextByteOffsets(t *testing.T) {
	text := "名前は久保 😀 kai@example.com です"
	a := newAdapter(t, func(string) string {
		return nerReply([2]string{"EMAIL_ADDRESS", "kai@example.com"})
	})

	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	require.Len(t, cls.Entities, 1)
	e := cls.Entities[0]
	assert.Equal(t, strings.Index(text, "kai@example.com"), e.Position)
	assert.Equal(t, "kai@example.com", e.Value)
}

func TestAnalyze_HallucinatedValuesDropped(t *testing.T) {
	text := "totally clean text"
	a := newAdapter(t, func(string) string {
		return nerReply(
			[2]string{"EMAIL_ADDRESS", "ghost@nowhere.example"}, // not in text
			[2]string{"PHONE_NUMBER", "+49 170 000000"},         // not in text
		)
	})

	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	assert.False(t, cls.HasPII, "values not present verbatim are hallucinations and must be dropped")
	assert.Empty(t, cls.Entities)
}

func TestAnalyze_PlaceholderValuesDropped(t *testing.T) {
	text := "contact [EMAIL] about the invoice"
	a := newAdapter(t, func(string) string {
		return nerReply([2]string{"EMAIL_ADDRESS", "[EMAIL]"})
	})

	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	assert.False(t, cls.HasPII, "redaction placeholders must not re-detect as PII (would false-block VerifyEgress)")
}

func TestAnalyze_SensitivityDrivesTier(t *testing.T) {
	text := "card 4111 1111 1111 1111 on file"
	a := newAdapter(t, func(string) string {
		return nerReply([2]string{"CREDIT_CARD", "4111 1111 1111 1111"})
	})

	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	require.True(t, cls.HasPII)
	assert.Equal(t, 2, cls.Tier, "credit cards carry built-in sensitivity >= 2 -> tier 2")
}

func TestAnalyze_CodeFencedReplyTolerated(t *testing.T) {
	text := "mail kai@example.com"
	a := newAdapter(t, func(string) string {
		return "```json\n" + nerReply([2]string{"EMAIL_ADDRESS", "kai@example.com"}) + "\n```"
	})

	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	assert.True(t, cls.HasPII)
}

func TestAnalyze_NonJSONReplyFailsClosed(t *testing.T) {
	a := newAdapter(t, func(string) string {
		return "I could not find any PII in this text."
	})

	cls, err := a.Analyze(context.Background(), "mail kai@example.com")
	require.Error(t, err, "prose instead of the entities object is an engine failure, not a clean scan")
	assert.Nil(t, cls)
	assert.True(t, errors.Is(err, adapter.ErrScannerUnavailable))
	assert.Equal(t, string(adapter.KindDecode), adapter.FailureKind(err))
}

func TestAnalyze_EmptyEntities(t *testing.T) {
	a := newAdapter(t, func(string) string { return `{"entities":[]}` })

	cls, err := a.Analyze(context.Background(), "clean text")
	require.NoError(t, err)
	assert.False(t, cls.HasPII)
	assert.NotNil(t, cls.Entities)
}

func TestRedactText_EndToEnd(t *testing.T) {
	text := "mail kai@example.com and call +49 170 1234567"
	a := newAdapter(t, func(userText string) string {
		var dets [][2]string
		if strings.Contains(userText, "kai@example.com") {
			dets = append(dets, [2]string{"EMAIL_ADDRESS", "kai@example.com"})
		}
		if strings.Contains(userText, "+49 170 1234567") {
			dets = append(dets, [2]string{"PHONE_NUMBER", "+49 170 1234567"})
		}
		return nerReply(dets...)
	})

	redacted, err := a.RedactText(context.Background(), text)
	require.NoError(t, err)
	assert.Equal(t, "mail [EMAIL] and call [PHONE]", redacted)

	// The verify re-scan sees only placeholders -> passes.
	require.NoError(t, a.VerifyEgress(context.Background(), redacted))
}

func TestVerifyEgress_ResidualBlocks(t *testing.T) {
	a := newAdapter(t, func(userText string) string {
		if strings.Contains(userText, "kai@example.com") {
			return nerReply([2]string{"EMAIL_ADDRESS", "kai@example.com"})
		}
		return `{"entities":[]}`
	})

	err := a.VerifyEgress(context.Background(), "still has kai@example.com")
	require.Error(t, err)
	assert.True(t, errors.Is(err, classifier.ErrPIIDetected))
}

func TestHealthCheck_ModelPresenceVerified(t *testing.T) {
	srv := testutil.NewNERMockServer(t, func(string) string { return `{"entities":[]}` }, "other-model")

	a, err := llm.New(llm.Config{Endpoint: srv.URL + "/v1", Model: "missing-model"})
	require.NoError(t, err)
	err = a.HealthCheck(context.Background())
	require.Error(t, err, "configured model absent from /models must fail the probe")
	assert.Contains(t, err.Error(), "missing-model")

	b, err := llm.New(llm.Config{Endpoint: srv.URL + "/v1", Model: "other-model"})
	require.NoError(t, err)
	assert.NoError(t, b.HealthCheck(context.Background()))
}

func TestNew_Validation(t *testing.T) {
	_, err := llm.New(llm.Config{Endpoint: "http://localhost:11434/v1"})
	assert.Error(t, err, "model is required")

	_, err = llm.New(llm.Config{Model: "m"})
	assert.Error(t, err, "endpoint is required")

	a, err := llm.New(llm.Config{Endpoint: "http://localhost:11434/v1", Model: "llama3.1:8b"})
	require.NoError(t, err)
	assert.Equal(t, "llm:llama3.1:8b", a.Detector())
	assert.Equal(t, "llm", a.EngineType())
	assert.Equal(t, llm.PromptVersion, a.EngineVersion())
}

func TestRelocate_OverlappingSelfOccurrences(t *testing.T) {
	// "aaaa" contains "aa" at offsets 0,1,2 — the advance-by-one loop plus
	// span dedupe must find all three without infinite-looping.
	res := llm.Relocate("aaaa", []llm.Detection{{Type: "CUSTOM", Value: "aa"}}, 0.8)
	require.Len(t, res.Results, 3)
	for i, r := range res.Results {
		assert.Equal(t, i, r.Start)
		assert.Equal(t, i+2, r.End)
	}
	assert.Zero(t, res.Hallucinated)
}

func TestRelocate_CountsHallucinationsAndPlaceholders(t *testing.T) {
	res := llm.Relocate("clean [IBAN] text", []llm.Detection{
		{Type: "EMAIL_ADDRESS", Value: "ghost@x.example"},
		{Type: "IBAN", Value: "[IBAN]"},
		{Type: "CUSTOM", Value: ""},
	}, 0.8)
	assert.Empty(t, res.Results)
	assert.Equal(t, 1, res.Hallucinated)
	assert.Equal(t, 1, res.PlaceholdersDropped)
}

func TestParseDetections_CapsRunaway(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"entities":[`)
	for i := 0; i < 1000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"type":"X","value":"v%d"}`, i)
	}
	sb.WriteString(`]}`)

	dets, err := llm.ParseDetections(sb.String())
	require.NoError(t, err)
	assert.Len(t, dets, 256, "detection count is bounded (untrusted input)")
}

func TestHealthCheck_ListedButUnrunnableModelFailsStartup(t *testing.T) {
	// The undersized-host failure mode: /v1/models lists the pulled model, but
	// completions fail (e.g. Ollama cannot load an 8B model in 4GB RAM). The
	// eager health probe must catch this at startup instead of letting every
	// scan fail-closed-block at runtime.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"llama3.1:8b"}]}`))
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"model requires more system memory"}`, http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a, err := llm.New(llm.Config{Endpoint: srv.URL + "/v1", Model: "llama3.1:8b"})
	require.NoError(t, err)

	err = a.HealthCheck(context.Background())
	require.Error(t, err, "a model that lists but cannot run must fail the startup probe")
	assert.Contains(t, err.Error(), "warm-up")
}

func TestAnalyze_RequestsAreTokenBounded(t *testing.T) {
	// Without a max_tokens ceiling, small models in JSON mode can repetition-
	// spiral on placeholder-only text and generate until the context fills —
	// which surfaces as deterministic scan timeouts on CPU hosts.
	var captured []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"entities\":[]}"}}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a, err := llm.New(llm.Config{Endpoint: srv.URL + "/v1", Model: "m"})
	require.NoError(t, err)
	_, err = a.Analyze(context.Background(), "Email [EMAIL] about IBAN [IBAN]")
	require.NoError(t, err)

	var req map[string]interface{}
	require.NoError(t, json.Unmarshal(captured, &req))
	assert.Equal(t, float64(2048), req["max_tokens"], "NER completions must be token-bounded")
	assert.Equal(t, float64(0), req["temperature"])
}

func TestParseDetections_ToleratedModelShapes(t *testing.T) {
	// Small models under JSON mode degenerate in structured but unambiguous
	// ways; each accepted shape is still gated by relocation afterwards.
	tests := []struct {
		name    string
		reply   string
		want    int
		wantErr bool
	}{
		{"canonical object", `{"entities":[{"type":"EMAIL_ADDRESS","value":"a@b.co"}]}`, 1, false},
		{"bare empty array (llama3.2:1b on placeholder-only text)", `[]`, 0, false},
		{"bare detection array", `[{"type":"EMAIL_ADDRESS","value":"a@b.co"}]`, 1, false},
		{"fenced array", "```json\n[]\n```", 0, false},
		{"array with prose around it", "Here you go: [] — nothing found.", 0, false},
		{"empty object", `{}`, 0, false},
		{"entities null", `{"entities":null}`, 0, false},
		{"prose only", "There is no PII in this text.", 0, true},
		{"empty reply", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dets, err := llm.ParseDetections(tt.reply)
			if tt.wantErr {
				require.Error(t, err, "unparseable replies stay fail-closed")
				return
			}
			require.NoError(t, err)
			assert.Len(t, dets, tt.want)
		})
	}
}

func TestVerifyEgress_BareArrayReplyOnRedactedText(t *testing.T) {
	// End-to-end shape of the field failure: raw text gets the canonical
	// object, the redacted verify re-scan gets a bare [] — the verify pass
	// must succeed instead of blocking with a decode failure.
	a := newAdapter(t, func(userText string) string {
		if strings.Contains(userText, "kai@example.com") {
			return nerReply([2]string{"EMAIL_ADDRESS", "kai@example.com"})
		}
		return `[]`
	})

	redacted, err := a.RedactText(context.Background(), "mail kai@example.com now")
	require.NoError(t, err)
	assert.Equal(t, "mail [EMAIL] now", redacted)
	assert.NoError(t, a.VerifyEgress(context.Background(), redacted),
		"a bare-array 'nothing found' reply must verify clean")
}
