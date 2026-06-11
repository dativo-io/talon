package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

const (
	dataFlowTestEmail = "john.doe@example.com"
	dataFlowTestIBAN  = "DE89370400440532013000"
)

func dataFlowRequestBody() string {
	return `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Email ` +
		dataFlowTestEmail + ` and IBAN ` + dataFlowTestIBAN + `"}]}`
}

// chatCompletionUpstream returns a chat completion whose content echoes the
// given text (used to prove input->output digest correlation).
func chatCompletionUpstream(content string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"id":    "chatcmpl-test",
			"model": "gpt-4o-mini",
			"choices": []interface{}{
				map[string]interface{}{
					"index":         0,
					"message":       map[string]interface{}{"role": "assistant", "content": content},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]interface{}{"prompt_tokens": 10, "completion_tokens": 5},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func findFlowItem(t *testing.T, df *evidence.DataFlow, source string) *evidence.DataFlowItem {
	t.Helper()
	require.NotNil(t, df, "data_flow must be present")
	for i := range df.Items {
		if df.Items[i].Source == source {
			return &df.Items[i]
		}
	}
	t.Fatalf("no data_flow item with source %q (items: %+v)", source, df.Items)
	return nil
}

func TestGatewayDataFlow_PromptToProviderAndResponseToClient(t *testing.T) {
	gw, upstream, evStore := setupOpenClawGateway(t, "redact",
		chatCompletionUpstream("Sure — I will reach out to "+dataFlowTestEmail+" shortly."))
	prov := gw.config.Providers["openai"]
	prov.Region = "US"
	gw.config.Providers["openai"] = prov

	w := makeGatewayRequest(gw, dataFlowRequestBody())
	require.Equal(t, http.StatusOK, w.Code)

	records, err := evStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, records, 1)
	ev := &records[0]

	require.NotNil(t, ev.DataFlow)
	assert.Equal(t, "talon-regex", ev.DataFlow.Detector)

	// Prompt -> provider: redacted before forwarding, full destination identity.
	prompt := findFlowItem(t, ev.DataFlow, evidence.FlowSourcePrompt)
	assert.Equal(t, evidence.FlowDispositionRedacted, prompt.Disposition)
	assert.Equal(t, evidence.FlowDestLLMProvider, prompt.Destination.Kind)
	assert.Equal(t, "openai", prompt.Destination.Name)
	assert.Equal(t, "gpt-4o-mini", prompt.Destination.Model)
	assert.Equal(t, "US", prompt.Destination.Region)
	u, _ := url.Parse(upstream.URL)
	assert.Equal(t, u.Host, prompt.Destination.Endpoint)
	assert.Equal(t, 2, prompt.Tier, "IBAN must classify the prompt as tier 2")
	assert.Contains(t, prompt.EntityTypes, "email")
	assert.Contains(t, prompt.EntityTypes, "iban")
	require.NotEmpty(t, prompt.ValueDigests)

	// Response -> client: the same email surfaced in the output; redacted by
	// response scanning, and the digest matches the prompt-side digest.
	response := findFlowItem(t, ev.DataFlow, evidence.FlowSourceResponse)
	assert.Equal(t, evidence.FlowDispositionRedacted, response.Disposition)
	assert.Equal(t, evidence.FlowDestClient, response.Destination.Kind)
	assert.Equal(t, "openclaw-main", response.Destination.Name)
	assert.Contains(t, response.EntityTypes, "email")

	emailDigest := evidence.FlowDigest(ev.TenantID, ev.CorrelationID, "email", dataFlowTestEmail)
	assert.Contains(t, prompt.ValueDigests, emailDigest)
	assert.Contains(t, response.ValueDigests, emailDigest,
		"same classified value must produce the same digest in input and output")

	// The signed record (including data_flow) must verify.
	assert.True(t, evStore.VerifyRecord(ev), "signed record with data_flow must verify")
}

func TestGatewayDataFlow_NeverStoresRawPII(t *testing.T) {
	gw, _, evStore := setupOpenClawGateway(t, "redact",
		chatCompletionUpstream("Done, contacting "+dataFlowTestEmail+"."))

	w := makeGatewayRequest(gw, dataFlowRequestBody())
	require.Equal(t, http.StatusOK, w.Code)

	records, err := evStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, records, 1)

	raw, err := json.Marshal(&records[0])
	require.NoError(t, err)
	serialized := string(raw)
	assert.NotContains(t, serialized, dataFlowTestEmail, "raw email must never reach evidence")
	assert.NotContains(t, serialized, dataFlowTestIBAN, "raw IBAN must never reach evidence")
	assert.NotContains(t, serialized, strings.Split(dataFlowTestEmail, "@")[0], "email local part must never reach evidence")
}

func TestGatewayDataFlow_BlockedRequestRecordsBlockedDisposition(t *testing.T) {
	gw, _, evStore := setupOpenClawGateway(t, "block",
		chatCompletionUpstream("never reached"))

	w := makeGatewayRequest(gw, dataFlowRequestBody())
	require.Equal(t, http.StatusBadRequest, w.Code, "PII block must reject the request")

	records, err := evStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, records, 1)
	ev := &records[0]

	prompt := findFlowItem(t, ev.DataFlow, evidence.FlowSourcePrompt)
	assert.Equal(t, evidence.FlowDispositionBlocked, prompt.Disposition,
		"blocked egress must still leave a flow trail with disposition=blocked")
	assert.Equal(t, evidence.FlowDestLLMProvider, prompt.Destination.Kind)
	assert.False(t, ev.PolicyDecision.Allowed)
}

func TestGatewayBuildDataFlow_CacheHit(t *testing.T) {
	gw, _, _ := setupOpenClawGateway(t, "warn", chatCompletionUpstream("unused"))

	text := "Email " + dataFlowTestEmail
	cls := gw.classifier.Scan(context.Background(), text)
	require.True(t, cls.HasPII)

	df := gw.buildDataFlow(dataFlowInputs{
		CorrelationID:  "corr_cache",
		TenantID:       "test-tenant",
		CallerName:     "openclaw-main",
		Provider:       "openai",
		Model:          "gpt-4o-mini",
		Allowed:        true,
		InputText:      text,
		Classification: cls,
		CacheHit:       true,
		CacheEntryID:   "entry-123",
	})
	require.NotNil(t, df)
	require.Len(t, df.Items, 1)
	item := df.Items[0]
	assert.Equal(t, evidence.FlowSourcePrompt, item.Source)
	assert.Equal(t, evidence.FlowDestCache, item.Destination.Kind,
		"cache hit must record the cache, not the provider, as destination")
	assert.Equal(t, "entry-123", item.Destination.Name)
	for _, it := range df.Items {
		assert.NotEqual(t, evidence.FlowDestLLMProvider, it.Destination.Kind,
			"nothing egressed to the provider on a cache hit")
	}
}

func TestGatewayBuildDataFlow_CacheStoreAfterForward(t *testing.T) {
	gw, _, _ := setupOpenClawGateway(t, "warn", chatCompletionUpstream("unused"))

	text := "Email " + dataFlowTestEmail
	cls := gw.classifier.Scan(context.Background(), text)
	require.True(t, cls.HasPII)

	df := gw.buildDataFlow(dataFlowInputs{
		CorrelationID:  "corr_store",
		TenantID:       "test-tenant",
		CallerName:     "openclaw-main",
		Provider:       "openai",
		Model:          "gpt-4o-mini",
		Allowed:        true,
		InputText:      text,
		Classification: cls,
		ResponsePII: &ResponsePIIScanResult{
			PIIDetected: true,
			PIITypes:    []string{"email"},
			Redacted:    true,
			Tier:        1,
		},
		CacheStored: true,
	})
	require.NotNil(t, df)

	kinds := make(map[string]int)
	for _, it := range df.Items {
		kinds[it.Destination.Kind]++
	}
	assert.Equal(t, 1, kinds[evidence.FlowDestLLMProvider], "prompt egressed to the provider")
	assert.Equal(t, 1, kinds[evidence.FlowDestClient], "response surfaced to the client")
	assert.Equal(t, 1, kinds[evidence.FlowDestCache], "stored response adds a cache destination item")
}

func TestGatewayDataFlow_RecordedWhenNoClassifiedData(t *testing.T) {
	gw, _, evStore := setupOpenClawGateway(t, "redact",
		chatCompletionUpstream("All good."))

	w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"What is the weather like?"}]}`)
	require.Equal(t, http.StatusOK, w.Code)

	records, err := evStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, records, 1)
	df := records[0].DataFlow
	require.NotNil(t, df, "every governed request must record its prompt egress flow")
	require.Len(t, df.Items, 1, "only the prompt -> provider item; no classified response items")
	item := df.Items[0]
	assert.Equal(t, evidence.FlowSourcePrompt, item.Source)
	assert.Equal(t, evidence.FlowDispositionForwarded, item.Disposition)
	assert.Equal(t, evidence.FlowDestLLMProvider, item.Destination.Kind)
	assert.Empty(t, item.EntityTypes, "no PII detected, no entity types")
	assert.Equal(t, 0, item.Tier)
}
