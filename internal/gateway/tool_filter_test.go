package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Unit tests — EvaluateToolPolicy
// ---------------------------------------------------------------------------

func TestEvaluateToolPolicy_NoRestrictions(t *testing.T) {
	res := EvaluateToolPolicy(
		[]string{"search_web", "delete_emails"},
		nil, nil,
	)
	assert.Equal(t, []string{"search_web", "delete_emails"}, res.Kept)
	assert.Empty(t, res.Removed)
}

func TestEvaluateToolPolicy_AllowlistOnly(t *testing.T) {
	res := EvaluateToolPolicy(
		[]string{"search_web", "delete_emails", "read_file"},
		[]string{"search_web", "read_file"},
		nil,
	)
	assert.Equal(t, []string{"search_web", "read_file"}, res.Kept)
	assert.Equal(t, []string{"delete_emails"}, res.Removed)
}

func TestEvaluateToolPolicy_ForbiddenOnly(t *testing.T) {
	res := EvaluateToolPolicy(
		[]string{"search_web", "delete_emails", "admin_reset"},
		nil,
		[]string{"delete_*", "admin_*"},
	)
	assert.Equal(t, []string{"search_web"}, res.Kept)
	assert.Equal(t, []string{"delete_emails", "admin_reset"}, res.Removed)
}

func TestEvaluateToolPolicy_ForbiddenOverridesAllowed(t *testing.T) {
	res := EvaluateToolPolicy(
		[]string{"search_web", "delete_emails"},
		[]string{"search_web", "delete_emails"},
		[]string{"delete_*"},
	)
	assert.Equal(t, []string{"search_web"}, res.Kept)
	assert.Equal(t, []string{"delete_emails"}, res.Removed,
		"forbidden must override allowed")
}

func TestEvaluateToolPolicy_AllRemoved(t *testing.T) {
	res := EvaluateToolPolicy(
		[]string{"admin_reset", "admin_delete"},
		nil,
		[]string{"admin_*"},
	)
	assert.Empty(t, res.Kept)
	assert.Equal(t, []string{"admin_reset", "admin_delete"}, res.Removed)
}

func TestEvaluateToolPolicy_ExactForbiddenMatch(t *testing.T) {
	res := EvaluateToolPolicy(
		[]string{"send_email", "read_email"},
		nil,
		[]string{"send_email"},
	)
	assert.Equal(t, []string{"read_email"}, res.Kept)
	assert.Equal(t, []string{"send_email"}, res.Removed)
}

func TestEvaluateToolPolicy_CaseInsensitive(t *testing.T) {
	res := EvaluateToolPolicy(
		[]string{"Delete_User", "search_web"},
		nil,
		[]string{"delete_*"},
	)
	assert.Equal(t, []string{"search_web"}, res.Kept)
	assert.Equal(t, []string{"Delete_User"}, res.Removed)
}

// ---------------------------------------------------------------------------
// Unit tests — ResolveToolPolicy (three-level merge)
// ---------------------------------------------------------------------------

func TestResolveToolPolicy_DefaultOnly(t *testing.T) {
	dp := &DefaultPolicyConfig{
		ForbiddenTools:   []string{"admin_*"},
		ToolPolicyAction: "block",
	}
	res := ResolveToolPolicy(dp, ProviderConfig{}, nil)
	assert.Equal(t, "block", res.Action)
	assert.Equal(t, []string{"admin_*"}, res.ForbiddenTools)
	assert.Empty(t, res.AllowedTools)
}

func TestResolveToolPolicy_ProviderMerge(t *testing.T) {
	dp := &DefaultPolicyConfig{
		ForbiddenTools:   []string{"admin_*"},
		ToolPolicyAction: "filter",
	}
	prov := ProviderConfig{
		ForbiddenTools:   []string{"export_*"},
		ToolPolicyAction: "block",
	}
	res := ResolveToolPolicy(dp, prov, nil)
	assert.Equal(t, "block", res.Action, "provider overrides default action")
	assert.Contains(t, res.ForbiddenTools, "admin_*")
	assert.Contains(t, res.ForbiddenTools, "export_*")
}

func TestResolveToolPolicy_CallerOverride(t *testing.T) {
	dp := &DefaultPolicyConfig{
		ForbiddenTools:   []string{"admin_*"},
		ToolPolicyAction: "block",
	}
	prov := ProviderConfig{
		ForbiddenTools: []string{"export_*"},
	}
	caller := &CallerPolicyOverrides{
		AllowedTools:     []string{"search_web", "read_file"},
		ForbiddenTools:   []string{"delete_*"},
		ToolPolicyAction: "filter",
	}
	res := ResolveToolPolicy(dp, prov, caller)
	assert.Equal(t, "filter", res.Action, "caller overrides all")
	assert.Equal(t, []string{"search_web", "read_file"}, res.AllowedTools)
	assert.Contains(t, res.ForbiddenTools, "admin_*")
	assert.Contains(t, res.ForbiddenTools, "export_*")
	assert.Contains(t, res.ForbiddenTools, "delete_*")
}

func TestResolveToolPolicy_NoDuplicateForbidden(t *testing.T) {
	dp := &DefaultPolicyConfig{ForbiddenTools: []string{"admin_*"}}
	prov := ProviderConfig{ForbiddenTools: []string{"admin_*", "export_*"}}
	caller := &CallerPolicyOverrides{ForbiddenTools: []string{"export_*", "delete_*"}}

	res := ResolveToolPolicy(dp, prov, caller)
	counts := make(map[string]int)
	for _, f := range res.ForbiddenTools {
		counts[f]++
	}
	for pattern, c := range counts {
		assert.Equal(t, 1, c, "pattern %q should appear exactly once", pattern)
	}
}

func TestResolveToolPolicy_DefaultAction(t *testing.T) {
	dp := &DefaultPolicyConfig{}
	res := ResolveToolPolicy(dp, ProviderConfig{}, nil)
	assert.Equal(t, DefaultToolPolicyAction, res.Action, "default action should be 'filter'")
}

// ---------------------------------------------------------------------------
// Unit tests — Tool name extraction
// ---------------------------------------------------------------------------

func TestExtractOpenAI_ChatCompletions_ToolNames(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "delete_emails", "parameters": {}}}
		]
	}`
	ex, err := ExtractOpenAI([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, []string{"search_web", "delete_emails"}, ex.ToolNames)
}

func TestExtractOpenAI_ResponsesAPI_ToolNames(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"input": "hello",
		"tools": [
			{"type": "function", "name": "search_web"},
			{"type": "function", "name": "read_file"}
		]
	}`
	ex, err := ExtractOpenAI([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, []string{"search_web", "read_file"}, ex.ToolNames)
}

func TestExtractOpenAI_NoTools(t *testing.T) {
	body := `{"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]}`
	ex, err := ExtractOpenAI([]byte(body))
	require.NoError(t, err)
	assert.Empty(t, ex.ToolNames)
}

func TestExtractAnthropic_ToolNames(t *testing.T) {
	body := `{
		"model": "claude-3-opus",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"name": "search_web", "description": "Search the web", "input_schema": {}},
			{"name": "send_email", "description": "Send email", "input_schema": {}}
		]
	}`
	ex, err := ExtractAnthropic([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, []string{"search_web", "send_email"}, ex.ToolNames)
}

// ---------------------------------------------------------------------------
// Unit tests — FilterRequestBodyTools
// ---------------------------------------------------------------------------

func TestFilterRequestBodyTools_OpenAI_ChatCompletions(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "delete_emails", "parameters": {}}},
			{"type": "function", "function": {"name": "read_file", "parameters": {}}}
		]
	}`
	filtered, err := FilterRequestBodyTools("openai", []byte(body), []string{"search_web", "read_file"})
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(filtered, &m))

	tools := m["tools"].([]interface{})
	assert.Len(t, tools, 2)

	names := toolNamesFromJSON(tools)
	assert.Contains(t, names, "search_web")
	assert.Contains(t, names, "read_file")
	assert.NotContains(t, names, "delete_emails")
}

func TestFilterRequestBodyTools_OpenAI_ResponsesAPI(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"input": "hello",
		"tools": [
			{"type": "function", "name": "search_web"},
			{"type": "function", "name": "delete_emails"}
		]
	}`
	filtered, err := FilterRequestBodyTools("openai", []byte(body), []string{"search_web"})
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(filtered, &m))

	tools := m["tools"].([]interface{})
	assert.Len(t, tools, 1)
	tool := tools[0].(map[string]interface{})
	assert.Equal(t, "search_web", tool["name"])
}

func TestFilterRequestBodyTools_Anthropic(t *testing.T) {
	body := `{
		"model": "claude-3-opus",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"name": "search_web", "description": "Search", "input_schema": {}},
			{"name": "delete_user", "description": "Delete", "input_schema": {}}
		]
	}`
	filtered, err := FilterRequestBodyTools("anthropic", []byte(body), []string{"search_web"})
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(filtered, &m))

	tools := m["tools"].([]interface{})
	assert.Len(t, tools, 1)
	tool := tools[0].(map[string]interface{})
	assert.Equal(t, "search_web", tool["name"])
}

func TestFilterRequestBodyTools_AllToolsRemoved(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [{"type": "function", "function": {"name": "admin_reset"}}],
		"tool_choice": {"type": "function", "function": {"name": "admin_reset"}}
	}`
	filtered, err := FilterRequestBodyTools("openai", []byte(body), nil)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(filtered, &m))

	assert.Nil(t, m["tools"], "tools should be removed when all are filtered")
	assert.Nil(t, m["tool_choice"], "tool_choice should be removed when all tools are filtered")
}

func TestFilterRequestBodyTools_ToolChoiceFixup(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web"}},
			{"type": "function", "function": {"name": "delete_emails"}}
		],
		"tool_choice": {"type": "function", "function": {"name": "delete_emails"}}
	}`
	filtered, err := FilterRequestBodyTools("openai", []byte(body), []string{"search_web"})
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(filtered, &m))

	assert.Equal(t, "auto", m["tool_choice"],
		"tool_choice must reset to 'auto' when it references a removed tool")
}

func TestFilterRequestBodyTools_ToolChoiceStringPreserved(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [{"type": "function", "function": {"name": "search_web"}}],
		"tool_choice": "required"
	}`
	filtered, err := FilterRequestBodyTools("openai", []byte(body), []string{"search_web"})
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(filtered, &m))

	assert.Equal(t, "required", m["tool_choice"],
		"string tool_choice values should be preserved")
}

func TestFilterRequestBodyTools_NoTools(t *testing.T) {
	body := `{"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]}`
	filtered, err := FilterRequestBodyTools("openai", []byte(body), []string{"search_web"})
	require.NoError(t, err)
	assert.JSONEq(t, body, string(filtered), "body without tools should pass through unchanged")
}

func TestFilterRequestBodyTools_InvalidJSON(t *testing.T) {
	_, err := FilterRequestBodyTools("openai", []byte(`{not json`), []string{"search_web"})
	require.Error(t, err, "invalid JSON must return an error")
}

func TestFilterRequestBodyTools_InvalidJSON_Anthropic(t *testing.T) {
	_, err := FilterRequestBodyTools("anthropic", []byte(`{not json`), []string{"search_web"})
	require.Error(t, err, "invalid JSON must return an error for Anthropic provider")
}

// ---------------------------------------------------------------------------
// Integration tests — Gateway with tool governance
// ---------------------------------------------------------------------------

func TestGateway_ToolGovernance_FilterMode(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"delete_*", "admin_*"}

	body := `{
		"model": "gpt-4o-mini",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "delete_emails", "parameters": {}}},
			{"type": "function", "function": {"name": "admin_reset", "parameters": {}}}
		]
	}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	var forwarded map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &forwarded))

	tools := forwarded["tools"].([]interface{})
	names := toolNamesFromJSON(tools)
	assert.Equal(t, []string{"search_web"}, names,
		"only search_web should be forwarded; delete_emails and admin_reset should be filtered")
}

func TestGateway_ToolGovernance_BlockMode(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[]}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"delete_*"}
	gw.config.DefaultPolicy.ToolPolicyAction = "block"

	body := `{
		"model": "gpt-4o-mini",
		"messages": [{"role": "user", "content": "delete my emails"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "delete_emails", "parameters": {}}}
		]
	}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusForbidden, w.Code,
		"block mode must reject the request when forbidden tools are present")
	assert.Contains(t, w.Body.String(), "forbidden tools",
		"error message should mention forbidden tools")
}

func TestGateway_ToolGovernance_CallerAllowlist(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "warn", handler)
	gw.config.Callers[0].PolicyOverrides.AllowedTools = []string{"search_web", "read_file"}

	body := `{
		"model": "gpt-4o-mini",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "delete_emails", "parameters": {}}},
			{"type": "function", "function": {"name": "read_file", "parameters": {}}},
			{"type": "function", "function": {"name": "send_sms", "parameters": {}}}
		]
	}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	var forwarded map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &forwarded))

	tools := forwarded["tools"].([]interface{})
	names := toolNamesFromJSON(tools)
	assert.Equal(t, []string{"search_web", "read_file"}, names,
		"only allowlisted tools should be forwarded")
}

func TestGateway_ToolGovernance_ThreeLevelMerge(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"admin_*"}
	gw.config.Providers["openai"] = ProviderConfig{
		Enabled:        true,
		BaseURL:        gw.config.Providers["openai"].BaseURL,
		SecretName:     "openai-api-key",
		ForbiddenTools: []string{"export_*"},
	}
	gw.config.Callers[0].PolicyOverrides.ForbiddenTools = []string{"bulk_*"}

	body := `{
		"model": "gpt-4o-mini",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "admin_reset", "parameters": {}}},
			{"type": "function", "function": {"name": "export_csv", "parameters": {}}},
			{"type": "function", "function": {"name": "bulk_delete", "parameters": {}}},
			{"type": "function", "function": {"name": "read_file", "parameters": {}}}
		]
	}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	var forwarded map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &forwarded))

	tools := forwarded["tools"].([]interface{})
	names := toolNamesFromJSON(tools)
	assert.Equal(t, []string{"search_web", "read_file"}, names,
		"admin_* (default), export_* (provider), bulk_* (caller) should all be filtered")
}

func TestGateway_ToolGovernance_NoToolsPassThrough(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"delete_*"}

	body := `{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hello"}]}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	var forwarded map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &forwarded))
	assert.Nil(t, forwarded["tools"],
		"requests without tools should pass through unchanged")
}

func TestGateway_ToolGovernance_AllToolsAllowed(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"admin_*"}

	body := `{
		"model": "gpt-4o-mini",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "read_file", "parameters": {}}}
		]
	}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	var forwarded map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &forwarded))

	tools := forwarded["tools"].([]interface{})
	names := toolNamesFromJSON(tools)
	assert.Equal(t, []string{"search_web", "read_file"}, names,
		"all-clean tools should pass through unmodified")
}

func TestGateway_ToolGovernance_Evidence(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
	})

	gw, _, evStore := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"delete_*"}

	body := `{
		"model": "gpt-4o-mini",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "delete_emails", "parameters": {}}}
		]
	}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	records, err := evStore.List(context.Background(), "test-tenant", "openclaw-main",
		time.Now().Add(-time.Minute), time.Now().Add(time.Minute), 10)
	require.NoError(t, err)
	require.NotEmpty(t, records)

	latest := records[0]
	require.NotNil(t, latest.ToolGovernance, "evidence must include tool governance data")
	assert.Equal(t, []string{"search_web", "delete_emails"}, latest.ToolGovernance.ToolsRequested)
	assert.Equal(t, []string{"delete_emails"}, latest.ToolGovernance.ToolsFiltered)
	assert.Equal(t, []string{"search_web"}, latest.ToolGovernance.ToolsForwarded)
}

// ---------------------------------------------------------------------------
// Unit tests — Anthropic tool_choice fixup
// ---------------------------------------------------------------------------

func TestFilterRequestBodyTools_Anthropic_ToolChoiceFixup(t *testing.T) {
	body := `{
		"model": "claude-3-opus",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"name": "search_web", "description": "Search", "input_schema": {}},
			{"name": "delete_user", "description": "Delete", "input_schema": {}}
		],
		"tool_choice": {"type": "tool", "name": "delete_user"}
	}`
	filtered, err := FilterRequestBodyTools("anthropic", []byte(body), []string{"search_web"})
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(filtered, &m))

	tcObj, ok := m["tool_choice"].(map[string]interface{})
	require.True(t, ok, "Anthropic tool_choice must be an object, not a string")
	assert.Equal(t, "auto", tcObj["type"],
		"Anthropic tool_choice referencing a removed tool must reset to {\"type\":\"auto\"}")
	tools := m["tools"].([]interface{})
	assert.Len(t, tools, 1)
	assert.Equal(t, "search_web", tools[0].(map[string]interface{})["name"])
}

// ---------------------------------------------------------------------------
// Unit tests — ExtractForProvider preserves ToolNames
// ---------------------------------------------------------------------------

func TestExtractForProvider_OpenAI_ToolNames(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "hi"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "read_file", "parameters": {}}}
		]
	}`
	ex, err := ExtractForProvider("openai", []byte(body))
	require.NoError(t, err)
	assert.Equal(t, []string{"search_web", "read_file"}, ex.ToolNames)
}

func TestExtractForProvider_Anthropic_ToolNames(t *testing.T) {
	body := `{
		"model": "claude-3-opus",
		"messages": [{"role": "user", "content": "hi"}],
		"tools": [
			{"name": "search_web", "description": "Search", "input_schema": {}},
			{"name": "send_email", "description": "Email", "input_schema": {}}
		]
	}`
	ex, err := ExtractForProvider("anthropic", []byte(body))
	require.NoError(t, err)
	assert.Equal(t, []string{"search_web", "send_email"}, ex.ToolNames)
}

// ---------------------------------------------------------------------------
// Unit tests — tool_choice kept for allowed tool
// ---------------------------------------------------------------------------

func TestFilterRequestBodyTools_ToolChoiceKeptForAllowedTool(t *testing.T) {
	body := `{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web"}},
			{"type": "function", "function": {"name": "delete_emails"}}
		],
		"tool_choice": {"type": "function", "function": {"name": "search_web"}}
	}`
	filtered, err := FilterRequestBodyTools("openai", []byte(body), []string{"search_web"})
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(filtered, &m))

	tc, ok := m["tool_choice"].(map[string]interface{})
	require.True(t, ok, "tool_choice should remain an object when referencing an allowed tool")
	fn := tc["function"].(map[string]interface{})
	assert.Equal(t, "search_web", fn["name"],
		"tool_choice must be preserved when it references a kept tool")
}

// ---------------------------------------------------------------------------
// Unit tests — nil ToolGovernance evidence
// ---------------------------------------------------------------------------

func TestGateway_Evidence_NilToolGovernance(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
	})

	gw, _, evStore := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"admin_*"}

	body := `{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hello"}]}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	records, err := evStore.List(context.Background(), "test-tenant", "openclaw-main",
		time.Now().Add(-time.Minute), time.Now().Add(time.Minute), 10)
	require.NoError(t, err)
	require.NotEmpty(t, records)

	assert.Nil(t, records[0].ToolGovernance,
		"evidence for a request without tools must have nil ToolGovernance, not an empty struct")
}

// ---------------------------------------------------------------------------
// Integration tests — Responses API + tool governance (filter)
// ---------------------------------------------------------------------------

func TestGateway_ToolGovernance_ResponsesAPI_Filter(t *testing.T) {
	var capturedBody []byte
	handler := responsesAPIUpstream(&capturedBody, new(string))

	gw, _, _ := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"delete_*"}

	body := `{
		"model": "gpt-4o-mini",
		"input": "hello",
		"tools": [
			{"type": "function", "name": "search_web"},
			{"type": "function", "name": "delete_emails"}
		]
	}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	var forwarded map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &forwarded))

	tools := forwarded["tools"].([]interface{})
	names := toolNamesFromJSON(tools)
	assert.Equal(t, []string{"search_web"}, names,
		"Responses API: delete_emails should be filtered out")
}

// ---------------------------------------------------------------------------
// Integration tests — Block mode evidence recording
// ---------------------------------------------------------------------------

func TestGateway_ToolGovernance_BlockMode_Evidence(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream should not be called in block mode")
	})

	gw, _, evStore := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"delete_*"}
	gw.config.DefaultPolicy.ToolPolicyAction = "block"

	body := `{
		"model": "gpt-4o-mini",
		"messages": [{"role": "user", "content": "delete stuff"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "delete_emails", "parameters": {}}}
		]
	}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusForbidden, w.Code)

	records, err := evStore.List(context.Background(), "test-tenant", "openclaw-main",
		time.Now().Add(-time.Minute), time.Now().Add(time.Minute), 10)
	require.NoError(t, err)
	require.NotEmpty(t, records)

	latest := records[0]
	require.NotNil(t, latest.ToolGovernance, "block-mode evidence must include ToolGovernance")
	assert.Equal(t, []string{"search_web", "delete_emails"}, latest.ToolGovernance.ToolsRequested)
	assert.Equal(t, []string{"delete_emails"}, latest.ToolGovernance.ToolsFiltered)
	assert.Equal(t, []string{"search_web"}, latest.ToolGovernance.ToolsForwarded,
		"ToolsForwarded should reflect what would have been forwarded")
}

// ---------------------------------------------------------------------------
// Integration tests — Filter mode with tool_choice fixup through gateway
// ---------------------------------------------------------------------------

func TestGateway_ToolGovernance_ToolChoiceFixup(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"delete_*"}

	body := `{
		"model": "gpt-4o-mini",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "delete_emails", "parameters": {}}}
		],
		"tool_choice": {"type": "function", "function": {"name": "delete_emails"}}
	}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	var forwarded map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &forwarded))

	assert.Equal(t, "auto", forwarded["tool_choice"],
		"tool_choice must be reset to 'auto' when it references a filtered tool")
	tools := forwarded["tools"].([]interface{})
	names := toolNamesFromJSON(tools)
	assert.Equal(t, []string{"search_web"}, names)
}

// ---------------------------------------------------------------------------
// Integration tests — All tools filtered through gateway
// ---------------------------------------------------------------------------

func TestGateway_ToolGovernance_AllToolsFiltered(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"admin_*"}

	body := `{
		"model": "gpt-4o-mini",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"type": "function", "function": {"name": "admin_reset", "parameters": {}}},
			{"type": "function", "function": {"name": "admin_delete", "parameters": {}}}
		],
		"tool_choice": {"type": "function", "function": {"name": "admin_reset"}}
	}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	var forwarded map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &forwarded))

	assert.Nil(t, forwarded["tools"],
		"all-tools-filtered: tools key should be removed from forwarded body")
	assert.Nil(t, forwarded["tool_choice"],
		"all-tools-filtered: tool_choice should be removed from forwarded body")
}

// ---------------------------------------------------------------------------
// Integration tests — Tool filtering + PII redaction combined (regression test)
// ---------------------------------------------------------------------------

func TestGateway_ToolGovernance_PIIRedaction_Combined(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"delete_*"}

	body := `{
		"model": "gpt-4o-mini",
		"messages": [{"role": "user", "content": "My IBAN is DE89370400440532013000, please delete my account."}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "delete_account", "parameters": {}}}
		]
	}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	var forwarded map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &forwarded))

	tools := forwarded["tools"].([]interface{})
	names := toolNamesFromJSON(tools)
	assert.Equal(t, []string{"search_web"}, names,
		"forbidden tool must be removed even when PII redaction is also active")
	assert.NotContains(t, names, "delete_account")

	msgs := forwarded["messages"].([]interface{})
	content := msgs[0].(map[string]interface{})["content"].(string)
	assert.NotContains(t, content, "DE89370400440532013000",
		"PII (IBAN) must be redacted in the forwarded body")
	assert.Contains(t, content, "[IBAN]",
		"PII redaction should replace the IBAN with a type marker")
}

// ---------------------------------------------------------------------------
// Integration tests — Tool filtering + streaming request
// ---------------------------------------------------------------------------

func TestGateway_ToolGovernance_Streaming(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		respJSON := `{"id":"resp_ok","output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":5,"output_tokens":2}}`
		_, _ = w.Write([]byte(sseResponse(respJSON)))
	})

	gw, _, _ := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ForbiddenTools = []string{"delete_*"}

	body := `{
		"model": "gpt-4o-mini",
		"messages": [{"role": "user", "content": "hello"}],
		"stream": true,
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "delete_emails", "parameters": {}}}
		]
	}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	var forwarded map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &forwarded))

	tools := forwarded["tools"].([]interface{})
	names := toolNamesFromJSON(tools)
	assert.Equal(t, []string{"search_web"}, names,
		"streaming request: forbidden tools must still be filtered")
	assert.Equal(t, true, forwarded["stream"],
		"stream flag should be preserved in forwarded body")
}

// ---------------------------------------------------------------------------
// Integration tests — Provider-level-only forbidden_tools
// ---------------------------------------------------------------------------

func TestGateway_ToolGovernance_ProviderOnlyForbidden(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "warn", handler)
	// No default forbidden tools, no caller overrides — only provider level.
	gw.config.DefaultPolicy.ForbiddenTools = nil
	gw.config.Providers["openai"] = ProviderConfig{
		Enabled:        true,
		BaseURL:        gw.config.Providers["openai"].BaseURL,
		SecretName:     "openai-api-key",
		ForbiddenTools: []string{"export_*"},
	}

	body := `{
		"model": "gpt-4o-mini",
		"messages": [{"role": "user", "content": "hello"}],
		"tools": [
			{"type": "function", "function": {"name": "search_web", "parameters": {}}},
			{"type": "function", "function": {"name": "export_csv", "parameters": {}}}
		]
	}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	var forwarded map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &forwarded))

	tools := forwarded["tools"].([]interface{})
	names := toolNamesFromJSON(tools)
	assert.Equal(t, []string{"search_web"}, names,
		"provider-level-only: export_csv should be filtered by provider forbidden_tools")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func toolNamesFromJSON(tools []interface{}) []string {
	var names []string
	for _, raw := range tools {
		tool, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if fn, ok := tool["function"].(map[string]interface{}); ok {
			if n, ok := fn["name"].(string); ok {
				names = append(names, n)
			}
		} else if n, ok := tool["name"].(string); ok {
			names = append(names, n)
		}
	}
	return names
}
