package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	openaisdk "github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/llm"
)

func TestOpenAIGenerate_MalformedToolCallArgsSurfaceError(t *testing.T) {
	tests := []struct {
		name       string
		args       string
		wantError  bool
		wantRawKey bool
	}{
		{"valid_json", `{"location":"Berlin"}`, false, false},
		{"empty_args", ``, false, false},
		{"malformed_json", `{location: Berlin`, true, true},
		{"array_instead_of_object", `["a","b"]`, true, true},
		{"truncated_json", `{"loc": "Ber`, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, provider := newOpenAITestServer(t, func(w http.ResponseWriter, r *http.Request) {
				resp := openaisdk.ChatCompletionResponse{
					ID: "chatcmpl-test", Model: "gpt-4o",
					Choices: []openaisdk.ChatCompletionChoice{{
						Message: openaisdk.ChatCompletionMessage{
							Role: "assistant", ToolCalls: []openaisdk.ToolCall{
								{ID: "call_1", Type: openaisdk.ToolTypeFunction, Function: openaisdk.FunctionCall{Name: "get_weather", Arguments: tt.args}},
							},
						},
						FinishReason: openaisdk.FinishReasonToolCalls,
					}},
					Usage: openaisdk.Usage{PromptTokens: 5, CompletionTokens: 10},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
			})

			resp, err := provider.Generate(context.Background(), &llm.Request{
				Model: "gpt-4o", Messages: []llm.Message{{Role: "user", Content: "test"}}, MaxTokens: 50,
			})
			require.NoError(t, err)
			require.Len(t, resp.ToolCalls, 1)

			args := resp.ToolCalls[0].Arguments
			if tt.wantRawKey {
				assert.Contains(t, args, "_parse_error", "malformed JSON must surface _parse_error key")
				assert.Contains(t, args, "_raw_arguments", "malformed JSON must surface _raw_arguments key")
			} else if tt.args != "" {
				assert.NotContains(t, args, "_parse_error", "valid JSON must not have _parse_error")
			}
		})
	}
}
