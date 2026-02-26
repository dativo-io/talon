package gateway

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsResponsesAPIPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/v1/responses", true},
		{"/v1/responses/rs_abc123", true},
		{"/v1/chat/completions", false},
		{"/v1/models", false},
		{"/v1/responses-extra", true},
		{"/v2/responses", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, isResponsesAPIPath(tt.path))
		})
	}
}

func TestEnsureResponsesStore(t *testing.T) {
	t.Run("adds store true when missing", func(t *testing.T) {
		input := `{"model":"gpt-4o","input":"Hello"}`
		result := ensureResponsesStore([]byte(input))

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &m))
		assert.Equal(t, true, m["store"])
		assert.Equal(t, "gpt-4o", m["model"])
		assert.Equal(t, "Hello", m["input"])
	})

	t.Run("overwrites store false so multi-turn works through proxy", func(t *testing.T) {
		input := `{"model":"gpt-4o","input":"Hello","store":false}`
		result := ensureResponsesStore([]byte(input))

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &m))
		assert.Equal(t, true, m["store"], "gateway forces store:true so referenced response IDs persist")
	})

	t.Run("preserves store true when already set", func(t *testing.T) {
		input := `{"model":"gpt-4o","input":"Hello","store":true}`
		result := ensureResponsesStore([]byte(input))

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &m))
		assert.Equal(t, true, m["store"])
	})

	t.Run("preserves all other fields", func(t *testing.T) {
		input := `{"model":"gpt-4o","input":[{"type":"message","role":"user","content":"Hi"}],"previous_response_id":"rs_abc123","temperature":0.7}`
		result := ensureResponsesStore([]byte(input))

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &m))
		assert.Equal(t, true, m["store"])
		assert.Equal(t, "gpt-4o", m["model"])
		assert.Equal(t, "rs_abc123", m["previous_response_id"])
		assert.InDelta(t, 0.7, m["temperature"], 0.001)
	})

	t.Run("invalid json returns original body", func(t *testing.T) {
		input := `not json`
		result := ensureResponsesStore([]byte(input))
		assert.Equal(t, input, string(result))
	})
}
