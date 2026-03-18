package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubTool is a minimal Tool implementation for testing.
type stubTool struct {
	name string
	desc string
}

func (s *stubTool) Name() string                 { return s.name }
func (s *stubTool) Description() string          { return s.desc }
func (s *stubTool) InputSchema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (s *stubTool) Execute(_ context.Context, params json.RawMessage) (json.RawMessage, error) {
	return json.RawMessage(`{"ok":true}`), nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	tool := &stubTool{name: "search", desc: "Search tool"}

	r.Register(tool)

	got, ok := r.Get("search")
	require.True(t, ok)
	assert.Equal(t, "search", got.Name())
	assert.Equal(t, "Search tool", got.Description())
}

func TestRegistry_GetMissing(t *testing.T) {
	r := NewRegistry()
	_, ok := r.Get("nonexistent")
	assert.False(t, ok)
}

func TestRegistry_List(t *testing.T) {
	r := NewRegistry()

	assert.Len(t, r.List(), 0)

	r.Register(&stubTool{name: "tool-a", desc: "A"})
	r.Register(&stubTool{name: "tool-b", desc: "B"})

	tools := r.List()
	assert.Len(t, tools, 2)

	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.Name()] = true
	}
	assert.True(t, names["tool-a"])
	assert.True(t, names["tool-b"])
}

func TestRegistry_OverwriteExisting(t *testing.T) {
	r := NewRegistry()

	r.Register(&stubTool{name: "search", desc: "v1"})
	r.Register(&stubTool{name: "search", desc: "v2"})

	got, ok := r.Get("search")
	require.True(t, ok)
	assert.Equal(t, "v2", got.Description())
	assert.Len(t, r.List(), 1)
}

func TestRegistry_Execute(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubTool{name: "echo", desc: "Echo"})

	tool, ok := r.Get("echo")
	require.True(t, ok)

	result, err := tool.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true}`, string(result))
}

func TestValidateAgainstSchema(t *testing.T) {
	validSchema := json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`)

	tests := []struct {
		name    string
		schema  json.RawMessage
		params  json.RawMessage
		wantErr bool
	}{
		{
			name:    "valid args",
			schema:  validSchema,
			params:  json.RawMessage(`{"query":"hello"}`),
			wantErr: false,
		},
		{
			name:    "invalid type",
			schema:  validSchema,
			params:  json.RawMessage(`{"query":42}`),
			wantErr: true,
		},
		{
			name:    "missing required",
			schema:  validSchema,
			params:  json.RawMessage(`{}`),
			wantErr: true,
		},
		{
			name:    "empty schema skips validation",
			schema:  json.RawMessage(`{}`),
			params:  json.RawMessage(`{"anything":true}`),
			wantErr: false,
		},
		{
			name:    "null schema skips validation",
			schema:  json.RawMessage(`null`),
			params:  json.RawMessage(`{"x":1}`),
			wantErr: false,
		},
		{
			name:    "nil params treated as empty object",
			schema:  json.RawMessage(`{"type":"object"}`),
			params:  nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAgainstSchema(tt.schema, tt.params)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "schema validation")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
