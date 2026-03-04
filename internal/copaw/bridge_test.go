package copaw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/tools"
)

func TestNewBridge(t *testing.T) {
	b := NewBridge(BridgeConfig{BaseURL: "http://localhost:8088"})
	require.NotNil(t, b)
	assert.NotNil(t, b.client)
	assert.Equal(t, "http://localhost:8088", b.cfg.BaseURL)
}

func TestNewBridge_WithClient(t *testing.T) {
	client := &http.Client{}
	b := NewBridge(BridgeConfig{BaseURL: "http://localhost:8088", HTTPClient: client})
	require.NotNil(t, b)
	assert.Same(t, client, b.client)
}

func TestListSkills_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/skills", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		body := []map[string]interface{}{
			{"name": "skill_a", "content": "Does A", "enabled": true},
			{"name": "skill_b", "content": "Long description " + string(make([]byte, 250)), "enabled": false},
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()

	b := NewBridge(BridgeConfig{BaseURL: server.URL, HTTPClient: server.Client()})
	skills, err := b.ListSkills(context.Background())
	require.NoError(t, err)
	require.Len(t, skills, 2)
	assert.Equal(t, "skill_a", skills[0].Name)
	assert.Equal(t, "Does A", skills[0].Description)
	assert.True(t, skills[0].Enabled)
	assert.Equal(t, "skill_b", skills[1].Name)
	assert.False(t, skills[1].Enabled)
	// truncateDescription(250+ chars, 200) -> 200 + "..."
	assert.Len(t, skills[1].Description, 203)
	assert.Contains(t, skills[1].Description, "...")
}

func TestListSkills_NonOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	b := NewBridge(BridgeConfig{BaseURL: server.URL, HTTPClient: server.Client()})
	skills, err := b.ListSkills(context.Background())
	assert.Error(t, err)
	assert.Nil(t, skills)
	assert.Contains(t, err.Error(), "503")
}

func TestListSkills_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	b := NewBridge(BridgeConfig{BaseURL: server.URL, HTTPClient: server.Client()})
	skills, err := b.ListSkills(context.Background())
	assert.Error(t, err)
	assert.Nil(t, skills)
	assert.Contains(t, err.Error(), "decode")
}

func TestRegisterAsTools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"name": "enabled_skill", "content": "Desc", "enabled": true},
			{"name": "disabled_skill", "content": "X", "enabled": false},
		})
	}))
	defer server.Close()

	b := NewBridge(BridgeConfig{BaseURL: server.URL, HTTPClient: server.Client()})
	reg := tools.NewRegistry()
	err := b.RegisterAsTools(context.Background(), reg)
	require.NoError(t, err)
	// Only enabled skill registered
	tool, ok := reg.Get("copaw_skill_enabled_skill")
	require.True(t, ok)
	assert.Equal(t, "copaw_skill_enabled_skill", tool.Name())
	assert.Equal(t, "Desc", tool.Description())
	_, ok = reg.Get("copaw_skill_disabled_skill")
	assert.False(t, ok)
}

func TestCopawSkillTool_Execute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"name": "test_skill", "content": "Test", "enabled": true},
		})
	}))
	defer server.Close()

	b := NewBridge(BridgeConfig{BaseURL: server.URL, HTTPClient: server.Client()})
	reg := tools.NewRegistry()
	err := b.RegisterAsTools(context.Background(), reg)
	require.NoError(t, err)
	tool, _ := reg.Get("copaw_skill_test_skill")
	out, err := tool.Execute(context.Background(), json.RawMessage(`{}`))
	require.Error(t, err)
	assert.Nil(t, out)
	assert.Contains(t, err.Error(), "not yet supported")
	assert.Contains(t, err.Error(), "test_skill")
}
