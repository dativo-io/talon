package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPolicy(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		strict  bool
		wantErr bool
	}{
		{
			name: "valid minimal policy",
			yaml: `
agent:
  name: test-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 100.0
`,
			strict:  false,
			wantErr: false,
		},
		{
			name: "valid full v2.0 policy",
			yaml: `
agent:
  name: sales-analyst
  description: Analyzes sales data
  version: 2.0.0
  model_tier: 1
capabilities:
  allowed_tools:
    - sql_query
    - file_read
  forbidden_patterns:
    - ".env"
triggers:
  schedule:
    - cron: "0 9 * * MON-FRI"
      prompt: "Generate daily sales summary"
      description: "Morning digest"
  webhooks:
    - name: sales-update
      source: generic
      prompt_template: "Analyze {{.payload}}"
      require_approval: false
secrets:
  allowed:
    - name: salesforce-api-key
      purpose: "CRM access"
  forbidden:
    - name: "admin-*"
memory:
  enabled: true
  max_entries: 50
  max_entry_size_kb: 5
  retention_days: 60
  review_mode: auto
  allowed_categories:
    - factual_corrections
    - domain_knowledge
  forbidden_categories:
    - policy_modifications
  audit: true
context:
  shared_mounts:
    - name: company-knowledge
      description: "Company facts"
      classification: tier_0
attachment_handling:
  mode: strict
  require_user_approval:
    - pdf
  auto_allow:
    - txt
  scanning:
    detect_instructions: true
    action_on_detection: block_and_flag
  sandboxing:
    wrap_content: true
policies:
  cost_limits:
    per_request: 5.0
    daily: 200.0
    monthly: 3000.0
  rate_limits:
    requests_per_minute: 60
    concurrent_executions: 1
  data_classification:
    input_scan: true
    output_scan: true
    redact_pii: true
  model_routing:
    tier_0:
      primary: gpt-4o-mini
      location: any
    tier_1:
      primary: gpt-4o
      fallback: gpt-4o-mini
      location: eu-west-1
      bedrock_only: true
  time_restrictions:
    enabled: false
    allowed_hours: "08:00-18:00"
    timezone: "Europe/Berlin"
    weekends: false
audit:
  log_level: detailed
  retention_days: 2555
  include_prompts: false
  include_responses: false
compliance:
  frameworks:
    - gdpr
    - eu-ai-act
  data_residency: eu
  ai_act_risk_level: limited
  human_oversight: on-demand
metadata:
  department: sales
  owner: test@company.eu
  tags:
    - sales
    - analytics
`,
			strict:  false,
			wantErr: false,
		},
		{
			name: "missing required agent version",
			yaml: `
agent:
  name: test-agent
policies:
  cost_limits:
    daily: 100.0
`,
			strict:  false,
			wantErr: true,
		},
		{
			name: "invalid version format",
			yaml: `
agent:
  name: test-agent
  version: v1.0
policies:
  cost_limits:
    daily: 100.0
`,
			strict:  false,
			wantErr: true,
		},
		{
			name: "invalid agent name with spaces",
			yaml: `
agent:
  name: "test agent"
  version: 1.0.0
policies:
  cost_limits:
    daily: 100.0
`,
			strict:  false,
			wantErr: true,
		},
		{
			name: "strict mode with empty cost limits",
			yaml: `
agent:
  name: test-agent
  version: 1.0.0
policies:
  cost_limits: {}
`,
			strict:  true,
			wantErr: true,
		},
		{
			name: "strict mode with valid cost limits",
			yaml: `
agent:
  name: test-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 100.0
    monthly: 1000.0
`,
			strict:  true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			policyPath := filepath.Join(tmpDir, "policy.yaml")
			err := os.WriteFile(policyPath, []byte(tt.yaml), 0644)
			require.NoError(t, err)

			ctx := context.Background()
			pol, err := LoadPolicy(ctx, policyPath, tt.strict)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, pol)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, pol)
				assert.NotEmpty(t, pol.Hash)
				assert.NotEmpty(t, pol.VersionTag)
			}
		})
	}
}

func TestPolicyVersioning(t *testing.T) {
	yamlContent := `
agent:
  name: test-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 100.0
`

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.yaml")
	err := os.WriteFile(policyPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	ctx := context.Background()
	pol, err := LoadPolicy(ctx, policyPath, false)
	require.NoError(t, err)

	assert.Contains(t, pol.VersionTag, "1.0.0:sha256:")
	assert.Len(t, pol.Hash, 64) // SHA-256 is 64 hex chars
}

func TestLoadPolicy_FileNotFound(t *testing.T) {
	ctx := context.Background()
	pol, err := LoadPolicy(ctx, "/nonexistent/path.yaml", false)
	assert.Error(t, err)
	assert.Nil(t, pol)
	assert.Contains(t, err.Error(), "reading policy file")
}

func TestApplyDefaults(t *testing.T) {
	t.Run("audit defaults applied when nil", func(t *testing.T) {
		pol := &Policy{}
		applyDefaults(pol)
		require.NotNil(t, pol.Audit)
		assert.Equal(t, "detailed", pol.Audit.LogLevel)
		assert.Equal(t, 2555, pol.Audit.RetentionDays)
	})

	t.Run("attachment handling defaults applied when nil", func(t *testing.T) {
		pol := &Policy{}
		applyDefaults(pol)
		require.NotNil(t, pol.AttachmentHandling)
		assert.Equal(t, "permissive", pol.AttachmentHandling.Mode)
		require.NotNil(t, pol.AttachmentHandling.Sandboxing)
		assert.True(t, pol.AttachmentHandling.Sandboxing.WrapContent)
	})

	t.Run("memory defaults applied when enabled", func(t *testing.T) {
		pol := &Policy{
			Memory: &MemoryConfig{Enabled: true},
		}
		applyDefaults(pol)
		assert.Equal(t, 100, pol.Memory.MaxEntries)
		assert.Equal(t, 10, pol.Memory.MaxEntrySizeKB)
		assert.Equal(t, 90, pol.Memory.RetentionDays)
		assert.Equal(t, "auto", pol.Memory.ReviewMode)
	})

	t.Run("memory defaults not applied when disabled", func(t *testing.T) {
		pol := &Policy{
			Memory: &MemoryConfig{Enabled: false},
		}
		applyDefaults(pol)
		assert.Equal(t, 0, pol.Memory.MaxEntries)
	})

	t.Run("model tier defaults to 1 with capabilities", func(t *testing.T) {
		pol := &Policy{
			Capabilities: &CapabilitiesConfig{
				AllowedTools: []string{"sql_query"},
			},
		}
		applyDefaults(pol)
		assert.Equal(t, 1, pol.Agent.ModelTier)
	})
}

func TestComputeHash(t *testing.T) {
	pol := &Policy{
		Agent: AgentConfig{Version: "2.0.0"},
	}
	content := []byte("test content")
	pol.ComputeHash(content)

	assert.Len(t, pol.Hash, 64)
	assert.Contains(t, pol.VersionTag, "2.0.0:sha256:")
	assert.Len(t, pol.VersionTag, len("2.0.0:sha256:")+8)

	// Same content should produce same hash
	pol2 := &Policy{
		Agent: AgentConfig{Version: "2.0.0"},
	}
	pol2.ComputeHash(content)
	assert.Equal(t, pol.Hash, pol2.Hash)
}
