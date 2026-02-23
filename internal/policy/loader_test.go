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
			name: "resource_limits with zero max_iterations and max_tool_calls_per_run passes schema",
			yaml: `
agent:
  name: test-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 100.0
  resource_limits:
    max_iterations: 0
    max_tool_calls_per_run: 0
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
			name: "strict mode requires compliance section",
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
			wantErr: true,
		},
		{
			name: "strict mode requires audit section",
			yaml: `
agent:
  name: test-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 100.0
    monthly: 1000.0
compliance:
  frameworks:
    - gdpr
  data_residency: eu
`,
			strict:  true,
			wantErr: true,
		},
		{
			name: "strict mode passes with all required sections",
			yaml: `
agent:
  name: test-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 100.0
    monthly: 1000.0
compliance:
  frameworks:
    - gdpr
  data_residency: eu
audit:
  log_level: detailed
  retention_days: 2555
`,
			strict:  true,
			wantErr: false,
		},
		{
			name: "strict mode fails with only per_request cost limit",
			yaml: `
agent:
  name: test-agent
  version: 1.0.0
policies:
  cost_limits:
    per_request: 5.0
compliance:
  frameworks:
    - gdpr
  data_residency: eu
audit:
  log_level: detailed
`,
			strict:  true,
			wantErr: true,
		},
		{
			name: "invalid memory mode fails schema validation",
			yaml: `
agent:
  name: test-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 100.0
memory:
  enabled: true
  mode: shadown
`,
			strict:  false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			policyPath := filepath.Join(tmpDir, "policy.yaml")
			err := os.WriteFile(policyPath, []byte(tt.yaml), 0o644)
			require.NoError(t, err)

			ctx := context.Background()
			pol, err := LoadPolicy(ctx, policyPath, tt.strict, tmpDir)

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
	err := os.WriteFile(policyPath, []byte(yamlContent), 0o644)
	require.NoError(t, err)

	ctx := context.Background()
	pol, err := LoadPolicy(ctx, policyPath, false, tmpDir)
	require.NoError(t, err)

	assert.Contains(t, pol.VersionTag, "1.0.0:sha256:")
	assert.Len(t, pol.Hash, 64) // SHA-256 is 64 hex chars
}

func TestLoadPolicy_BlockOnPII(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "agent.talon.yaml")
	yamlContent := `
agent:
  name: block-pii-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 100.0
  data_classification:
    input_scan: true
    block_on_pii: true
  model_routing:
    tier_0:
      primary: gpt-4
`
	require.NoError(t, os.WriteFile(policyPath, []byte(yamlContent), 0o644))

	pol, err := LoadPolicy(ctx, policyPath, false, tmpDir)
	require.NoError(t, err)
	require.NotNil(t, pol.Policies)
	require.NotNil(t, pol.Policies.DataClassification)
	assert.True(t, pol.Policies.DataClassification.BlockOnPII)
	assert.True(t, pol.Policies.DataClassification.InputScan)
}

func TestLoadPolicy_FileNotFound(t *testing.T) {
	ctx := context.Background()
	// Use baseDir "/" so path is considered under base; error is from missing file.
	pol, err := LoadPolicy(ctx, "/nonexistent/path.yaml", false, "/")
	assert.Error(t, err)
	assert.Nil(t, pol)
	assert.Contains(t, err.Error(), "reading policy file")
}

func TestLoadPolicy_PathOutsideBase(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte("agent:\n  name: x\n  version: 1.0.0\n"), 0o644))

	// Path under a different base (e.g. path traversal) must be rejected.
	otherBase := t.TempDir()
	pol, err := LoadPolicy(ctx, policyPath, false, otherBase)
	assert.Error(t, err)
	assert.Nil(t, pol)
	assert.Contains(t, err.Error(), "outside base directory")
}

func TestResolvePathUnderBase(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "sub", "policy.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(policyPath), 0o755))

	// Relative path under base resolves correctly.
	resolved, err := ResolvePathUnderBase(dir, "sub/policy.yaml")
	require.NoError(t, err)
	assert.Equal(t, policyPath, resolved)

	// Absolute path under base is allowed.
	resolved, err = ResolvePathUnderBase(dir, policyPath)
	require.NoError(t, err)
	assert.Equal(t, policyPath, resolved)

	// Path outside base is rejected.
	_, err = ResolvePathUnderBase(dir, filepath.Join(t.TempDir(), "other.yaml"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outside base directory")

	// Traversal attempt is rejected.
	_, err = ResolvePathUnderBase(dir, "sub/../../../etc/passwd")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outside base directory")
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

func TestValidateRouting(t *testing.T) {
	t.Run("nil routing returns no warnings", func(t *testing.T) {
		warnings, err := ValidateRouting(nil)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("bedrock model with bedrock_only produces no warning", func(t *testing.T) {
		routing := &ModelRoutingConfig{
			Tier2: &TierConfig{
				Primary:     "anthropic.claude-3-sonnet-20240229-v1:0",
				BedrockOnly: true,
			},
		}
		warnings, err := ValidateRouting(routing)
		assert.NoError(t, err)
		assert.Empty(t, warnings, "bedrock model name should not trigger warning")
	})

	t.Run("amazon model with bedrock_only produces no warning", func(t *testing.T) {
		routing := &ModelRoutingConfig{
			Tier2: &TierConfig{
				Primary:     "amazon.titan-text-premier-v1:0",
				BedrockOnly: true,
			},
		}
		warnings, err := ValidateRouting(routing)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("all bedrock vendor prefixes produce no warning", func(t *testing.T) {
		bedrockModels := []struct {
			name  string
			model string
		}{
			{"anthropic", "anthropic.claude-3-sonnet-20240229-v1:0"},
			{"amazon", "amazon.titan-text-premier-v1:0"},
			{"meta", "meta.llama3-1-70b-instruct-v1:0"},
			{"cohere", "cohere.command-r-plus-v1:0"},
			{"ai21", "ai21.jamba-1-5-large-v1:0"},
			{"stability", "stability.stable-diffusion-xl-v1"},
			{"mistral", "mistral.mistral-large-2402-v1:0"},
		}
		for _, tt := range bedrockModels {
			t.Run(tt.name, func(t *testing.T) {
				routing := &ModelRoutingConfig{
					Tier2: &TierConfig{
						Primary:     tt.model,
						BedrockOnly: true,
					},
				}
				warnings, err := ValidateRouting(routing)
				assert.NoError(t, err)
				assert.Empty(t, warnings, "bedrock model %q should not trigger warning", tt.model)
			})
		}
	})

	t.Run("non-bedrock model with bedrock_only produces warning", func(t *testing.T) {
		routing := &ModelRoutingConfig{
			Tier2: &TierConfig{
				Primary:     "claude-sonnet-4-20250514",
				BedrockOnly: true,
			},
		}
		warnings, err := ValidateRouting(routing)
		assert.NoError(t, err)
		require.Len(t, warnings, 1)
		assert.Equal(t, "tier_2", warnings[0].Tier)
		assert.Contains(t, warnings[0].Message, "bedrock_only is true")
		assert.Contains(t, warnings[0].Message, "claude-sonnet-4-20250514")
	})

	t.Run("non-bedrock fallback with bedrock_only produces warning", func(t *testing.T) {
		routing := &ModelRoutingConfig{
			Tier1: &TierConfig{
				Primary:     "anthropic.claude-3-sonnet-20240229-v1:0",
				Fallback:    "gpt-4o",
				BedrockOnly: true,
			},
		}
		warnings, err := ValidateRouting(routing)
		assert.NoError(t, err)
		require.Len(t, warnings, 1)
		assert.Equal(t, "tier_1", warnings[0].Tier)
		assert.Contains(t, warnings[0].Message, "gpt-4o")
	})

	t.Run("both primary and fallback non-bedrock produce two warnings", func(t *testing.T) {
		routing := &ModelRoutingConfig{
			Tier2: &TierConfig{
				Primary:     "claude-sonnet-4-20250514",
				Fallback:    "gpt-4o",
				BedrockOnly: true,
			},
		}
		warnings, err := ValidateRouting(routing)
		assert.NoError(t, err)
		assert.Len(t, warnings, 2, "should warn about both primary and fallback")
	})

	t.Run("bedrock_only false produces no warnings regardless of model", func(t *testing.T) {
		routing := &ModelRoutingConfig{
			Tier0: &TierConfig{
				Primary:     "gpt-4o",
				BedrockOnly: false,
			},
			Tier1: &TierConfig{
				Primary:     "claude-sonnet-4-20250514",
				BedrockOnly: false,
			},
		}
		warnings, err := ValidateRouting(routing)
		assert.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("multiple tiers with warnings", func(t *testing.T) {
		routing := &ModelRoutingConfig{
			Tier1: &TierConfig{
				Primary:     "gpt-4o",
				BedrockOnly: true,
			},
			Tier2: &TierConfig{
				Primary:     "claude-sonnet-4-20250514",
				BedrockOnly: true,
			},
		}
		warnings, err := ValidateRouting(routing)
		assert.NoError(t, err)
		assert.Len(t, warnings, 2, "should warn for each tier")
	})
}

func TestLoadPolicy_RoutingWarnings(t *testing.T) {
	t.Run("policy with non-bedrock model and bedrock_only loads with warning", func(t *testing.T) {
		yamlContent := `
agent:
  name: test-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 100.0
  model_routing:
    tier_2:
      primary: "claude-sonnet-4-20250514"
      bedrock_only: true
`
		tmpDir := t.TempDir()
		policyPath := filepath.Join(tmpDir, "policy.yaml")
		require.NoError(t, os.WriteFile(policyPath, []byte(yamlContent), 0o644))

		ctx := context.Background()
		pol, err := LoadPolicy(ctx, policyPath, false, tmpDir)
		// Policy should still load (warnings are non-fatal)
		require.NoError(t, err)
		require.NotNil(t, pol)
		assert.True(t, pol.Policies.ModelRouting.Tier2.BedrockOnly)
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

// FuzzLoadPolicy runs policy loading on fuzz YAML input to catch panics and edge cases.
func FuzzLoadPolicy(f *testing.F) {
	ctx := context.Background()
	f.Add([]byte("agent:\n  name: x\n"))
	f.Add([]byte("policies:\n  cost_limits:\n    daily: 1\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.yaml")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Skip(err)
		}
		_, _ = LoadPolicy(ctx, path, false, dir)
	})
}
