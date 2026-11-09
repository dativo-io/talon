package console

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

// configService is the fixture service with every configuration source set,
// including a proxy file, and with secrets planted wherever a config file
// could carry one.
func configService(t *testing.T) (*Service, *fixture) {
	t.Helper()
	f := seed(t)
	gw := `gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      base_url: "https://user:SUPERSECRET-BASEURL@api.openai.com/v1?api_key=SUPERSECRET-QUERY"
      secret_name: openai-api-key
      allowed_models: ["gpt-4o-mini"]
      fallback:
        - provider: azure-openai
          model: gpt-4o-mini
    azure-openai:
      enabled: true
      api_family: openai
      base_url: "https://example.openai.azure.com"
      secret_name: azure-openai-key
  organization_policy:
    defaults:
      pii_action: redact
      daily_cost: 100
      retry:
        max_attempts: 3
    constraints:
      forbidden_tools: ["admin_*"]
      max_monthly_cost: 500
    log_prompts: true
    cost_webhook_url: "https://hooks.example/T0K3N-SUPERSECRET-WEBHOOK"
`
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, "talon.config.yaml"), []byte(gw), 0o600))
	px := `agent:
  name: hr-mcp-proxy
  type: mcp_proxy
proxy:
  upstream:
    vendor: hr-backend
    url: "http://svc:SUPERSECRET-PROXYURL@hr-upstream:9000/mcp?token=SUPERSECRET-PROXYQUERY"
    auth:
      secret_name: hr-upstream-token
  allowed_tools:
    - name: hr_aggregate_sql
  forbidden_tools: ["hr_employee_export"]
`
	pxPath := filepath.Join(f.dir, "proxy.talon.yaml")
	require.NoError(t, os.WriteFile(pxPath, []byte(px), 0o600))
	svc := f.service(t)
	svc.cfg.ConfigSources = ConfigSources{AgentsDir: filepath.Join(f.dir, "agents"), GatewayConfig: filepath.Join(f.dir, "talon.config.yaml"), ProxyConfig: pxPath}
	return svc, f
}

func TestConfiguration_SemanticSummaryFromTheFiles(t *testing.T) {
	svc, _ := configService(t)
	c := svc.Configuration(context.Background(), "")

	org := c.Organization
	require.Equal(t, StateOK, org.Availability.State, org.Availability.Error)
	assert.Equal(t, "redact", org.PIIAction)
	assert.InDelta(t, 100, org.DailyCost, 1e-9)
	assert.InDelta(t, 500, org.MaxMonthlyCost, 1e-9)
	assert.Equal(t, []string{"admin_*"}, org.ForbiddenTools)
	require.NotNil(t, org.Retry)
	assert.Equal(t, 3, org.Retry.MaxAttempts)
	assert.True(t, org.LogPrompts)
	assert.True(t, org.CostWebhook, "the webhook is reported as configured, never shown")
	require.Len(t, org.Providers, 2)
	assert.Equal(t, "azure-openai", org.Providers[0].Name, "providers sorted by name")
	p := org.Providers[1]
	assert.Equal(t, "https://api.openai.com", p.Endpoint, "scheme and host only")
	assert.Equal(t, "openai-api-key", p.SecretName, "a vault reference name is shown")
	assert.Equal(t, []string{"azure-openai/gpt-4o-mini"}, p.Fallback)

	require.Equal(t, StateOK, c.UseCases.Availability.State)
	names := []string{}
	for _, u := range c.UseCases.Items {
		names = append(names, u.Name)
	}
	assert.Equal(t, []string{"hr-analytics-assistant", "scratch"}, names, "sorted, one entry per agent file")
	assert.InDelta(t, 10, c.UseCases.Items[0].CostDaily, 1e-9)
	assert.NotEmpty(t, c.UseCases.Items[0].SourcePath)

	px := c.MCPProxy
	require.Equal(t, StateOK, px.Availability.State, px.Availability.Error)
	assert.Equal(t, "hr-backend", px.Vendor)
	assert.Equal(t, "http://hr-upstream:9000", px.Endpoint)
	assert.Equal(t, []string{"hr_aggregate_sql"}, px.AllowedTools)
	assert.Equal(t, []string{"hr_employee_export"}, px.ForbiddenTools)
	assert.Equal(t, "hr-upstream-token", px.AuthSecretName)

	assert.Equal(t, StateUnknown, c.EffectivePolicy.State, "provenance is #305's: never merged here")
	assert.Equal(t, StateUnknown, c.ActiveGeneration.State, "file contents are not proof of the running generation (#538)")

	scoped := svc.Configuration(context.Background(), "acme")
	assert.Equal(t, StateEmpty, scoped.UseCases.Availability.State, "no agent file declares tenant acme")
}

// TestConfiguration_NeverLeaksSecretValues: credentials planted in URLs and
// webhook settings must not appear anywhere in the serialized DTO.
func TestConfiguration_NeverLeaksSecretValues(t *testing.T) {
	svc, _ := configService(t)
	raw, err := json.Marshal(svc.Configuration(context.Background(), ""))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "SUPERSECRET")
	assert.NotContains(t, string(raw), "api_key=")
	assert.NotContains(t, string(raw), "hooks.example")
}

func TestConfiguration_MissingAndInvalidSources(t *testing.T) {
	f := seed(t)
	svc := f.service(t)
	c := svc.Configuration(context.Background(), "")
	assert.Equal(t, StateUnknown, c.Organization.Availability.State, "no sources configured: unknown, not empty")
	assert.Equal(t, StateUnknown, c.UseCases.Availability.State)
	assert.Equal(t, StateUnknown, c.MCPProxy.Availability.State)

	bad := filepath.Join(f.dir, "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("gateway: [not a map"), 0o600))
	svc.cfg.ConfigSources = ConfigSources{GatewayConfig: bad, ProxyConfig: filepath.Join(f.dir, "missing-proxy.yaml"), AgentsDir: filepath.Join(f.dir, "agents")}
	c = svc.Configuration(context.Background(), "")
	assert.Equal(t, StateUnavailable, c.Organization.Availability.State)
	assert.NotEmpty(t, c.Organization.Availability.Error)
	assert.Equal(t, StateUnavailable, c.MCPProxy.Availability.State)

	leaky := filepath.Join(f.dir, "leaky.yaml")
	require.NoError(t, os.WriteFile(leaky, []byte("gateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      base_url: \"https://u:SUPERSECRET-ERR@api.openai.com\"\n      secret_name: k\n      fallback:\n        - provider: nowhere\n"), 0o600))
	svc.cfg.ConfigSources.GatewayConfig = leaky
	c = svc.Configuration(context.Background(), "")
	assert.Equal(t, StateUnavailable, c.Organization.Availability.State)
	assert.NotContains(t, c.Organization.Availability.Error, "SUPERSECRET", "a load error never echoes credentials")

	svc.cfg.ConfigSources.GatewayConfig = filepath.Join(f.dir, "absent.yaml")
	c = svc.Configuration(context.Background(), "")
	assert.Equal(t, StateEmpty, c.Organization.Availability.State, "no gateway file: agent-only installation")
}

func TestSearch_BoundedExactLookups(t *testing.T) {
	f := seed(t)
	svc := f.service(t)
	ctx := context.Background()

	r, err := svc.Search(ctx, "", "hr-")
	require.NoError(t, err)
	require.Len(t, r.UseCases, 1)
	assert.Equal(t, "hr-analytics-assistant", r.UseCases[0].Name)
	assert.Equal(t, []string{"explanation_code"}, r.Unsupported)

	r, err = svc.Search(ctx, "", "e_export")
	require.NoError(t, err)
	require.Len(t, r.Evidence, 1)
	assert.Equal(t, "e_export", r.Evidence[0].ID)
	require.NotNil(t, r.Evidence[0].Outcome)
	assert.Equal(t, "not_dispatched", r.Evidence[0].Outcome.Dispatch)

	r, err = svc.Search(ctx, "", "corr_e_llm")
	require.NoError(t, err)
	require.Len(t, r.Evidence, 1, "exact correlation id")
	assert.Equal(t, "e_llm", r.Evidence[0].ID)

	r, err = svc.Search(ctx, "", "hr-demo-s1")
	require.NoError(t, err)
	require.Len(t, r.Sessions, 1)
	assert.Equal(t, 3, r.Sessions[0].RecordCount)
	assert.False(t, r.Sessions[0].Managed, "evidence-observed only: no session-store row")

	r, err = svc.Search(ctx, "", "e_acme")
	require.NoError(t, err)
	assert.Empty(t, r.Evidence, "another tenant's record is not found from the default scope")
	assert.Equal(t, StateEmpty, r.Availability.State)
	r, err = svc.Search(ctx, "acme", "e_acme")
	require.NoError(t, err)
	assert.Len(t, r.Evidence, 1)

	_, err = svc.Search(ctx, "", "  ")
	assert.ErrorIs(t, err, ErrInvalidArgument)
	_, err = svc.Search(ctx, "", string(make([]byte, MaxSearchQuery+1)))
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

// TestSearch_TenantFilterBeforeLimit (#553 review): 11 records of tenant
// "default" share a correlation id with one record of tenant "acme"; the acme
// search must find acme's record even though the default tenant's records
// fill the first page of the id.
func TestSearch_TenantFilterBeforeLimit(t *testing.T) {
	f := seed(t)
	ctx := context.Background()
	for i := 0; i < 11; i++ {
		require.NoError(t, f.writer.Store(ctx, &evidence.Evidence{
			ID: fmt.Sprintf("shared-%02d", i), CorrelationID: "corr-shared", TenantID: "default", AgentID: "scratch",
			Timestamp: f.now.Add(-time.Duration(40-i) * time.Minute), InvocationType: "gateway",
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		}))
	}
	require.NoError(t, f.writer.Store(ctx, &evidence.Evidence{
		ID: "shared-acme", CorrelationID: "corr-shared", TenantID: "acme", AgentID: "hr-analytics-assistant",
		Timestamp: f.now.Add(-time.Minute), InvocationType: "gateway",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
	}))
	svc := f.service(t)
	r, err := svc.Search(ctx, "acme", "corr-shared")
	require.NoError(t, err)
	require.Len(t, r.Evidence, 1)
	assert.Equal(t, "shared-acme", r.Evidence[0].ID)
	r, err = svc.Search(ctx, "default", "corr-shared")
	require.NoError(t, err)
	assert.Len(t, r.Evidence, maxSearchResults, "bounded")
	for _, e := range r.Evidence {
		assert.Equal(t, "default", e.TenantID)
	}
}
