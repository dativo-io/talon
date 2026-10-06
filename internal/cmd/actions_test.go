package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/secrets"
)

// talon actions (#427): list/show/validate read the ONE shared catalog
// projection, discover trusted sources through the same discoverer serve
// uses, label the result as a CLI candidate, and never print a secret.

type cliUpstream struct {
	srv   *httptest.Server
	calls atomic.Int64
	auth  atomic.Value
}

func newCLIUpstream(t *testing.T) *cliUpstream {
	t.Helper()
	u := &cliUpstream{}
	u.auth.Store("")
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.calls.Add(1)
		u.auth.Store(r.Header.Get("Authorization"))
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		var result string
		switch req.Method {
		case wire.MethodDiscover:
			result = `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"ttlMs":1,"cacheScope":"public","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"refunds-upstream","version":"3.1"}}}`
		case wire.MethodToolsList:
			result = `{"resultType":"complete","tools":[{"name":"refund.create","description":"Create a refund","inputSchema":{"type":"object","properties":{"ticket_id":{"type":"string"},"amount":{"type":"number"},"region":{"type":"string","x-mcp-header":"Region"}},"required":["ticket_id","amount"]}}],"ttlMs":30000,"cacheScope":"public"}`
		default:
			t.Errorf("unexpected upstream method %q (discovery never calls tools)", req.Method)
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":` + result + `}`))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func writeCatalogAgent(t *testing.T, dir, upstreamURL, auth string) string {
	t.Helper()
	y := `agent:
  name: support-bot
  version: "1.0.0"
capabilities:
  forbidden_tools: [delete_customer]
actions:
  sources:
    refunds:
      type: mcp
      url: ` + upstreamURL + `
` + auth + `  definitions:
    create_refund_request:
      source: refunds
      upstream_name: refund.create
      review:
        fields: [ticket_id, amount]
        non_material: [region]
    notify_customer:
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id]
        properties:
          ticket_id: {type: string}
      destination: {type: http, url: "https://notify.internal/v1", success: {status_codes: [200]}}
policies:
  cost_limits:
    daily: 10
  approvals:
    rules:
      refund-request:
        actions: [create_refund_request]
        approver_groups: [support-leads]
`
	p := filepath.Join(dir, "agent.talon.yaml")
	require.NoError(t, os.WriteFile(p, []byte(y), 0o600))
	return p
}

func runActions(t *testing.T, args ...string) (string, error) {
	t.Helper()
	actionsAgent, actionsPolicyPath, actionsJSON, actionsValidateFor, actionsValidateIn = "default", "", false, "", ""
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(append([]string{"actions"}, args...))
	rootCmd.SetContext(context.Background())
	err := rootCmd.Execute()
	return buf.String(), err
}

func TestActionsCLI_ListShowValidate(t *testing.T) {
	up := newCLIUpstream(t)
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	agentPath := writeCatalogAgent(t, dir, up.srv.URL, "")

	out, err := runActions(t, "list", "--policy", agentPath, "--json")
	require.NoError(t, err, out)
	var listed struct {
		Candidate string             `json:"candidate"`
		Catalog   action.CatalogView `json:"catalog"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &listed))
	assert.Contains(t, listed.Candidate, "Candidate catalog")
	assert.Contains(t, listed.Candidate, "ACTIVE runtime generation, which may differ")
	require.Len(t, listed.Catalog.Actions, 2)
	assert.Equal(t, "create_refund_request", listed.Catalog.Actions[0].Name)
	assert.Equal(t, "refund.create", listed.Catalog.Actions[0].UpstreamName)
	assert.Equal(t, "mcp", listed.Catalog.Actions[0].Source.Type)
	assert.Equal(t, "REQUIRE_APPROVAL", listed.Catalog.Actions[0].Verdict)
	assert.Equal(t, "refund-request", listed.Catalog.Actions[0].ApprovalRules[0].ID)
	assert.Equal(t, []action.MirroredParam{{Header: "Region", Path: []string{"region"}, Type: "string"}}, listed.Catalog.Actions[0].MirroredParams)
	assert.Equal(t, "notify_customer", listed.Catalog.Actions[1].Name)
	assert.Equal(t, "declared", listed.Catalog.Actions[1].Source.Type)
	assert.Equal(t, "ALLOW", listed.Catalog.Actions[1].Verdict)
	require.Len(t, listed.Catalog.Sources, 1)
	assert.Equal(t, "refunds-upstream", listed.Catalog.Sources[0].ServerInfo.Name)
	assert.EqualValues(t, 2, up.calls.Load(), "server/discover + one tools/list page")

	// Human output names the same facts.
	out, err = runActions(t, "list", "--policy", agentPath)
	require.NoError(t, err, out)
	assert.Contains(t, out, "create_refund_request")
	assert.Contains(t, out, "mcp:refunds")
	assert.Contains(t, out, "refund.create")
	assert.Contains(t, out, "REQUIRE_APPROVAL")

	out, err = runActions(t, "show", "create_refund_request", "--policy", agentPath)
	require.NoError(t, err, out)
	for _, want := range []string{"Upstream action:    refund.create", "Review fields:      amount, ticket_id", "Non-material:       region", "Destination:        mcp  " + up.srv.URL, "Mcp-Param-Region <- region (string)", "Approval rule:      refund-request (groups: support-leads)", "talon/whole-payload/v1", "talon_forwarded"} {
		assert.Contains(t, out, want)
	}
	_, err = runActions(t, "show", "refund.create", "--policy", agentPath)
	require.Error(t, err, "only the canonical name is an identity")
	assert.Contains(t, err.Error(), "not in agent")

	// validate: a valid document yields the canonical digest and the exact
	// reviewer projection; an undeclared field is rejected (exit non-zero).
	input := filepath.Join(dir, "in.json")
	require.NoError(t, os.WriteFile(input, []byte(`{"ticket_id":"T-1","amount":50.00,"region":"eu"}`), 0o600))
	out, err = runActions(t, "validate", "--policy", agentPath, "--action", "create_refund_request", "--input", input, "--json")
	require.NoError(t, err, out)
	var res actionsValidateResult
	require.NoError(t, json.Unmarshal([]byte(out), &res))
	assert.True(t, res.Valid)
	assert.Equal(t, action.Digest([]byte(`{"amount":50.00,"region":"eu","ticket_id":"T-1"}`)), res.ArgumentsDigest, "canonical digest, source-literal number")
	assert.Equal(t, `50.00`, string(res.Review["amount"]))
	_, hasRegion := res.Review["region"]
	assert.False(t, hasRegion, "non_material fields are omitted from the reviewer projection")
	assert.Equal(t, "REQUIRE_APPROVAL", res.Verdict)
	assert.Equal(t, "refund-request", res.MatchedRuleID)
	assert.Equal(t, listed.Catalog.Actions[0].DefinitionDigest, res.DefinitionDigest, "validate and list share one projection")

	require.NoError(t, os.WriteFile(input, []byte(`{"ticket_id":"T-1","amount":50,"approver_group":"anyone"}`), 0o600))
	out, err = runActions(t, "validate", "--policy", agentPath, "--action", "create_refund_request", "--input", input)
	require.Error(t, err)
	assert.Contains(t, out, "INVALID")
}

func TestActionsCLI_VaultAuthNeverPrinted(t *testing.T) {
	const secret = "upstream-token-DO-NOT-PRINT"
	up := newCLIUpstream(t)
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SECRETS_KEY", "0123456789abcdef0123456789abcdef")
	store, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	require.NoError(t, store.Set(context.Background(), "refunds-mcp-key", []byte(secret), secrets.ACL{}))
	require.NoError(t, store.Close())
	agentPath := writeCatalogAgent(t, dir, up.srv.URL, "      auth:\n        secret_name: refunds-mcp-key\n")

	out, err := runActions(t, "list", "--policy", agentPath, "--json")
	require.NoError(t, err, out)
	assert.Equal(t, "Bearer "+secret, up.auth.Load().(string), "the vault credential reached the source")
	assert.NotContains(t, out, secret)
	assert.NotContains(t, out, "refunds-mcp-key", "not even the reference name is part of the projection")
	out, err = runActions(t, "show", "create_refund_request", "--policy", agentPath)
	require.NoError(t, err, out)
	assert.NotContains(t, out, secret)
}

func TestActionsCLI_SourceFailureIsAnError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	agentPath := writeCatalogAgent(t, dir, dead.URL, "")
	out, err := runActions(t, "list", "--policy", agentPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "discovering trusted action sources")
	assert.Contains(t, err.Error(), "actions.sources.refunds")
	assert.False(t, strings.Contains(out, "Catalog digest"), "no partial catalog is printed")
}
