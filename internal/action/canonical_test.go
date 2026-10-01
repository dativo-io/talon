package action

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
)

func TestCanonicalize(t *testing.T) {
	cases := map[string]string{
		`{"b":1,"a":{"y":[3,2,1],"x":null}}`:  `{"a":{"x":null,"y":[3,2,1]},"b":1}`,
		"{ \"amount\" : 50.00 , \"n\": 1e2 }": `{"amount":50.00,"n":1e2}`,
		`{"s":"<a>&é"}`:                       `{"s":"<a>&é"}`,
		`[]`:                                  `[]`,
		`{"z":{},"a":[{"k":true}]}`:           `{"a":[{"k":true}],"z":{}}`,
	}
	for in, want := range cases {
		got, err := Canonicalize([]byte(in))
		require.NoError(t, err, in)
		require.Equal(t, want, string(got), in)
	}
	a, _ := Canonicalize([]byte(`{"amount":50}`))
	b, _ := Canonicalize([]byte(`{"amount":50.0}`))
	require.NotEqual(t, Digest(a), Digest(b), "1 and 1.0 are different material arguments")
	c, _ := Canonicalize([]byte(`{"note":null}`))
	d, _ := Canonicalize([]byte(`{}`))
	require.NotEqual(t, Digest(c), Digest(d), "explicit null is not absence")
	for _, bad := range []string{`{"a":1,"a":2}`, `{"a":1} x`, `{`, `"\xff"`, `{"a":` + deep(40) + `}`} {
		_, err := Canonicalize([]byte(bad))
		require.Error(t, err, bad)
	}
}

func deep(n int) string {
	s := "1"
	for i := 0; i < n; i++ {
		s = "[" + s + "]"
	}
	return s
}

func objSchema(props map[string]any, required ...any) map[string]any {
	m := map[string]any{"type": "object", "additionalProperties": false, "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func dest() policy.ActionDestinationConfig {
	return policy.ActionDestinationConfig{Type: "http", URL: "https://api.example/x"}
}

func TestCompileCatalog_FailsClosed(t *testing.T) {
	good := policy.ActionDefinitionConfig{InputSchema: objSchema(map[string]any{"a": map[string]any{"type": "string"}}), Destination: dest()}
	for name, cfg := range map[string]policy.ActionDefinitionConfig{
		"Bad-Name":    good,
		"no_schema":   {Destination: dest()},
		"not_object":  {InputSchema: map[string]any{"type": "string", "additionalProperties": false}, Destination: dest()},
		"open_schema": {InputSchema: map[string]any{"type": "object", "properties": map[string]any{}}, Destination: dest()},
		"plain_http":  {InputSchema: good.InputSchema, Destination: policy.ActionDestinationConfig{Type: "http", URL: "http://api.example/x"}},
		"creds":       {InputSchema: good.InputSchema, Destination: policy.ActionDestinationConfig{Type: "http", URL: "https://u:p@api.example/x"}},
		"bad_type":    {InputSchema: good.InputSchema, Destination: policy.ActionDestinationConfig{Type: "grpc", URL: "https://api.example/x"}},
		"bad_success": {InputSchema: good.InputSchema, Destination: policy.ActionDestinationConfig{Type: "http", URL: "https://api.example/x", Success: &policy.ActionSuccessConfig{StatusCodes: []int{302}}}},
		"has_id":      {InputSchema: map[string]any{"$id": "https://evil.example/s", "type": "object", "additionalProperties": false}, Destination: dest()},
	} {
		_, err := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{name: cfg}})
		require.Error(t, err, name)
	}
	cat, err := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"ok": good, "loop": {InputSchema: good.InputSchema, Destination: policy.ActionDestinationConfig{Type: "http", URL: "http://127.0.0.1:9/x"}}}})
	require.NoError(t, err)
	require.Equal(t, []string{"loop", "ok"}, cat.Names())
	d, _ := cat.Lookup("ok")
	require.Equal(t, "POST", d.Destination.Method)
	require.Equal(t, ExecutionProfileTalonForwarded, d.ExecutionProfile)
	require.Equal(t, []string{"a"}, d.Review.Shown, "absent review shows every field")
	cat2, _ := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"loop": {InputSchema: good.InputSchema, Destination: policy.ActionDestinationConfig{Type: "http", URL: "http://127.0.0.1:9/x"}}, "ok": good}})
	require.Equal(t, cat.Digest, cat2.Digest, "catalog digest is order-independent")
}

// B5: the projection must cover every material field; omission needs an
// explicit non-material classification; paths must exist; every
// classification change moves the definition digest.
func TestCompileReview_Sufficiency(t *testing.T) {
	props := map[string]any{"recipient": map[string]any{"type": "string"}, "amount": map[string]any{"type": "number"}, "currency": map[string]any{"type": "string"}}
	mk := func(r *policy.ActionReviewConfig) (*Definition, error) {
		cat, err := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"pay": {InputSchema: objSchema(props), Review: r, Destination: dest()}}})
		if err != nil {
			return nil, err
		}
		d, _ := cat.Lookup("pay")
		return d, nil
	}
	_, err := mk(&policy.ActionReviewConfig{Fields: []string{"recipient"}})
	require.Error(t, err, "a reviewer could approve a €10,000 transfer without seeing the amount")
	require.Contains(t, err.Error(), "amount")
	_, err = mk(&policy.ActionReviewConfig{Fields: []string{"recipient", "amount", "currency", "memo"}})
	require.Error(t, err, "nonexistent review path")
	_, err = mk(&policy.ActionReviewConfig{Fields: []string{"recipient", "amount", "currency"}, NonMaterial: []string{"currency"}})
	require.Error(t, err, "double classification")
	full, err := mk(&policy.ActionReviewConfig{Fields: []string{"recipient", "amount", "currency"}})
	require.NoError(t, err)
	nonMat, err := mk(&policy.ActionReviewConfig{Fields: []string{"recipient", "amount"}, NonMaterial: []string{"currency"}})
	require.NoError(t, err)
	require.NotEqual(t, full.ProjectionDigest, nonMat.ProjectionDigest)
	require.NotEqual(t, full.DefinitionDigest, nonMat.DefinitionDigest, "projection is part of the definition digest")
	require.Equal(t, full.SchemaDigest, nonMat.SchemaDigest, "only the projection changed")
	proj := nonMat.ReviewProjection([]byte(`{"amount":10000,"currency":"EUR","recipient":"acct-1"}`))
	require.Equal(t, `10000`, string(proj["amount"]), "material fields are shown exactly")
	require.Equal(t, `"acct-1"`, string(proj["recipient"]))
	_, hasCurrency := proj["currency"]
	require.False(t, hasCurrency, "non-material fields are omitted")
	// Success contract is part of the definition digest too.
	withSuccess, err := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"pay": {InputSchema: objSchema(props), Destination: policy.ActionDestinationConfig{Type: "http", URL: "https://api.example/x", Success: &policy.ActionSuccessConfig{StatusCodes: []int{200}}}}}})
	require.NoError(t, err)
	ws, _ := withSuccess.Lookup("pay")
	require.NotEqual(t, full.DefinitionDigest, ws.DefinitionDigest)
}

// A masked material field would let a reviewer approve a value they never
// saw: the catalog fails closed, whatever else is declared.
func TestCompileReview_MaskedIsRejected(t *testing.T) {
	props := map[string]any{"recipient": map[string]any{"type": "string"}, "amount": map[string]any{"type": "number"}, "iban": map[string]any{"type": "string"}}
	for name, r := range map[string]*policy.ActionReviewConfig{
		"masked material amount":  {Fields: []string{"recipient", "iban"}, Masked: []string{"amount"}},
		"masked only":             {Masked: []string{"iban"}},
		"masked alongside others": {Fields: []string{"recipient"}, Masked: []string{"iban"}, NonMaterial: []string{"amount"}},
		"masked unknown field":    {Fields: []string{"recipient", "amount", "iban"}, Masked: []string{"nope"}},
	} {
		_, err := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"pay": {InputSchema: objSchema(props), Review: r, Destination: dest()}}})
		require.Error(t, err, name)
		require.Contains(t, err.Error(), "review.masked", name)
	}
	cat, err := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"pay": {InputSchema: objSchema(props), Review: &policy.ActionReviewConfig{Fields: []string{"recipient", "amount", "iban"}}, Destination: dest()}}})
	require.NoError(t, err)
	d, _ := cat.Lookup("pay")
	proj := d.ReviewProjection([]byte(`{"amount":10000,"iban":"DE89370400440532013000","recipient":"acct-1"}`))
	require.Equal(t, `"DE89370400440532013000"`, string(proj["iban"]), "a shown field is the exact dispatched value")
}

// The public contract is JSON Schema 2020-12: an absent $schema compiles
// as 2020-12, the canonical URI is accepted, every other dialect is
// refused before compilation (DefaultDraft alone would compile a draft-07
// document under draft-07 semantics).
func TestSchemaDialect_PinnedTo2020(t *testing.T) {
	base := func(dialect any) map[string]any {
		m := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"a": map[string]any{"type": "string"}}}
		if dialect != nil {
			m["$schema"] = dialect
		}
		return m
	}
	cases := []struct {
		name    string
		dialect any
		ok      bool
	}{
		{"absent", nil, true},
		{"canonical 2020-12", "https://json-schema.org/draft/2020-12/schema", true},
		{"canonical 2020-12 with empty fragment", "https://json-schema.org/draft/2020-12/schema#", true},
		{"draft-07", "http://json-schema.org/draft-07/schema#", false},
		{"draft-07 https", "https://json-schema.org/draft-07/schema", false},
		{"2019-09", "https://json-schema.org/draft/2019-09/schema", false},
		{"draft-04", "http://json-schema.org/draft-04/schema#", false},
		{"arbitrary dialect", "https://example.com/my-dialect", false},
		{"non-string", 2020, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cat, err := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"x": {InputSchema: base(tc.dialect), Destination: dest()}}})
			if !tc.ok {
				require.Error(t, err)
				require.Contains(t, err.Error(), "$schema")
				return
			}
			require.NoError(t, err)
			d, _ := cat.Lookup("x")
			require.NoError(t, d.ValidateArguments([]byte(`{"a":"x"}`)))
			require.Error(t, d.ValidateArguments([]byte(`{"a":1}`)))
			require.Error(t, d.ValidateArguments([]byte(`{"b":"x"}`)), "closed schema under 2020-12 semantics")
		})
	}
}

// B9: schemas compile offline; no $ref can cause an HTTP request, a
// filesystem read or a remote load.
func TestCompileSchema_NoExternalResolution(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); _, _ = w.Write([]byte(`{"type":"string"}`)) }))
	defer srv.Close()
	secret := filepath.Join(t.TempDir(), "secret.json")
	require.NoError(t, os.WriteFile(secret, []byte(`{"type":"string"}`), 0o600))
	for name, ref := range map[string]string{
		"http":  srv.URL + "/schema.json",
		"https": "https://schemas.example/s.json#/definitions/x",
		"file":  "file://" + secret,
		"other": "urn:example:schema",
	} {
		t.Run(name, func(t *testing.T) {
			schema := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"a": map[string]any{"$ref": ref}}}
			_, err := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"x": {InputSchema: schema, Destination: dest()}}})
			require.Error(t, err)
			require.ErrorIs(t, err, ErrExternalRef)
		})
	}
	require.Zero(t, hits.Load(), "no HTTP request was made during compilation")
	// In-document refs remain supported.
	schema := map[string]any{
		"type": "object", "additionalProperties": false,
		"$defs":      map[string]any{"money": map[string]any{"type": "number", "minimum": 0}},
		"properties": map[string]any{"amount": map[string]any{"$ref": "#/$defs/money"}},
	}
	cat, err := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"x": {InputSchema: schema, Destination: dest()}}})
	require.NoError(t, err)
	d, _ := cat.Lookup("x")
	require.NoError(t, d.ValidateArguments([]byte(`{"amount":5}`)))
	require.Error(t, d.ValidateArguments([]byte(`{"amount":-1}`)))
	require.Zero(t, hits.Load())
}

// Conformance for the supported 2020-12 subset.
func TestSchemaConformanceSubset(t *testing.T) {
	schema := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type":    "object", "additionalProperties": false,
		"required": []any{"ticket_id", "amount", "currency"},
		"properties": map[string]any{
			"ticket_id": map[string]any{"type": "string", "minLength": 2, "maxLength": 10, "pattern": "^T-[0-9]+$"},
			"amount":    map[string]any{"type": "number", "minimum": 0.01, "maximum": 1000},
			"currency":  map[string]any{"type": "string", "enum": []any{"EUR", "USD"}},
			"kind":      map[string]any{"const": "refund"},
			"tags":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 3},
			"customer":  map[string]any{"type": "object", "additionalProperties": false, "required": []any{"id"}, "properties": map[string]any{"id": map[string]any{"type": "string"}}},
		},
	}
	cat, err := CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"x": {InputSchema: schema, Destination: dest()}}})
	require.NoError(t, err)
	d, _ := cat.Lookup("x")
	ok := []string{
		`{"ticket_id":"T-1","amount":5,"currency":"EUR"}`,
		`{"ticket_id":"T-1","amount":5,"currency":"EUR","kind":"refund","tags":["a"],"customer":{"id":"c"}}`,
	}
	bad := map[string]string{
		"missing required":      `{"ticket_id":"T-1","amount":5}`,
		"extra property":        `{"ticket_id":"T-1","amount":5,"currency":"EUR","x":1}`,
		"pattern":               `{"ticket_id":"X-1","amount":5,"currency":"EUR"}`,
		"maxLength":             `{"ticket_id":"T-123456789","amount":5,"currency":"EUR"}`,
		"minimum":               `{"ticket_id":"T-1","amount":0,"currency":"EUR"}`,
		"maximum":               `{"ticket_id":"T-1","amount":1001,"currency":"EUR"}`,
		"enum":                  `{"ticket_id":"T-1","amount":5,"currency":"GBP"}`,
		"const":                 `{"ticket_id":"T-1","amount":5,"currency":"EUR","kind":"refunds"}`,
		"items type":            `{"ticket_id":"T-1","amount":5,"currency":"EUR","tags":[1]}`,
		"maxItems":              `{"ticket_id":"T-1","amount":5,"currency":"EUR","tags":["a","b","c","d"]}`,
		"nested required":       `{"ticket_id":"T-1","amount":5,"currency":"EUR","customer":{}}`,
		"nested additional":     `{"ticket_id":"T-1","amount":5,"currency":"EUR","customer":{"id":"c","x":1}}`,
		"wrong type for number": `{"ticket_id":"T-1","amount":"5","currency":"EUR"}`,
	}
	for _, in := range ok {
		c, err := Canonicalize([]byte(in))
		require.NoError(t, err)
		require.NoError(t, d.ValidateArguments(c), in)
	}
	for name, in := range bad {
		c, err := Canonicalize([]byte(in))
		require.NoError(t, err)
		require.Error(t, d.ValidateArguments(c), name)
	}
	_, err = CompileCatalog(&policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{"x": {InputSchema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"a": map[string]any{"type": "nonsense"}}}, Destination: dest()}}})
	require.Error(t, err, "invalid keyword values fail at compile, never silently pass")
	require.True(t, strings.Contains(err.Error(), "compile"))
}

func TestVerdictPrecedence(t *testing.T) {
	pol := &policy.Policy{
		Capabilities: &policy.CapabilitiesConfig{ForbiddenTools: []string{"publish_release"}},
		Policies: policy.PoliciesConfig{Approvals: &policy.ApprovalsConfig{Rules: map[string]policy.ApprovalRuleConfig{
			"releases": {Actions: []string{"publish_*"}, ApproverGroups: []string{"release-managers"}},
		}}},
	}
	ap, err := CompileApprovalPolicy(pol)
	require.NoError(t, err)
	require.Equal(t, VerdictDeny, ap.Evaluate("publish_release").Outcome, "DENY beats a matching approval rule")
	v := ap.Evaluate("publish_docs")
	require.Equal(t, VerdictRequireApproval, v.Outcome)
	require.Equal(t, "releases", v.RuleID)
	require.Equal(t, []string{"release-managers"}, v.ApproverGroups)
	require.Equal(t, VerdictAllow, ap.Evaluate("notify").Outcome)
	require.Equal(t, DefaultApprovalLifetime, ap.ExpiresAfter)
	ap2, _ := CompileApprovalPolicy(pol)
	require.Equal(t, ap.Digest, ap2.Digest)
	pol.Policies.Approvals.Rules["releases"] = policy.ApprovalRuleConfig{Actions: []string{"publish_*"}, ApproverGroups: []string{"anyone"}}
	ap3, _ := CompileApprovalPolicy(pol)
	require.NotEqual(t, ap.Digest, ap3.Digest, "approver groups are approval-relevant")
	_, err = CompileApprovalPolicy(&policy.Policy{Policies: policy.PoliciesConfig{Approvals: &policy.ApprovalsConfig{ExpiresAfter: "never"}}})
	require.Error(t, err)
	_, err = CompileApprovalPolicy(&policy.Policy{Policies: policy.PoliciesConfig{Approvals: &policy.ApprovalsConfig{Rules: map[string]policy.ApprovalRuleConfig{"r": {Actions: []string{"x"}}}}}})
	require.Error(t, err, "rule without approver groups fails closed")
}
