package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/compliance"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil"
)

// newComplianceTestServer builds a routed server with an evidence store seeded
// with records for two tenants, an admin key, one tenant key, and a static
// declarations loader.
func newComplianceTestServer(t *testing.T) (http.Handler, *evidence.Store) {
	t.Helper()
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	gen := evidence.NewGenerator(store)
	seed := []evidence.GenerateParams{
		{
			CorrelationID:  "corr_compliance_a1",
			TenantID:       "tenant-a",
			AgentID:        "agent-a",
			InvocationType: "manual",
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
			Compliance:     evidence.Compliance{Frameworks: []string{"gdpr", "eu-ai-act"}},
			Cost:           0.5,
		},
		{
			CorrelationID:  "corr_compliance_a2",
			TenantID:       "tenant-a",
			AgentID:        "agent-a",
			InvocationType: "manual",
			PolicyDecision: evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"budget"}},
			Compliance:     evidence.Compliance{Frameworks: []string{"gdpr"}},
		},
		{
			CorrelationID:  "corr_compliance_b1",
			TenantID:       "tenant-b",
			AgentID:        "agent-b",
			InvocationType: "manual",
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
			Compliance:     evidence.Compliance{Frameworks: []string{"gdpr"}},
		},
	}
	for i := range seed {
		_, err := gen.Generate(context.Background(), seed[i])
		require.NoError(t, err)
	}

	srv := NewServer(
		nil, store, nil, engine, pol, "", nil,
		"admin-secret",
		map[string]string{"tenant-secret": "tenant-a"},
		WithComplianceDeclarations(func(context.Context) compliance.Declarations {
			return compliance.Declarations{
				Controller: compliance.ControllerDeclarations{
					Name:    "Example GmbH",
					Contact: "privacy@example.eu",
				},
			}
		}),
	)
	return srv.Routes(), store
}

func doComplianceRequest(t *testing.T, h http.Handler, path string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var adminHeader = map[string]string{"X-Talon-Admin-Key": "admin-secret"}

func TestComplianceEndpoints_AuthMatrix(t *testing.T) {
	srv, _ := newComplianceTestServer(t)
	paths := []string{
		"/v1/compliance/coverage",
		"/v1/compliance/ropa",
		"/v1/compliance/annex-iv",
		"/v1/compliance/report",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			// Missing credentials.
			rec := doComplianceRequest(t, srv, path, nil)
			assert.Equal(t, http.StatusUnauthorized, rec.Code, "missing key must be rejected")

			// Tenant bearer must be rejected: compliance exports are admin-only.
			rec = doComplianceRequest(t, srv, path, map[string]string{"Authorization": "Bearer tenant-secret"})
			assert.Equal(t, http.StatusUnauthorized, rec.Code, "tenant key must be rejected")

			// Admin key is accepted.
			rec = doComplianceRequest(t, srv, path, adminHeader)
			assert.Equal(t, http.StatusOK, rec.Code, "admin key must be accepted")
		})
	}
}

func TestComplianceCoverage_FrameworksAndWarnings(t *testing.T) {
	srv, _ := newComplianceTestServer(t)
	rec := doComplianceRequest(t, srv, "/v1/compliance/coverage", adminHeader)
	require.Equal(t, http.StatusOK, rec.Code)

	var out struct {
		EvidenceCountTotal int `json:"evidence_count_total"`
		Frameworks         []struct {
			Framework     string                      `json:"framework"`
			EvidenceCount int                         `json:"evidence_count"`
			DeniedCount   int                         `json:"denied_count"`
			Controls      []compliance.ControlMapping `json:"controls"`
		} `json:"frameworks"`
		DeclarationWarnings map[string][]string `json:"declaration_warnings"`
		ClaimNote           string              `json:"claim_note"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))

	assert.Equal(t, 3, out.EvidenceCountTotal)
	byFramework := map[string]int{}
	for _, fw := range out.Frameworks {
		byFramework[fw.Framework] = fw.EvidenceCount
		assert.NotEmpty(t, fw.Controls, "framework %s must list its controls", fw.Framework)
	}
	for _, expected := range []string{"gdpr", "eu-ai-act", "nis2", "dora", "iso-27001"} {
		_, ok := byFramework[expected]
		assert.True(t, ok, "coverage must include framework %s", expected)
	}
	assert.Equal(t, 3, byFramework["gdpr"])
	assert.Equal(t, 1, byFramework["eu-ai-act"])

	// Controller is declared but processing declarations are not: RoPA warnings
	// must flag the processing fields, Annex IV the system fields.
	require.Contains(t, out.DeclarationWarnings, "ropa")
	require.Contains(t, out.DeclarationWarnings, "annex_iv")
	assert.NotEmpty(t, out.DeclarationWarnings["ropa"])
	assert.NotEmpty(t, out.DeclarationWarnings["annex_iv"])
	for _, w := range out.DeclarationWarnings["ropa"] {
		assert.NotContains(t, w, "controller.name", "declared controller must not be flagged")
	}

	assert.Contains(t, out.ClaimNote, "not a completed legal filing")
}

func TestComplianceRoPA_HTMLDownload(t *testing.T) {
	srv, _ := newComplianceTestServer(t)
	rec := doComplianceRequest(t, srv, "/v1/compliance/ropa", adminHeader)
	require.Equal(t, http.StatusOK, rec.Code)

	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "talon-ropa.html")
	body := rec.Body.String()
	assert.Contains(t, body, "Record of Processing Activities")
	assert.Contains(t, body, "Example GmbH", "declared controller must render")
	assert.Contains(t, body, "not a completed legal filing", "claims-discipline footer required")
}

func TestComplianceRoPA_JSONTenantScoped(t *testing.T) {
	srv, _ := newComplianceTestServer(t)
	rec := doComplianceRequest(t, srv, "/v1/compliance/ropa?format=json&tenant=tenant-a", adminHeader)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "talon-ropa.json")

	var doc compliance.Document
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&doc))
	assert.Equal(t, "gdpr", doc.Framework)
	assert.Equal(t, "tenant-a", doc.TenantID)
	assert.Equal(t, 2, doc.Linkage.EvidenceCount, "tenant filter must exclude tenant-b records")
	assert.Equal(t, "Example GmbH", findDocTableValue(doc, "Controller"))
}

func TestComplianceAnnexIV_JSON(t *testing.T) {
	srv, _ := newComplianceTestServer(t)
	rec := doComplianceRequest(t, srv, "/v1/compliance/annex-iv?format=json", adminHeader)
	require.Equal(t, http.StatusOK, rec.Code)

	var doc compliance.Document
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&doc))
	assert.Equal(t, "eu-ai-act", doc.Framework)
	assert.Equal(t, 3, doc.Linkage.EvidenceCount)
	assert.NotEmpty(t, doc.Warnings, "missing system declarations must surface as warnings")
}

func TestComplianceReport_FrameworkFilter(t *testing.T) {
	srv, _ := newComplianceTestServer(t)
	rec := doComplianceRequest(t, srv, "/v1/compliance/report?format=json&framework=gdpr", adminHeader)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "talon-compliance-report.json")

	var report compliance.Report
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&report))
	assert.Equal(t, "gdpr", report.Framework)
	assert.Equal(t, 3, report.EvidenceCount)
	assert.Equal(t, 1, report.DeniedCount)
	for _, m := range report.Mappings {
		assert.Equal(t, "gdpr", m.Framework)
	}
}

func TestComplianceExport_InvalidParams(t *testing.T) {
	srv, _ := newComplianceTestServer(t)

	rec := doComplianceRequest(t, srv, "/v1/compliance/ropa?format=pdf", adminHeader)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	rec = doComplianceRequest(t, srv, "/v1/compliance/report?from=12-31-2026", adminHeader)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestComplianceExport_RecordsControlPlaneEvidence(t *testing.T) {
	srv, store := newComplianceTestServer(t)
	rec := doComplianceRequest(t, srv, "/v1/compliance/ropa?tenant=tenant-a", adminHeader)
	require.Equal(t, http.StatusOK, rec.Code)

	list, err := store.List(context.Background(), "tenant-a", "", time.Time{}, time.Time{}, 100)
	require.NoError(t, err)
	var found bool
	for i := range list {
		if list[i].InvocationType == "control_plane" &&
			list[i].PolicyDecision.Action == "compliance_export_ropa" {
			found = true
			break
		}
	}
	assert.True(t, found, "compliance export must generate a signed control-plane evidence record")
}

func TestComplianceEndpoints_NoDeclarationsLoaderStillWorks(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, "admin-secret", map[string]string{})
	rec := doComplianceRequest(t, srv.Routes(), "/v1/compliance/ropa?format=json", adminHeader)
	require.Equal(t, http.StatusOK, rec.Code)

	var doc compliance.Document
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&doc))
	assert.NotEmpty(t, doc.Warnings, "zero declarations must surface as warnings, not errors")
}

// findDocTableValue returns the second cell of the first table row whose first
// cell equals label, searching all document sections.
func findDocTableValue(doc compliance.Document, label string) string {
	for _, sec := range doc.Sections {
		if sec.Table == nil {
			continue
		}
		for _, row := range sec.Table.Rows {
			if len(row) >= 2 && strings.EqualFold(row[0], label) {
				return row[1]
			}
		}
	}
	return ""
}
