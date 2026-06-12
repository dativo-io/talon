package server

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dativo-io/talon/web"
)

func TestDashboardHTML_ContainsEvidenceIntegritySurface(t *testing.T) {
	html := web.DashboardHTML
	assert.NotEmpty(t, html)
	assert.True(t, strings.Contains(html, "evidence-verify-visible"))
	assert.True(t, strings.Contains(html, "evidence-integrity-state"))
	assert.True(t, strings.Contains(html, "evidence-signature-grid"))
	assert.True(t, strings.Contains(html, "evidence-spend-grid"))
	assert.True(t, strings.Contains(html, "Evidence-grade, not just logs"))
}

func TestDashboardHTML_ContainsComplianceMode(t *testing.T) {
	html := web.DashboardHTML
	assert.NotEmpty(t, html)
	// Compliance tab and panel surfaces.
	assert.True(t, strings.Contains(html, `data-tab="compliance"`))
	assert.True(t, strings.Contains(html, "panel-compliance"))
	assert.True(t, strings.Contains(html, "compliance-framework-cards"))
	assert.True(t, strings.Contains(html, "compliance-controls-tbody"))
	assert.True(t, strings.Contains(html, "compliance-warnings"))
	assert.True(t, strings.Contains(html, "compliance-evidence-tbody"))
	// One-click export hooks against the compliance HTTP API.
	assert.True(t, strings.Contains(html, "/v1/compliance/coverage"))
	assert.True(t, strings.Contains(html, "/v1/compliance/ropa"))
	assert.True(t, strings.Contains(html, "/v1/compliance/annex-iv"))
	assert.True(t, strings.Contains(html, "/v1/compliance/report"))
	// Claims discipline: supporting evidence, never a determination.
	assert.True(t, strings.Contains(html, "Not a certification or compliance determination"))
}

func TestDashboardHTML_ContainsUnifiedFinOpsSurface(t *testing.T) {
	html := web.DashboardHTML
	assert.NotEmpty(t, html)
	// Budget utilization and cache stats mapped from the /api/v1/metrics snapshot.
	assert.True(t, strings.Contains(html, "finops-budget-daily"))
	assert.True(t, strings.Contains(html, "finops-budget-monthly"))
	assert.True(t, strings.Contains(html, "finops-cache-hits"))
	assert.True(t, strings.Contains(html, "finops-cache-saved"))
	// Caller / model / provider spend breakdowns.
	assert.True(t, strings.Contains(html, "finops-callers-tbody"))
	assert.True(t, strings.Contains(html, "finops-models-tbody"))
	assert.True(t, strings.Contains(html, "finops-providers-tbody"))
	// Store-wide denial breakdown wired to the dedicated endpoint.
	assert.True(t, strings.Contains(html, "denials-store-summary"))
	assert.True(t, strings.Contains(html, "/v1/dashboard/denials-by-reason"))
	// Gateway dashboard stays available as a deep link.
	assert.True(t, strings.Contains(html, "/gateway/dashboard"))
}

func TestGatewayDashboardHTML_ContainsEvidenceReviewLink(t *testing.T) {
	html := web.GatewayDashboardHTML
	assert.NotEmpty(t, html)
	assert.True(t, strings.Contains(html, "#evidence-gateway"))
	assert.True(t, strings.Contains(html, "Open approvals and evidence review"))
}
