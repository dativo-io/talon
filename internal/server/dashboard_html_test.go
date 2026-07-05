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

// Orchestration sessions panel (#199, epic #192 PR-H).

func TestGatewayDashboardHTML_SessionsPanel(t *testing.T) {
	html := web.GatewayDashboardHTML
	assert.Contains(t, html, `id="panel-sessions"`, "sessions panel must exist")
	assert.Contains(t, html, `id="sessions-table"`)
	assert.Contains(t, html, "Coding Sessions (orchestration)")
	assert.Contains(t, html, `style="display:none"`, "sessions panel hidden by default")
	assert.Contains(t, html, "renderSessions(d.sessions, d.denials_by_reason)")
	// Naming collision resolved: the metrics feed card no longer claims the
	// word "Session"; the new panel owns it.
	assert.NotContains(t, html, "Session Timeline (Lifecycle)")
	assert.Contains(t, html, "Gateway Activity Feed")
}

// TestGatewayDashboardHTML_SessionFieldsEscaped is the XSS fixture at the
// source level: every client-asserted string the sessions renderer
// interpolates must pass through esc(). session_id/agent_id/client/models are
// hostile input (#199 hygiene requirement).
func TestGatewayDashboardHTML_SessionFieldsEscaped(t *testing.T) {
	html := web.GatewayDashboardHTML
	for _, expr := range []string{
		"esc(sess.session_id)",
		"esc(sess.client || '-')",
		"esc((sess.callers || []).join(', '))",
		"esc((sess.models || []).join(', '))",
		"esc((sess.providers || []).join(', '))",
		"esc(a.agent_id || '(unattributed)')",
		"esc(a.parent_agent_id)",
		"esc(dd.reason)",
	} {
		assert.Contains(t, html, expr, "client-asserted value must be escaped: %s", expr)
	}
	// No raw interpolation of the hostile fields anywhere in the renderer.
	assert.NotContains(t, html, "+ sess.session_id +", "session_id must never be interpolated unescaped")
	assert.NotContains(t, html, "+ a.agent_id +", "agent_id must never be interpolated unescaped")
}
