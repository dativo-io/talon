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

func TestGatewayDashboardHTML_ContainsEvidenceReviewLink(t *testing.T) {
	html := web.GatewayDashboardHTML
	assert.NotEmpty(t, html)
	assert.True(t, strings.Contains(html, "#evidence-gateway"))
	assert.True(t, strings.Contains(html, "Open approvals and evidence review"))
}
