package compliance

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

func TestBuildReportAndRenderHTML(t *testing.T) {
	evs := []evidence.Evidence{
		{
			ID:             "req_1",
			Compliance:     evidence.Compliance{Frameworks: []string{"gdpr"}},
			PolicyDecision: evidence.PolicyDecision{Allowed: true},
			Classification: evidence.Classification{PIIDetected: []string{"email"}},
			Execution:      evidence.Execution{Cost: 0.01},
		},
		{
			ID:             "req_2",
			Compliance:     evidence.Compliance{Frameworks: []string{"gdpr"}},
			PolicyDecision: evidence.PolicyDecision{Allowed: false},
			Execution:      evidence.Execution{Cost: 0.02},
		},
	}
	r := BuildReport("gdpr", "acme", "support", "2026-03-01", "2026-03-31", evs)
	require.Equal(t, 2, r.EvidenceCount)
	require.Equal(t, 1, r.DeniedCount)
	require.Equal(t, 1, r.PIIRecordCount)
	require.GreaterOrEqual(t, len(r.Mappings), 1)

	html, err := RenderHTML(r)
	require.NoError(t, err)
	s := string(html)
	require.Contains(t, s, "<!DOCTYPE html>")
	require.Contains(t, s, "Talon Compliance Report")
	require.NotContains(t, strings.ToLower(s), "http://")
	require.NotContains(t, strings.ToLower(s), "https://")
}

func TestRenderJSON(t *testing.T) {
	r := Report{GeneratedAt: time.Now().UTC(), Framework: "gdpr", EvidenceCount: 3}
	b, err := RenderJSON(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"framework": "gdpr"`)
}
