package gateway

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
)

const sovereigntyDenyReason = "sovereignty: provider not EU/LOCAL"

// denySovereigntyExcluded responds with 403 when the routed provider is excluded
// under eu_strict (non-EU/LOCAL region). Data residency is a HARD platform
// boundary (#266 review round 4): it blocks in EVERY mode — enforce, shadow,
// AND log_only — because forwarding EU-resident data to a non-EU provider even
// to "observe" would itself breach residency. Returns true when hard-denied.
func (g *Gateway) denySovereigntyExcluded(
	w http.ResponseWriter,
	ctx context.Context,
	agent *ResolvedIdentity,
	route RouteResult,
	start time.Time,
	correlationID string,
	extracted ExtractedRequest,
	classification *classifier.Classification,
	attSummary *AttachmentsScanSummary,
	isShadow bool,
	shadowViolations *[]evidence.ShadowViolation,
) bool {
	mode := g.config.EffectiveSovereigntyMode
	if mode != config.DataSovereigntyEUStrict {
		return false
	}
	region := strings.ToUpper(strings.TrimSpace(g.providerRegion(route.Provider)))
	if region == "EU" || region == "LOCAL" {
		return false
	}

	// Data-sovereignty eu_strict is a HARD PLATFORM BOUNDARY, not an
	// observable governance control (#266 review round 4): it blocks in EVERY
	// mode — enforce, shadow, AND log_only. Forwarding confidential EU data to
	// a non-EU provider merely to "observe" would itself breach residency, so
	// shadow/log_only must never let it egress.
	_ = isShadow
	durationMS := time.Since(start).Milliseconds()
	msg := "provider blocked by sovereignty.mode=eu_strict (non-EU/LOCAL region)"
	WriteProviderError(w, g.config.providerAPIFamily(route.Provider), http.StatusForbidden, msg)
	RecordSovereigntyProviderDenied(ctx, route.Provider)
	persisted, err := g.recordEvidence(ctx, correlationID, agent, route.Provider, extracted.Model, start, extracted.Text,
		classification, nil, 0, durationMS, "", false, []string{sovereigntyDenyReason}, false, nil, attSummary, nil, nil, false, "", 0, 0, false, 0, 0, 0)
	if err != nil {
		g.handleEvidenceWriteFailure(ctx, err)
		return true
	}
	g.emitMetrics(ctx, agent, route.Provider, extracted.Model, classification, nil, nil, nil, 0, durationMS, false, true, "", false, 0, 0, 0, persisted)
	return true
}
