package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/rs/zerolog/log"
)

const sovereigntyDenyReason = "sovereignty: provider not EU/LOCAL"

// denySovereigntyExcluded responds with 403 when the routed provider is excluded
// under eu_strict (non-EU/LOCAL region). In shadow mode it records a violation
// and returns false so the request continues to upstream. Returns true when the
// request was hard-denied (enforce mode only).
func (g *Gateway) denySovereigntyExcluded(
	w http.ResponseWriter,
	ctx context.Context,
	caller *CallerConfig,
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

	if isShadow {
		*shadowViolations = append(*shadowViolations, evidence.ShadowViolation{
			Type:   "sovereignty_deny",
			Detail: fmt.Sprintf("provider %s region %s blocked by sovereignty.mode=eu_strict", route.Provider, region),
			Action: "block",
		})
		log.Warn().Str("caller", caller.Name).Str("provider", route.Provider).Str("region", region).Str("enforcement_mode", "shadow").Msg("shadow_sovereignty_deny")
		RecordSovereigntyProviderDenied(ctx, route.Provider)
		return false
	}

	durationMS := time.Since(start).Milliseconds()
	msg := "provider blocked by sovereignty.mode=eu_strict (non-EU/LOCAL region)"
	WriteProviderError(w, g.config.providerAPIFamily(route.Provider), http.StatusForbidden, msg)
	RecordSovereigntyProviderDenied(ctx, route.Provider)
	persisted, err := g.recordEvidence(ctx, correlationID, caller, route.Provider, extracted.Model, start, extracted.Text,
		classification, nil, 0, durationMS, "", false, []string{sovereigntyDenyReason}, false, nil, attSummary, nil, nil, false, "", 0, 0, false, 0, 0, 0)
	if err != nil {
		g.handleEvidenceWriteFailure(ctx, err)
		return true
	}
	g.emitMetrics(ctx, caller, route.Provider, extracted.Model, classification, nil, nil, nil, 0, durationMS, false, true, "", false, 0, 0, 0, persisted)
	return true
}
