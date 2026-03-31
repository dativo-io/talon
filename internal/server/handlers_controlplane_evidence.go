package server

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/evidence"
)

// recordControlPlaneAction generates a signed evidence record for operator
// interventions (kill, lockdown, pause, resume, tool disable, approval decisions).
// These records are queryable via the evidence API and carry HMAC integrity.
func (s *Server) recordControlPlaneAction(ctx context.Context, tenantID, action, operator, detail string) {
	if s.evidenceStore == nil {
		return
	}
	normalizedTenantID := tenantID
	if normalizedTenantID == "" {
		normalizedTenantID = "default"
	}
	sessionID := s.ensureControlPlaneSessionID(ctx, normalizedTenantID, operator)

	gen := evidence.NewGenerator(s.evidenceStore)
	_, err := gen.Generate(ctx, evidence.GenerateParams{
		CorrelationID:   "cp_" + action + "_" + time.Now().UTC().Format("20060102T150405Z"),
		SessionID:       sessionID,
		TenantID:        normalizedTenantID,
		AgentID:         "",
		InvocationType:  "control_plane",
		RequestSourceID: operator,
		PolicyDecision: evidence.PolicyDecision{
			Allowed: true,
			Action:  action,
			Reasons: []string{detail},
		},
		InputPrompt:    action + ": " + detail,
		OutputResponse: operator,
		Status:         action,
		FailureReason:  "",
	})
	if err != nil {
		log.Warn().Err(err).Str("action", action).Str("tenant_id", normalizedTenantID).
			Msg("failed to record control plane evidence")
	}
}

func (s *Server) ensureControlPlaneSessionID(ctx context.Context, tenantID, operator string) string {
	if s.sessionStore != nil {
		ss, err := s.sessionStore.Create(ctx, tenantID, "control-plane", operator, 0)
		if err == nil && ss != nil && ss.ID != "" {
			return ss.ID
		}
		if err != nil {
			log.Warn().Err(err).Str("tenant_id", tenantID).Msg("control_plane_session_create_failed")
		}
	}
	return fmt.Sprintf("sess_cp_%d", time.Now().UTC().UnixNano())
}
