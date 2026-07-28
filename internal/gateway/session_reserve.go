package gateway

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/session"
)

// sessionReservationStaleAfter bounds how long a leaked reservation (a crash
// between reserve and settle) can suppress a session's headroom: the next
// request on the session heals it (heal-on-touch in ReserveSessionCost).
// Longer than any legitimate in-flight request — request_timeout governs the
// non-streaming path and stream_idle_timeout aborts silent streams (#217), so
// a reservation older than this cannot belong to live work.
const sessionReservationStaleAfter = 15 * time.Minute

// sessionView is the session-budget state ONE request's admission decision is
// evaluated against — computed once (with the reservation) and passed to the
// primary policy input AND every failover candidate, so all of them see the
// identical spend (TestPolicyInputParity_WithAssertedSession).
type sessionView struct {
	// costTotal = settled spend + every OTHER request's reservation; the
	// caller's own estimate is excluded (the policy rule adds it back as
	// estimated_cost).
	costTotal   float64
	stageCounts *session.StageCounts
	ok          bool // view computed (asserted session)
	unavailable bool // store failure — fail open, annotate in evidence
}

// sessionReservation is one request's claim on session-cap headroom (#144).
// Exactly one of release/settle consumes it; done guards double-consumption
// (the deferred release after a successful settle is a no-op).
type sessionReservation struct {
	rowID    string
	estimate float64
	done     bool
}

// reserveSessionBudget computes the session-budget view for an asserted
// session and, when this request carries a positive pre-request estimate,
// atomically reserves that estimate against the session BEFORE policy
// evaluation. Concurrent requests therefore serialize: each admission sees
// prior in-flight reservations in costTotal instead of the same pre-burst
// settled spend — the session cap stops being soft against bursts (#144).
// The policy engine remains the only decider; this function only changes the
// spend input it sees.
//
// Zero-estimate requests (count_tokens) build a read-only view and never
// create a session row — count-only traffic must not materialize sessions.
func (g *Gateway) reserveSessionBudget(ctx context.Context, agent *ResolvedIdentity, sessionID, sessionSource string, estimate float64) (*sessionView, *sessionReservation) {
	if g.sessionStore == nil || sessionID == "" || !isAssertedSessionSource(sessionSource) {
		return nil, nil
	}
	if estimate <= 0 {
		switch sess, err := g.sessionStore.GetByExternal(ctx, agent.TenantID, agent.Name, sessionID); {
		case err == nil:
			return g.viewForSession(ctx, sess.ID, sess.TotalCost+sess.ReservedCost), nil
		case errors.Is(err, session.ErrSessionNotFound):
			// First request of a session: zero spend, so an agent cap still
			// bounds a single oversized request.
			return &sessionView{ok: true}, nil
		default:
			log.Warn().Err(err).Str("session_id", sessionID).Msg("gateway_session_budget_lookup_failed")
			return &sessionView{unavailable: true}, nil
		}
	}
	sess, err := g.sessionStore.GetOrCreateExternal(ctx, agent.TenantID, agent.Name, sessionID, sessionSource)
	if err != nil {
		log.Warn().Err(err).Str("session_id", sessionID).Msg("gateway_session_budget_lookup_failed")
		return &sessionView{unavailable: true}, nil
	}
	spend, err := g.sessionStore.ReserveSessionCost(ctx, sess.ID, estimate, sessionReservationStaleAfter)
	if err != nil {
		// Reservation failure fails open like every session-store failure
		// (#198) — the gap is visible via the session_budget_unavailable
		// evidence annotation.
		log.Warn().Err(err).Str("session_id", sess.ID).Msg("gateway_session_reserve_failed")
		return &sessionView{unavailable: true}, nil
	}
	return g.viewForSession(ctx, sess.ID, spend), &sessionReservation{rowID: sess.ID, estimate: estimate}
}

func (g *Gateway) viewForSession(ctx context.Context, rowID string, costTotal float64) *sessionView {
	view := &sessionView{ok: true, costTotal: costTotal}
	if sc, err := g.sessionStore.GetStageCounts(ctx, rowID); err == nil {
		view.stageCounts = sc
	}
	return view
}

// releaseSessionReservation returns an unconsumed reservation — every path
// that ends the request without settling (policy deny, tool block, upstream
// failure, panic) reaches this via defer. Detached context: the request
// context is typically already canceled on those paths, and an unreleased
// reservation would silently shrink the session's headroom until the stale
// heal.
func (g *Gateway) releaseSessionReservation(res *sessionReservation) {
	if res == nil || res.done || g.sessionStore == nil {
		return
	}
	res.done = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.sessionStore.ReleaseSessionReservation(ctx, res.rowID, res.estimate); err != nil {
		log.Warn().Err(err).Str("session_id", res.rowID).Msg("gateway_session_release_failed")
	}
}
