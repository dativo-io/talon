// Package evidence cache_event records cache lifecycle events (eviction, GDPR erasure) as evidence.
package evidence

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// CacheEventType is the type of cache-related audit event.
const (
	CacheEventEviction      = "cache_eviction"       // Background eviction of expired entries
	CacheEventErasureTenant = "cache_erasure_tenant" // GDPR Art. 17: erase all cache for tenant
	CacheEventErasureUser   = "cache_erasure_user"   // GDPR Art. 17: erase cache for tenant+user
)

// CacheEventParams holds parameters for recording a cache lifecycle event.
type CacheEventParams struct {
	TenantID        string // Tenant scope
	UserID          string // For cache_erasure_user; empty for eviction/tenant erasure
	EventType       string // CacheEventEviction, CacheEventErasureTenant, or CacheEventErasureUser
	EntriesAffected int64  // Number of entries removed
	Details         string // Optional human-readable detail (e.g. "expired TTL")
}

// RecordCacheEvent stores a cache lifecycle event as an evidence record so it appears in the audit trail.
// Use for evictions (background job) and GDPR erasure (CLI/API). InvocationType is set to the event type
// so `talon audit list --type cache_eviction` (or cache_erasure_*) can filter.
func (g *Generator) RecordCacheEvent(ctx context.Context, p CacheEventParams) (*Evidence, error) {
	ev := &Evidence{
		ID:              "cache_" + uuid.New().String()[:12],
		CorrelationID:   "cache_" + uuid.New().String()[:12],
		Timestamp:       time.Now(),
		TenantID:        p.TenantID,
		AgentID:         "",
		InvocationType:  p.EventType,
		RequestSourceID: "system",
		PolicyDecision:  PolicyDecision{Allowed: true, Action: "allow", PolicyVersion: ""},
		Classification:  Classification{},
		Execution: Execution{
			Cost:       0,
			DurationMS: 0,
		},
		AuditTrail:            AuditTrail{},
		Compliance:            Compliance{},
		ModelRoutingRationale: p.Details,
	}
	if p.EntriesAffected > 0 {
		ev.Execution.Tokens = TokenUsage{Input: int(p.EntriesAffected), Output: 0}
	}
	if err := g.store.Store(ctx, ev); err != nil {
		return nil, err
	}
	return ev, nil
}
