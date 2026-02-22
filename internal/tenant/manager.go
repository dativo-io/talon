// Package tenant provides multi-tenant request validation: rate limiting and
// cost budget enforcement using the evidence store.
package tenant

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
	"golang.org/x/time/rate"
)

var (
	ErrTenantNotFound        = errors.New("tenant not found")
	ErrRateLimitExceeded     = errors.New("rate limit exceeded")
	ErrDailyBudgetExceeded   = errors.New("daily budget exceeded")
	ErrMonthlyBudgetExceeded = errors.New("monthly budget exceeded")
)

// Tenant holds per-tenant configuration for rate limits and cost budgets.
type Tenant struct {
	ID            string
	DisplayName   string
	DailyBudget   float64 // EUR; 0 means no daily limit
	MonthlyBudget float64 // EUR; 0 means no monthly limit
	RateLimit     int     // requests per second; 0 means no limit
}

// Manager validates incoming requests per tenant: existence, rate limit, and budgets.
type Manager struct {
	tenants       map[string]*Tenant
	limiters      map[string]*rate.Limiter
	evidenceStore *evidence.Store
	mu            sync.RWMutex
}

// NewManager creates a tenant manager with the given tenants and evidence store for budget checks.
func NewManager(tenants []Tenant, evidenceStore *evidence.Store) *Manager {
	m := &Manager{
		tenants:       make(map[string]*Tenant),
		limiters:      make(map[string]*rate.Limiter),
		evidenceStore: evidenceStore,
	}
	for i := range tenants {
		t := &tenants[i]
		m.tenants[t.ID] = t
		if t.RateLimit > 0 {
			m.limiters[t.ID] = rate.NewLimiter(rate.Limit(t.RateLimit), t.RateLimit*2) // burst = 2s worth
		}
	}
	return m
}

// ValidateRequest checks that the tenant exists, is within rate limit, and within daily/monthly budgets.
// Returns a typed error on failure.
func (m *Manager) ValidateRequest(ctx context.Context, tenantID string) error {
	m.mu.RLock()
	t, ok := m.tenants[tenantID]
	m.mu.RUnlock()
	if !ok {
		return ErrTenantNotFound
	}

	if lim := m.limiter(tenantID); lim != nil {
		if !lim.Allow() {
			return ErrRateLimitExceeded
		}
	}

	if m.evidenceStore == nil {
		return nil
	}

	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)

	if t.DailyBudget > 0 {
		cost, err := m.evidenceStore.CostTotal(ctx, tenantID, "", dayStart, dayEnd)
		if err != nil {
			return err
		}
		if cost >= t.DailyBudget {
			return ErrDailyBudgetExceeded
		}
	}

	if t.MonthlyBudget > 0 {
		cost, err := m.evidenceStore.CostTotal(ctx, tenantID, "", monthStart, monthEnd)
		if err != nil {
			return err
		}
		if cost >= t.MonthlyBudget {
			return ErrMonthlyBudgetExceeded
		}
	}

	return nil
}

func (m *Manager) limiter(tenantID string) *rate.Limiter {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.limiters[tenantID]
}
