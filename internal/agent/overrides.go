package agent

import (
	"fmt"
	"sync"
	"time"
)

// TenantOverride holds runtime overrides for a single tenant. Overrides
// take precedence over .talon.yaml policy and are applied at Run() entry
// and tool dispatch.
type TenantOverride struct {
	Lockdown      bool      `json:"lockdown"`                 // When true, all new runs are rejected
	LockdownAt    time.Time `json:"lockdown_at,omitempty"`    // When lockdown was activated
	LockdownBy    string    `json:"lockdown_by,omitempty"`    // Admin identifier who set lockdown
	DisabledTools []string  `json:"disabled_tools,omitempty"` // Tools blocked by override
	DisableReason string    `json:"disable_reason,omitempty"` // Incident ID or explanation

	MaxCostPerRun *float64 `json:"max_cost_per_run,omitempty"` // Tighter cost cap (overrides YAML)
	MaxToolCalls  *int     `json:"max_tool_calls,omitempty"`   // Tighter tool call cap
}

// OverrideStore provides in-memory runtime overrides per tenant. Thread-safe.
// Checked at Run() entry for lockdown and in buildLLMTools for tool disabling.
type OverrideStore struct {
	mu        sync.RWMutex
	overrides map[string]*TenantOverride // keyed by tenant_id
}

// NewOverrideStore creates an empty override store.
func NewOverrideStore() *OverrideStore {
	return &OverrideStore{
		overrides: make(map[string]*TenantOverride),
	}
}

// ErrTenantLocked is returned when a run is attempted on a locked-down tenant.
var ErrTenantLocked = fmt.Errorf("tenant is locked down")

// Get returns the current override for a tenant, or nil if none.
func (os *OverrideStore) Get(tenantID string) *TenantOverride {
	os.mu.RLock()
	defer os.mu.RUnlock()
	ov, ok := os.overrides[tenantID]
	if !ok {
		return nil
	}
	cp := *ov
	cp.DisabledTools = append([]string(nil), ov.DisabledTools...)
	return &cp
}

// SetLockdown enables or disables tenant lockdown.
func (os *OverrideStore) SetLockdown(tenantID string, locked bool, by string) {
	os.mu.Lock()
	defer os.mu.Unlock()
	ov := os.getOrCreate(tenantID)
	ov.Lockdown = locked
	if locked {
		ov.LockdownAt = time.Now()
		ov.LockdownBy = by
	} else {
		ov.LockdownAt = time.Time{}
		ov.LockdownBy = ""
	}
}

// IsLocked returns true if the tenant is in lockdown mode.
func (os *OverrideStore) IsLocked(tenantID string) bool {
	os.mu.RLock()
	defer os.mu.RUnlock()
	ov, ok := os.overrides[tenantID]
	return ok && ov.Lockdown
}

// DisableTools adds tools to the disabled list for a tenant.
func (os *OverrideStore) DisableTools(tenantID string, tools []string, reason string) {
	os.mu.Lock()
	defer os.mu.Unlock()
	ov := os.getOrCreate(tenantID)
	existing := make(map[string]bool)
	for _, t := range ov.DisabledTools {
		existing[t] = true
	}
	for _, t := range tools {
		if !existing[t] {
			ov.DisabledTools = append(ov.DisabledTools, t)
			existing[t] = true
		}
	}
	ov.DisableReason = reason
}

// EnableTools removes tools from the disabled list for a tenant.
func (os *OverrideStore) EnableTools(tenantID string, tools []string) {
	os.mu.Lock()
	defer os.mu.Unlock()
	ov, ok := os.overrides[tenantID]
	if !ok {
		return
	}
	removeSet := make(map[string]bool)
	for _, t := range tools {
		removeSet[t] = true
	}
	filtered := ov.DisabledTools[:0]
	for _, t := range ov.DisabledTools {
		if !removeSet[t] {
			filtered = append(filtered, t)
		}
	}
	ov.DisabledTools = filtered
}

// DisabledToolsFor returns the list of disabled tools for a tenant.
func (os *OverrideStore) DisabledToolsFor(tenantID string) []string {
	os.mu.RLock()
	defer os.mu.RUnlock()
	ov, ok := os.overrides[tenantID]
	if !ok || len(ov.DisabledTools) == 0 {
		return nil
	}
	return append([]string(nil), ov.DisabledTools...)
}

// SetPolicyOverride sets a tighter cost or tool call cap for a tenant.
func (os *OverrideStore) SetPolicyOverride(tenantID string, maxCostPerRun *float64, maxToolCalls *int) {
	os.mu.Lock()
	defer os.mu.Unlock()
	ov := os.getOrCreate(tenantID)
	ov.MaxCostPerRun = maxCostPerRun
	ov.MaxToolCalls = maxToolCalls
}

// ClearOverride removes all overrides for a tenant.
func (os *OverrideStore) ClearOverride(tenantID string) {
	os.mu.Lock()
	defer os.mu.Unlock()
	delete(os.overrides, tenantID)
}

// ListAll returns all tenant overrides.
func (os *OverrideStore) ListAll() map[string]TenantOverride {
	os.mu.RLock()
	defer os.mu.RUnlock()
	result := make(map[string]TenantOverride, len(os.overrides))
	for k, v := range os.overrides {
		cp := *v
		cp.DisabledTools = append([]string(nil), v.DisabledTools...)
		result[k] = cp
	}
	return result
}

func (os *OverrideStore) getOrCreate(tenantID string) *TenantOverride {
	ov, ok := os.overrides[tenantID]
	if !ok {
		ov = &TenantOverride{}
		os.overrides[tenantID] = ov
	}
	return ov
}
