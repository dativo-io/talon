package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOverrideStore_EmptyGet(t *testing.T) {
	store := NewOverrideStore()
	assert.Nil(t, store.Get("nonexistent"))
}

func TestOverrideStore_SetLockdown(t *testing.T) {
	store := NewOverrideStore()

	store.SetLockdown("acme", true, "admin_api")
	assert.True(t, store.IsLocked("acme"))

	ov := store.Get("acme")
	require.NotNil(t, ov)
	assert.True(t, ov.Lockdown)
	assert.Equal(t, "admin_api", ov.LockdownBy)
	assert.False(t, ov.LockdownAt.IsZero())
}

func TestOverrideStore_LiftLockdown(t *testing.T) {
	store := NewOverrideStore()

	store.SetLockdown("acme", true, "admin_api")
	store.SetLockdown("acme", false, "")

	assert.False(t, store.IsLocked("acme"))

	ov := store.Get("acme")
	require.NotNil(t, ov)
	assert.False(t, ov.Lockdown)
	assert.Empty(t, ov.LockdownBy)
	assert.True(t, ov.LockdownAt.IsZero())
}

func TestOverrideStore_IsLocked_NonexistentTenant(t *testing.T) {
	store := NewOverrideStore()
	assert.False(t, store.IsLocked("ghost"))
}

func TestOverrideStore_DisableTools(t *testing.T) {
	store := NewOverrideStore()

	store.DisableTools("acme", []string{"send_email", "delete_all"}, "INC-001")
	disabled := store.DisabledToolsFor("acme")
	assert.ElementsMatch(t, []string{"send_email", "delete_all"}, disabled)

	ov := store.Get("acme")
	assert.Equal(t, "INC-001", ov.DisableReason)
}

func TestOverrideStore_DisableTools_NoDuplicates(t *testing.T) {
	store := NewOverrideStore()

	store.DisableTools("acme", []string{"send_email"}, "first")
	store.DisableTools("acme", []string{"send_email", "query_db"}, "second")

	disabled := store.DisabledToolsFor("acme")
	assert.Len(t, disabled, 2, "send_email should not be duplicated")
	assert.ElementsMatch(t, []string{"send_email", "query_db"}, disabled)
}

func TestOverrideStore_EnableTools(t *testing.T) {
	store := NewOverrideStore()

	store.DisableTools("acme", []string{"a", "b", "c"}, "test")
	store.EnableTools("acme", []string{"b"})

	disabled := store.DisabledToolsFor("acme")
	assert.ElementsMatch(t, []string{"a", "c"}, disabled)
}

func TestOverrideStore_EnableTools_NonexistentTenant(t *testing.T) {
	store := NewOverrideStore()
	store.EnableTools("ghost", []string{"a"}) // no panic
}

func TestOverrideStore_DisabledToolsFor_Empty(t *testing.T) {
	store := NewOverrideStore()
	assert.Nil(t, store.DisabledToolsFor("ghost"))
}

func TestOverrideStore_SetPolicyOverride(t *testing.T) {
	store := NewOverrideStore()

	maxCost := 0.05
	maxTools := 3
	store.SetPolicyOverride("acme", &maxCost, &maxTools)

	ov := store.Get("acme")
	require.NotNil(t, ov)
	require.NotNil(t, ov.MaxCostPerRun)
	require.NotNil(t, ov.MaxToolCalls)
	assert.InDelta(t, 0.05, *ov.MaxCostPerRun, 1e-9)
	assert.Equal(t, 3, *ov.MaxToolCalls)
}

func TestOverrideStore_SetPolicyOverride_PartialNil(t *testing.T) {
	store := NewOverrideStore()

	maxCost := 1.0
	store.SetPolicyOverride("acme", &maxCost, nil)

	ov := store.Get("acme")
	require.NotNil(t, ov.MaxCostPerRun)
	assert.Nil(t, ov.MaxToolCalls)
}

func TestOverrideStore_ClearOverride(t *testing.T) {
	store := NewOverrideStore()

	store.SetLockdown("acme", true, "admin")
	store.DisableTools("acme", []string{"tool_a"}, "reason")

	store.ClearOverride("acme")
	assert.Nil(t, store.Get("acme"))
	assert.False(t, store.IsLocked("acme"))
	assert.Nil(t, store.DisabledToolsFor("acme"))
}

func TestOverrideStore_ListAll(t *testing.T) {
	store := NewOverrideStore()

	store.SetLockdown("acme", true, "admin")
	store.DisableTools("globex", []string{"tool_a"}, "reason")

	all := store.ListAll()
	assert.Len(t, all, 2)

	acme, ok := all["acme"]
	assert.True(t, ok)
	assert.True(t, acme.Lockdown)

	globex, ok := all["globex"]
	assert.True(t, ok)
	assert.ElementsMatch(t, []string{"tool_a"}, globex.DisabledTools)
}

func TestOverrideStore_ListAll_Empty(t *testing.T) {
	store := NewOverrideStore()
	all := store.ListAll()
	assert.Empty(t, all)
}

func TestOverrideStore_GetReturnsCopy(t *testing.T) {
	store := NewOverrideStore()
	store.DisableTools("acme", []string{"tool_a"}, "reason")

	ov := store.Get("acme")
	ov.DisabledTools = append(ov.DisabledTools, "mutated")

	original := store.Get("acme")
	assert.Len(t, original.DisabledTools, 1, "mutation of copy should not affect store")
}

func TestOverrideStore_MultiTenantIsolation(t *testing.T) {
	store := NewOverrideStore()

	store.SetLockdown("acme", true, "admin")
	store.DisableTools("globex", []string{"tool_x"}, "test")

	assert.True(t, store.IsLocked("acme"))
	assert.False(t, store.IsLocked("globex"))
	assert.Nil(t, store.DisabledToolsFor("acme"))
	assert.ElementsMatch(t, []string{"tool_x"}, store.DisabledToolsFor("globex"))
}
