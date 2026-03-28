package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToolApprovalStore_ApproveFlow(t *testing.T) {
	store := NewToolApprovalStore(5 * time.Second)
	ctx := context.Background()

	var status ToolApprovalStatus
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		status = store.RequestApproval(ctx, "req_corr1234", "acme", "bot", "send_email", "call_1", map[string]any{"to": "user@example.com"})
	}()

	// Wait for request to appear
	require.Eventually(t, func() bool {
		return len(store.ListPending()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	pending := store.ListPending()
	require.Len(t, pending, 1)
	assert.Equal(t, "send_email", pending[0].ToolName)
	assert.Equal(t, ToolApprovalPending, pending[0].Status)
	assert.Nil(t, pending[0].ch, "channel should not leak")

	reqID := pending[0].ID
	ok := store.Approve(reqID, "admin_api", "verified recipient")
	assert.True(t, ok)

	wg.Wait()
	assert.Equal(t, ToolApprovalApproved, status)

	resolved := store.Get(reqID)
	require.NotNil(t, resolved)
	assert.Equal(t, ToolApprovalApproved, resolved.Status)
	assert.Equal(t, "admin_api", resolved.ResolvedBy)
	assert.Equal(t, "verified recipient", resolved.Reason)
}

func TestToolApprovalStore_DenyFlow(t *testing.T) {
	store := NewToolApprovalStore(5 * time.Second)
	ctx := context.Background()

	var status ToolApprovalStatus
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		status = store.RequestApproval(ctx, "req_deny1234", "acme", "bot", "delete_all", "call_2", nil)
	}()

	require.Eventually(t, func() bool {
		return len(store.ListPending()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	pending := store.ListPending()
	reqID := pending[0].ID

	ok := store.Deny(reqID, "admin_api", "too dangerous")
	assert.True(t, ok)

	wg.Wait()
	assert.Equal(t, ToolApprovalDenied, status)
}

func TestToolApprovalStore_TimeoutFlow(t *testing.T) {
	store := NewToolApprovalStore(100 * time.Millisecond)
	ctx := context.Background()

	status := store.RequestApproval(ctx, "req_tmout123", "acme", "bot", "slow_tool", "call_3", nil)
	assert.Equal(t, ToolApprovalTimeout, status)
}

func TestToolApprovalStore_ContextCancellation(t *testing.T) {
	store := NewToolApprovalStore(10 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())

	var status ToolApprovalStatus
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		status = store.RequestApproval(ctx, "req_cancel12", "acme", "bot", "tool_x", "call_4", nil)
	}()

	require.Eventually(t, func() bool {
		return len(store.ListPending()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	cancel()
	wg.Wait()
	assert.Equal(t, ToolApprovalDenied, status, "context cancel should resolve as denied")
}

func TestToolApprovalStore_ApproveNonPending(t *testing.T) {
	store := NewToolApprovalStore(5 * time.Second)
	assert.False(t, store.Approve("nonexistent", "admin", ""), "approve nonexistent should return false")
}

func TestToolApprovalStore_DenyNonPending(t *testing.T) {
	store := NewToolApprovalStore(5 * time.Second)
	assert.False(t, store.Deny("nonexistent", "admin", ""), "deny nonexistent should return false")
}

func TestToolApprovalStore_DoubleApprove(t *testing.T) {
	store := NewToolApprovalStore(5 * time.Second)
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.RequestApproval(ctx, "req_double12", "acme", "bot", "tool_a", "call_5", nil)
	}()

	require.Eventually(t, func() bool {
		return len(store.ListPending()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	reqID := store.ListPending()[0].ID
	assert.True(t, store.Approve(reqID, "admin", ""))
	assert.False(t, store.Approve(reqID, "admin", ""), "second approve should return false")

	wg.Wait()
}

func TestToolApprovalStore_Get(t *testing.T) {
	store := NewToolApprovalStore(5 * time.Second)
	assert.Nil(t, store.Get("nonexistent"))
}

func TestToolApprovalStore_ListPending_Empty(t *testing.T) {
	store := NewToolApprovalStore(5 * time.Second)
	assert.Empty(t, store.ListPending())
}

func TestToolApprovalStore_Cleanup(t *testing.T) {
	store := NewToolApprovalStore(50 * time.Millisecond)
	ctx := context.Background()

	// Create and resolve a request
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.RequestApproval(ctx, "req_clean123", "acme", "bot", "tool_c", "call_6", nil)
	}()

	require.Eventually(t, func() bool {
		return len(store.ListPending()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	reqID := store.ListPending()[0].ID
	store.Approve(reqID, "admin", "")
	wg.Wait()

	// Wait for the request to become old enough for cleanup
	time.Sleep(60 * time.Millisecond)

	removed := store.Cleanup(50 * time.Millisecond)
	assert.Equal(t, 1, removed)
	assert.Nil(t, store.Get(reqID))
}

func TestToolApprovalStore_CleanupSkipsPending(t *testing.T) {
	store := NewToolApprovalStore(10 * time.Second)
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.RequestApproval(ctx, "req_pend1234", "acme", "bot", "tool_p", "call_7", nil)
	}()

	require.Eventually(t, func() bool {
		return len(store.ListPending()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	removed := store.Cleanup(0)
	assert.Equal(t, 0, removed, "pending requests should not be cleaned up")

	// Cleanup: approve to unblock goroutine
	reqID := store.ListPending()[0].ID
	store.Approve(reqID, "admin", "")
	wg.Wait()
}

func TestToolApprovalStore_DefaultTimeout(t *testing.T) {
	store := NewToolApprovalStore(0)
	assert.NotNil(t, store, "zero timeout should use default")
}
