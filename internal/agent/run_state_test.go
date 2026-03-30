package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		status   RunStatus
		terminal bool
	}{
		{RunStatusQueued, false},
		{RunStatusRunning, false},
		{RunStatusPaused, false},
		{RunStatusCompleted, true},
		{RunStatusFailed, true},
		{RunStatusTerminated, true},
		{RunStatusBlocked, true},
		{RunStatusDenied, true},
	}
	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			assert.Equal(t, tt.terminal, tt.status.IsTerminal())
		})
	}
}

func TestRunRegistry_RegisterAndGet(t *testing.T) {
	rr := NewRunRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("corr-1", "tenant-a", "agent-x", "sess-1", cancel)
	_ = ctx

	rs := rr.Get("corr-1")
	require.NotNil(t, rs)
	assert.Equal(t, "corr-1", rs.CorrelationID)
	assert.Equal(t, "tenant-a", rs.TenantID)
	assert.Equal(t, "agent-x", rs.AgentID)
	assert.Equal(t, "sess-1", rs.SessionID)
	assert.Equal(t, RunStatusQueued, rs.Status)
	assert.False(t, rs.StartedAt.IsZero())
	assert.Nil(t, rs.cancel, "cancel func should not leak via Get")
	assert.Nil(t, rs.pauseCh, "pauseCh should not leak via Get")
}

func TestRunRegistry_GetNotFound(t *testing.T) {
	rr := NewRunRegistry()
	assert.Nil(t, rr.Get("nonexistent"))
}

func TestRunRegistry_SetStatus(t *testing.T) {
	rr := NewRunRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("corr-1", "t", "a", "", cancel)
	rr.SetStatus("corr-1", RunStatusRunning, FailureNone)

	rs := rr.Get("corr-1")
	require.NotNil(t, rs)
	assert.Equal(t, RunStatusRunning, rs.Status)

	rr.SetStatus("corr-1", RunStatusCompleted, FailureNone)
	rs = rr.Get("corr-1")
	assert.Equal(t, RunStatusCompleted, rs.Status)
	assert.True(t, rs.DurationMS >= 0)
}

func TestRunRegistry_SetStatusIgnoresTerminal(t *testing.T) {
	rr := NewRunRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("corr-1", "t", "a", "", cancel)
	rr.SetStatus("corr-1", RunStatusFailed, FailureLLMError)
	rr.SetStatus("corr-1", RunStatusRunning, FailureNone)

	rs := rr.Get("corr-1")
	assert.Equal(t, RunStatusFailed, rs.Status, "should not transition from terminal state")
	assert.Equal(t, FailureLLMError, rs.FailureReason)
}

func TestRunRegistry_SetStatusNotFound(t *testing.T) {
	rr := NewRunRegistry()
	rr.SetStatus("ghost", RunStatusRunning, FailureNone) // no panic
}

func TestRunRegistry_UpdateMetrics(t *testing.T) {
	rr := NewRunRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("corr-1", "t", "a", "", cancel)
	rr.UpdateMetrics("corr-1", 5, 3, 0.042)

	rs := rr.Get("corr-1")
	require.NotNil(t, rs)
	assert.Equal(t, 5, rs.StepCount)
	assert.Equal(t, 3, rs.ToolCalls)
	assert.InDelta(t, 0.042, rs.CostAccrued, 1e-9)
}

func TestRunRegistry_UpdateMetricsNotFound(t *testing.T) {
	rr := NewRunRegistry()
	rr.UpdateMetrics("ghost", 1, 1, 1.0) // no panic
}

func TestRunRegistry_ListActiveOnly(t *testing.T) {
	rr := NewRunRegistry()
	_, c1 := context.WithCancel(context.Background())
	_, c2 := context.WithCancel(context.Background())
	_, c3 := context.WithCancel(context.Background())
	defer c1()
	defer c2()
	defer c3()

	rr.Register("active-1", "t", "a", "", c1)
	rr.Register("active-2", "t", "a", "", c2)
	rr.Register("done-1", "t", "a", "", c3)
	rr.SetStatus("active-1", RunStatusRunning, FailureNone)
	rr.SetStatus("done-1", RunStatusCompleted, FailureNone)

	active := rr.List()
	assert.Len(t, active, 2, "List should return only non-terminal runs")

	all := rr.ListAll()
	assert.Len(t, all, 3, "ListAll should return all runs")
}

func TestRunRegistry_Kill(t *testing.T) {
	rr := NewRunRegistry()
	ctx, cancel := context.WithCancel(context.Background())

	rr.Register("corr-1", "t", "a", "", cancel)
	rr.SetStatus("corr-1", RunStatusRunning, FailureNone)

	killed := rr.Kill("corr-1")
	assert.True(t, killed)
	assert.Error(t, ctx.Err(), "context should be cancelled")

	rs := rr.Get("corr-1")
	assert.Equal(t, RunStatusTerminated, rs.Status)
	assert.Equal(t, FailureOperatorKill, rs.FailureReason)
}

func TestRunRegistry_KillNotFound(t *testing.T) {
	rr := NewRunRegistry()
	assert.False(t, rr.Kill("nonexistent"))
}

func TestRunRegistry_KillAlreadyTerminal(t *testing.T) {
	rr := NewRunRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("corr-1", "t", "a", "", cancel)
	rr.SetStatus("corr-1", RunStatusCompleted, FailureNone)

	assert.False(t, rr.Kill("corr-1"), "kill of terminal run should return false")
}

func TestRunRegistry_KillAllForTenant(t *testing.T) {
	rr := NewRunRegistry()
	ctx1, c1 := context.WithCancel(context.Background())
	ctx2, c2 := context.WithCancel(context.Background())
	_, c3 := context.WithCancel(context.Background())
	defer c3()

	rr.Register("t1-run1", "tenant-a", "a", "", c1)
	rr.Register("t1-run2", "tenant-a", "a", "", c2)
	rr.Register("t2-run1", "tenant-b", "a", "", c3)

	killed := rr.KillAllForTenant("tenant-a")
	assert.Equal(t, 2, killed)
	assert.Error(t, ctx1.Err())
	assert.Error(t, ctx2.Err())

	rs := rr.Get("t2-run1")
	assert.Equal(t, RunStatusQueued, rs.Status, "tenant-b run should be unaffected")
}

func TestRunRegistry_Deregister(t *testing.T) {
	rr := NewRunRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("corr-1", "t", "a", "", cancel)
	rr.Deregister("corr-1")

	assert.Nil(t, rr.Get("corr-1"))
	assert.Equal(t, 0, rr.ActiveRunCount())
}

func TestRunRegistry_Count(t *testing.T) {
	rr := NewRunRegistry()
	_, c1 := context.WithCancel(context.Background())
	_, c2 := context.WithCancel(context.Background())
	_, c3 := context.WithCancel(context.Background())
	defer c1()
	defer c2()
	defer c3()

	rr.Register("r1", "tenant-a", "a", "", c1)
	rr.Register("r2", "tenant-a", "a", "", c2)
	rr.Register("r3", "tenant-b", "a", "", c3)
	rr.SetStatus("r2", RunStatusCompleted, FailureNone)

	assert.Equal(t, 1, rr.Count("tenant-a"))
	assert.Equal(t, 1, rr.Count("tenant-b"))
	assert.Equal(t, 2, rr.ActiveRunCount())
}

func TestRunRegistry_PauseResume(t *testing.T) {
	rr := NewRunRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("corr-1", "t", "a", "", cancel)

	assert.False(t, rr.Pause("corr-1"), "can't pause a queued run")

	rr.SetStatus("corr-1", RunStatusRunning, FailureNone)
	assert.True(t, rr.Pause("corr-1"))
	assert.True(t, rr.IsPaused("corr-1"))

	rs := rr.Get("corr-1")
	assert.Equal(t, RunStatusPaused, rs.Status)

	assert.False(t, rr.Pause("corr-1"), "can't pause an already paused run")
}

func TestRunRegistry_Resume(t *testing.T) {
	rr := NewRunRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("corr-1", "t", "a", "", cancel)
	rr.SetStatus("corr-1", RunStatusRunning, FailureNone)
	rr.Pause("corr-1")

	paused, pauseCh := rr.IsPausedWithCh("corr-1")
	require.True(t, paused)
	require.NotNil(t, pauseCh)

	resumed := rr.Resume("corr-1")
	assert.True(t, resumed)

	select {
	case <-pauseCh:
		// channel was closed on resume — correct
	case <-time.After(100 * time.Millisecond):
		t.Fatal("pauseCh should have been closed on resume")
	}

	rs := rr.Get("corr-1")
	assert.Equal(t, RunStatusRunning, rs.Status)
	assert.False(t, rr.IsPaused("corr-1"))
}

func TestRunRegistry_ResumeNotPaused(t *testing.T) {
	rr := NewRunRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("corr-1", "t", "a", "", cancel)
	rr.SetStatus("corr-1", RunStatusRunning, FailureNone)

	assert.False(t, rr.Resume("corr-1"), "can't resume a running (not paused) run")
}

func TestRunRegistry_IsPausedWithCh_NotFound(t *testing.T) {
	rr := NewRunRegistry()
	paused, ch := rr.IsPausedWithCh("ghost")
	assert.False(t, paused)
	assert.Nil(t, ch)
}

func TestRunRegistry_IsPaused_NotFound(t *testing.T) {
	rr := NewRunRegistry()
	assert.False(t, rr.IsPaused("ghost"))
}

func TestRunRegistry_ConcurrentAccess(t *testing.T) {
	rr := NewRunRegistry()
	var wg sync.WaitGroup
	const n = 100

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "corr-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
			_, cancel := context.WithCancel(context.Background())
			rr.Register(id, "t", "a", "", cancel)
			rr.SetStatus(id, RunStatusRunning, FailureNone)
			rr.UpdateMetrics(id, i, i, float64(i))
			_ = rr.Get(id)
			_ = rr.List()
			_ = rr.Count("t")
			rr.Kill(id)
			cancel()
		}(i)
	}
	wg.Wait()
}

// TestRunRegistry_PauseResumeRace exercises the exact race that existed
// when IsPaused() and PauseCh() were separate calls: a concurrent Resume()
// could close the old channel and replace it before PauseCh() ran,
// returning the new (never-closed) channel and hanging the select.
//
// With IsPausedWithCh the status and channel are read under a single lock,
// so the captured channel is always the one Resume() will close.
func TestRunRegistry_PauseResumeRace(t *testing.T) {
	const iterations = 200
	rr := NewRunRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("race-1", "t", "a", "", cancel)
	rr.SetStatus("race-1", RunStatusRunning, FailureNone)

	var wg sync.WaitGroup

	for i := 0; i < iterations; i++ {
		rr.Pause("race-1")

		wg.Add(2)

		// Goroutine 1: simulates the agent loop reading pause state + channel.
		unblocked := make(chan struct{})
		go func() {
			defer wg.Done()
			paused, ch := rr.IsPausedWithCh("race-1")
			if !paused || ch == nil {
				close(unblocked)
				return
			}
			select {
			case <-ch:
			case <-ctx.Done():
				t.Error("agent loop hung — IsPausedWithCh returned stale channel")
			}
			close(unblocked)
		}()

		// Goroutine 2: simulates an operator resuming the run concurrently.
		go func() {
			defer wg.Done()
			rr.Resume("race-1")
		}()

		select {
		case <-unblocked:
		case <-time.After(2 * time.Second):
			t.Fatal("deadlock: agent goroutine did not unblock after resume")
		}

		wg.Wait()

		// Reset to running for the next iteration.
		rr.SetStatus("race-1", RunStatusRunning, FailureNone)
	}
}
