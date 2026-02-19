package trigger

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
)

type mockRunner struct {
	calls []string
}

func (m *mockRunner) RunFromTrigger(ctx context.Context, agentName, prompt, invocationType string) error {
	m.calls = append(m.calls, agentName+":"+prompt+":"+invocationType)
	return nil
}

func TestRegisterSchedules_AddsEntries(t *testing.T) {
	runner := &mockRunner{}
	sched := NewScheduler(runner)

	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "sales-analyst"},
		Triggers: &policy.TriggersConfig{
			Schedule: []policy.ScheduleTrigger{
				{Cron: "0 9 * * *", Prompt: "Morning report", Description: "daily"},
				{Cron: "0 17 * * *", Prompt: "Evening summary", Description: "daily"},
			},
		},
	}

	err := sched.RegisterSchedules(pol)
	require.NoError(t, err)
	assert.Equal(t, 2, sched.Entries())
}

func TestRegisterSchedules_InvalidCron(t *testing.T) {
	runner := &mockRunner{}
	sched := NewScheduler(runner)

	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "test"},
		Triggers: &policy.TriggersConfig{
			Schedule: []policy.ScheduleTrigger{
				{Cron: "not a valid cron", Prompt: "test"},
			},
		},
	}

	err := sched.RegisterSchedules(pol)
	assert.Error(t, err)
}

func TestStartStop(t *testing.T) {
	runner := &mockRunner{}
	sched := NewScheduler(runner)
	sched.Start()
	sched.Stop()
}
