// Package trigger implements cron scheduling and webhook handling for agent execution.
package trigger

import (
	"context"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/policy"
)

// AgentRunner is the interface for executing agent runs from triggers.
type AgentRunner interface {
	RunFromTrigger(ctx context.Context, agentName, prompt, invocationType string) error
}

// Scheduler manages cron-based agent execution.
type Scheduler struct {
	cron   *cron.Cron
	runner AgentRunner
}

// NewScheduler creates a scheduler backed by the given runner.
// Cron expressions use the standard 5-field format: minute hour day-of-month month day-of-week
// (e.g. "0 9 * * 1-5" for 09:00 on weekdays). Do not use WithSeconds() so docs and configs match.
func NewScheduler(runner AgentRunner) *Scheduler {
	return &Scheduler{
		cron:   cron.New(),
		runner: runner,
	}
}

// RegisterSchedules adds cron entries from the policy's trigger configuration.
func (s *Scheduler) RegisterSchedules(pol *policy.Policy) error {
	if pol.Triggers == nil || len(pol.Triggers.Schedule) == 0 {
		return nil
	}

	agentName := pol.Agent.Name

	for _, sched := range pol.Triggers.Schedule {
		prompt := sched.Prompt
		desc := sched.Description

		_, err := s.cron.AddFunc(sched.Cron, func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()

			log.Info().
				Str("agent_id", agentName).
				Str("description", desc).
				Msg("scheduled_trigger_fired")

			if err := s.runner.RunFromTrigger(ctx, agentName, prompt, "scheduled"); err != nil {
				log.Error().Err(err).
					Str("agent_id", agentName).
					Msg("scheduled_trigger_failed")
			}
		})
		if err != nil {
			return fmt.Errorf("registering cron %q for agent %s: %w", sched.Cron, agentName, err)
		}
	}

	return nil
}

// Start begins executing registered cron jobs.
func (s *Scheduler) Start() {
	s.cron.Start()
}

// Stop halts the scheduler and waits for running jobs to complete.
func (s *Scheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
}

// Entries returns the number of registered cron entries (for testing).
func (s *Scheduler) Entries() int {
	return len(s.cron.Entries())
}
