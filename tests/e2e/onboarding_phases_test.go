//go:build e2e

package e2e

import (
	"fmt"
	"testing"
	"time"
)

// onboardingPhasePrefix marks a timed onboarding step in the test log;
// scripts/onboarding-acceptance.sh collects these lines into its summary
// (#575: adoption is measured where it is accepted, not by a separate
// benchmark).
const onboardingPhasePrefix = "onboarding-phase:"

// onboardingPhases records how long each customer-visible step of the
// onboarding journey takes on the binary under test. Only the step itself is
// timed, never the assertions around it, and a timing never fails a test:
// correctness assertions do. Nothing is printed for a failed test, whose
// timings measure nothing.
type onboardingPhases struct {
	t       *testing.T
	journey string
	order   []string
	took    map[string]time.Duration
	notes   map[string]string
}

func newOnboardingPhases(t *testing.T, journey string) *onboardingPhases {
	t.Helper()
	p := &onboardingPhases{t: t, journey: journey, took: map[string]time.Duration{}, notes: map[string]string{}}
	t.Cleanup(p.print)
	return p
}

// step runs fn and adds its duration to the named phase; a phase may be
// split around assertions.
func (p *onboardingPhases) step(name string, fn func()) {
	p.t.Helper()
	start := time.Now()
	fn()
	if _, seen := p.took[name]; !seen {
		p.order = append(p.order, name)
	}
	p.took[name] += time.Since(start)
}

// note qualifies a phase's timing, e.g. with a setting that shapes it.
func (p *onboardingPhases) note(name, note string) { p.notes[name] = note }

func (p *onboardingPhases) print() {
	if p.t.Failed() {
		return
	}
	for _, name := range p.order {
		line := fmt.Sprintf("%s %s | %s | %.2fs", onboardingPhasePrefix, p.journey, name, p.took[name].Seconds())
		if n := p.notes[name]; n != "" {
			line += " | " + n
		}
		p.t.Log(line)
	}
}
