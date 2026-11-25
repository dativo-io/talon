package effective

import "github.com/dativo-io/talon/internal/fleet"

// Status is what `talon agents show <name>` leads with: one headline an
// operator scans for, and the one next step. It is a presentation of facts
// that exist elsewhere (the fleet row's health and the verification's next
// step), not a stored state and not another health model. The CLI and the
// console's use-case list and page (#575) all call StatusOf, so they cannot
// say different things about the same installation.
type Status struct {
	// Code is stable: working | disabled | not_active |
	// runtime_not_confirmed | waiting_for_first_request | needs_attention |
	// blocked | not_determined.
	Code     string `json:"code"`
	Headline string `json:"headline"`
	// Next is the step the CLI prints under "Next". Absent when the status
	// is not determined.
	Next *NextStep `json:"next,omitempty"`
	// Also is the verification's own next step when a blocking health
	// condition leads (Code blocked) and that step is itself an action.
	Also *NextStep `json:"also,omitempty"`
}

// Status codes.
const (
	StatusWorking             = "working"
	StatusDisabled            = "disabled"
	StatusNotActive           = "not_active"
	StatusRuntimeNotConfirmed = "runtime_not_confirmed"
	StatusWaitingFirstRequest = "waiting_for_first_request"
	StatusNeedsAttention      = "needs_attention"
	StatusBlocked             = "blocked"
	// StatusNotDetermined: the effective report could not be built, so
	// nothing is said about runtime, traffic or policy.
	StatusNotDetermined = "not_determined"
)

// StatusOf derives the status of one use case from its fleet row and its
// verification (Report.Verification; nil when the report could not be
// built).
//
// A BLOCKED health (a period cap is exhausted, or the policy denies
// everything) takes precedence over what the verification of earlier traffic
// says: a use case that verified yesterday and is refused every request
// today is not "Working", and there is something to do. Otherwise the
// headline is the verification's next step in two or three words, and
// "Working" needs both verified traffic and a running process that serves the
// use case now (nextStepOf). Neither the fleet row nor the verification is
// changed.
func StatusOf(row *fleet.AgentRow, v *Verification) Status {
	var next *NextStep
	if v != nil {
		n := v.Next
		next = &n
	}
	if step, blocked := blockedStep(row); blocked {
		s := Status{Code: StatusBlocked, Headline: "Blocked", Next: &step}
		// A verification step that is itself an action (start the runtime,
		// restart it, send a request) is still stated after it; "nothing to
		// do" is not.
		if next != nil && next.Code != NextNone {
			s.Also = next
		}
		return s
	}
	if next == nil {
		return Status{Code: StatusNotDetermined, Headline: "Not determined"}
	}
	code, headline := headlineOf(next.Code)
	return Status{Code: code, Headline: headline, Next: next}
}

// headlineOf words a next step's code in two or three words; the sentence is
// the step's text.
func headlineOf(nextCode string) (code, headline string) {
	switch nextCode {
	case NextNone:
		return StatusWorking, "Working"
	case NextEnable:
		return StatusDisabled, "Disabled"
	case NextStartRuntime, NextFixReload, NextWaitReload:
		return StatusNotActive, "Not active"
	case NextCheckRuntime:
		return StatusRuntimeNotConfirmed, "Runtime not confirmed"
	case NextSendRequest:
		return StatusWaitingFirstRequest, "Waiting for its first request"
	}
	return StatusNeedsAttention, "Needs attention"
}

// blockedStep is the next action of a use case whose health is BLOCKED: a
// persistent condition refuses all normal new work.
func blockedStep(row *fleet.AgentRow) (NextStep, bool) {
	if row == nil || row.Health != fleet.HealthBlocked {
		return NextStep{}, false
	}
	why := row.Why
	if why == "" || why == "—" {
		why = "a persistent condition refuses all new work"
	}
	step := NextStep{Code: NextBlocked, Text: "New requests of this use case are refused: " + why + "."}
	for _, c := range row.Causes {
		switch c.Kind {
		case fleet.CauseBudgetExhausted:
			step.Text += " They are served again when the period ends or the cap is raised (in the use case's file, within what the company policy allows)."
			step.Commands = []string{"talon costs --agent " + row.Name}
			return step, true
		case fleet.CausePolicyDenyAll, fleet.CauseInvalidConfig:
			step.Text += " The full report shows the rule and the file that sets it."
			step.Commands = []string{"talon agents show " + row.Name + " --effective"}
			return step, true
		}
	}
	step.Text += " The full report shows the policy and the spend behind it."
	step.Commands = []string{"talon agents show " + row.Name + " --effective"}
	return step, true
}
